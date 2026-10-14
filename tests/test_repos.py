from pathlib import Path
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from aegis.backend.db.database import Base, get_db
from aegis.backend.main import app
from aegis.backend.services import repository_service


@pytest.fixture
def client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[TestClient, None, None]:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'test.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    def fake_clone(url):
        canonical_url, owner, name = repository_service.parse_github_url(url)
        return repository_service.RepositoryMetadata(
            url=canonical_url,
            owner=owner,
            name=name,
            default_branch="main",
            local_path=tmp_path / "workspace",
        )

    monkeypatch.setattr(repository_service, "clone_repository", fake_clone)
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_submit_repository(client: TestClient) -> None:
    response = client.post(
        "/repositories",
        json={"url": "https://github.com/octo/project"},
    )

    assert response.status_code == 201
    assert response.json()["owner"] == "octo"
    assert response.json()["default_branch"] == "main"


def test_reject_non_github_repository(client: TestClient) -> None:
    client = TestClient(app)
    response = client.post(
        "/repositories",
        json={"url": "https://gitlab.com/octo/project"},
    )

    assert response.status_code == 422


def test_analyze_registered_repository(client: TestClient, tmp_path: Path, monkeypatch) -> None:
    from aegis.backend.core.config import settings
    root = tmp_path / "workspaces"
    clone = root / "example"
    (clone / ".git").mkdir(parents=True)
    (clone / "package.json").write_text('{"scripts":{"test":"node --test"}}')
    monkeypatch.setattr(settings, "workspace_root", root)

    def fake_clone(url):
        canonical, owner, name = repository_service.parse_github_url(url)
        return repository_service.RepositoryMetadata(canonical, owner, name, "main", clone)

    monkeypatch.setattr(repository_service, "clone_repository", fake_clone)
    registered = client.post("/repositories", json={"url": "https://github.com/octo/project"}).json()
    result = client.post(f"/repositories/{registered['id']}/analysis", json={"use_model": False})
    assert result.status_code == 200
    assert result.json()["projects"][0]["package_managers"] == ["npm"]
    assert result.json()["inference_status"] == "not_requested"
    from aegis.backend.sandbox import executor
    from aegis.backend.schemas.repository import DependencyResolution

    async def fake_resolution(path, report):
        assert path == clone
        report.projects[0].resolutions = [DependencyResolution(ecosystem='Node',method='npm-installed-tree',status='completed')]
        report.resolution_status = 'completed'
        return report

    monkeypatch.setattr(executor,'resolve_repository_analysis',fake_resolution)
    resolved = client.post(f"/repositories/{registered['id']}/analysis",json={'use_model':False,'resolve_dependencies':True})
    assert resolved.status_code == 200
    assert resolved.json()['resolution_status'] == 'completed'
    assert resolved.json()['projects'][0]['resolutions'][0]['method'] == 'npm-installed-tree'
    assert client.post("/repositories/999/analysis", json={"use_model": False}).status_code == 404
    monkeypatch.setattr(settings, "workspace_root", tmp_path)
    assert client.post(f"/repositories/{registered['id']}/analysis", json={"use_model": False}).status_code == 422
