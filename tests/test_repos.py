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
