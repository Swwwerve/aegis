"""FastAPI application entry point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api.remediation import router as remediation_router
from .api.repos import router as repositories_router
from .api.scans import router as scans_router
from .core.config import settings
from .db.database import init_db


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize required database tables before serving requests."""

    init_db()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(repositories_router, prefix="/repositories", tags=["repositories"])
app.include_router(scans_router, prefix="/scans", tags=["scans"])
app.include_router(remediation_router, prefix="/remediation", tags=["remediation"])
app.include_router(
    repositories_router, prefix="/api/repositories", include_in_schema=False
)
app.include_router(scans_router, prefix="/api/scans", include_in_schema=False)
app.include_router(
    remediation_router, prefix="/api/remediation", include_in_schema=False
)

FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
app.mount(
    "/assets",
    StaticFiles(directory=FRONTEND_DIST / "assets", check_dir=False),
    name="frontend-assets",
)


@app.get("/", include_in_schema=False)
def frontend():
    """Serve the production UI when built; API routes remain available independently."""
    index = FRONTEND_DIST / "index.html"
    if index.is_file():
        return FileResponse(index)
    return {
        "message": "Aegis API is running. Build the frontend with npm run build in frontend/, or use the Vite dev server on port 5173.",
        "docs": "/docs",
    }
