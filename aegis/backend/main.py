"""FastAPI application entry point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

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
