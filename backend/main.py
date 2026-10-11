


"""FastAPI application entry point."""

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI

from .api.repos import router as repositories_router
from .core.config import settings
from .db.database import init_db


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize required database tables before serving requests."""

    init_db()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(repositories_router, prefix="/repositories", tags=["repositories"])
