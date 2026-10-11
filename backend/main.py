


"""FastAPI application entry point."""

from fastapi import FastAPI

from .api.repos import router as repositories_router
from .core.config import settings

app = FastAPI(title=settings.app_name)
app.include_router(repositories_router, prefix="/repositories", tags=["repositories"])
