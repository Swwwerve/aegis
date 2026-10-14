"""Environment-backed application settings."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration used by the API and repository intake service."""

    app_name: str = "Aegis"
    database_url: str = "sqlite:///./aegis.db"
    github_token: str | None = None
    openai_api_key: SecretStr | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    workspace_root: Path = Path("workspaces")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="AEGIS_",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""

    return Settings()


settings = get_settings()
