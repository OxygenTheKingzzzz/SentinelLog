from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Year is never inferred from log contents."""

    database_url: str = "postgresql+psycopg://sentinellog:sentinellog@127.0.0.1:5432/sentinellog"
    source_year: int | None = None
    max_upload_bytes: int = 33_554_432
    log_level: str = "INFO"
    anomaly_artifact_dir: str = "var/anomaly-models"
    # Colon-separated absolute directories. Empty means no live path can be authorized.
    live_allow_roots: str = ""
    # Comma-separated browser origins. Empty means no cross-origin browser access.
    cors_origins: str = "http://127.0.0.1:5173,http://localhost:5173"
    # In-process limit for import, detection, anomaly train/score, and PDF export.
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60
    debug: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("source_year", mode="before")
    @classmethod
    def empty_year_is_none(cls, value: object) -> object:
        if value is None or value == "":
            return None
        return value

    @field_validator("source_year")
    @classmethod
    def year_in_range(cls, value: int | None) -> int | None:
        if value is None:
            return None
        if value < 1970 or value > 2100:
            raise ValueError("source_year must be between 1970 and 2100")
        return value

    @field_validator("max_upload_bytes")
    @classmethod
    def upload_limit_positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("max_upload_bytes must be positive")
        return value

    @field_validator("cors_origins")
    @classmethod
    def cors_origins_are_explicit(cls, value: str) -> str:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if any(part == "*" for part in parts):
            raise ValueError("cors_origins cannot be *")
        return ",".join(parts)

    @field_validator("rate_limit_requests", "rate_limit_window_seconds")
    @classmethod
    def rate_limit_positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("rate limit settings must be positive")
        return value

    def origin_list(self) -> list[str]:
        return [part.strip() for part in self.cors_origins.split(",") if part.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
