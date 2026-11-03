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


@lru_cache
def get_settings() -> Settings:
    return Settings()
