from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class MemorySettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(
        default="sqlite:///./data/incidents.db",
        validation_alias="DATABASE_URL",
    )
    similar_case_limit: int = Field(default=5, ge=1, le=25, validation_alias="SIMILAR_CASE_LIMIT")
    similar_case_minimum_score: float = Field(
        default=0.25,
        ge=0,
        le=1,
        validation_alias="SIMILAR_CASE_MINIMUM_SCORE",
    )
