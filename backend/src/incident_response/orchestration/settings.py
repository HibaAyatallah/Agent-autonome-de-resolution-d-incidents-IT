from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkflowSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    agent_timeout_seconds: float = Field(
        default=5.0,
        ge=0.1,
        le=60,
        validation_alias="AGENT_TIMEOUT_SECONDS",
    )
    max_agent_attempts: int = Field(default=2, ge=1, le=3, validation_alias="MAX_AGENT_ATTEMPTS")
