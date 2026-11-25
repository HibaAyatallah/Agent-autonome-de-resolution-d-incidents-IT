from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class RemediationApprovalSettings(BaseSettings):
    """Optional API credential for recording human plan decisions."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    token: SecretStr = Field(default=SecretStr(""), validation_alias="REMEDIATION_APPROVAL_TOKEN")
    reviewer_id: str = Field(default="", max_length=100, validation_alias="REMEDIATION_APPROVER_ID")
