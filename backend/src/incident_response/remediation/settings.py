from __future__ import annotations

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ReviewerCredential(BaseModel):
    reviewer_id: str = Field(min_length=1, max_length=100)
    token: SecretStr

    @field_validator("reviewer_id")
    @classmethod
    def reviewer_id_must_be_trimmed(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("reviewer_id must not contain surrounding whitespace.")
        return value

    @field_validator("token")
    @classmethod
    def token_must_be_strong(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < 32:
            raise ValueError("Reviewer tokens must contain at least 32 characters.")
        return value


class RemediationApprovalSettings(BaseSettings):
    """Optional reviewer credentials, with a single-reviewer legacy fallback."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    token: SecretStr = Field(default=SecretStr(""), validation_alias="REMEDIATION_APPROVAL_TOKEN")
    reviewer_id: str = Field(default="", max_length=100, validation_alias="REMEDIATION_APPROVER_ID")
    reviewers: list[ReviewerCredential] = Field(
        default_factory=list,
        validation_alias="REMEDIATION_REVIEWERS",
    )

    @model_validator(mode="after")
    def reviewer_credentials_must_be_unique(self) -> RemediationApprovalSettings:
        reviewer_ids = [reviewer.reviewer_id for reviewer in self.reviewers]
        reviewer_tokens = [reviewer.token.get_secret_value() for reviewer in self.reviewers]
        if len(set(reviewer_ids)) != len(reviewer_ids):
            raise ValueError("Reviewer IDs must be unique.")
        if len(set(reviewer_tokens)) != len(reviewer_tokens):
            raise ValueError("Reviewer tokens must be unique.")
        return self
