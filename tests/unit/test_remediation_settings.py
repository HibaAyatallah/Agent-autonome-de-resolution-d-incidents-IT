import unittest

from incident_response.remediation.settings import RemediationApprovalSettings
from pydantic import ValidationError


class RemediationApprovalSettingsTests(unittest.TestCase):
    def test_reviewer_tokens_must_be_strong(self) -> None:
        with self.assertRaises(ValidationError):
            RemediationApprovalSettings(
                REMEDIATION_REVIEWERS=[{"reviewer_id": "reviewer-a", "token": "short"}]
            )

    def test_reviewer_ids_and_tokens_must_be_unique(self) -> None:
        credential = {"reviewer_id": "reviewer-a", "token": "a" * 40}
        with self.assertRaises(ValidationError):
            RemediationApprovalSettings(
                REMEDIATION_REVIEWERS=[credential, {**credential, "token": "b" * 40}]
            )
        with self.assertRaises(ValidationError):
            RemediationApprovalSettings(
                REMEDIATION_REVIEWERS=[credential, {"reviewer_id": "reviewer-b", "token": "a" * 40}]
            )

    def test_reviewer_id_cannot_contain_surrounding_whitespace(self) -> None:
        with self.assertRaises(ValidationError):
            RemediationApprovalSettings(
                REMEDIATION_REVIEWERS=[{"reviewer_id": " reviewer-a ", "token": "a" * 40}]
            )


if __name__ == "__main__":
    unittest.main()
