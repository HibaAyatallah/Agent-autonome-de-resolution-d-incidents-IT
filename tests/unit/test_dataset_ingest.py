import json
import unittest

import pandas as pd
from incident_response.dataset.ingest import (
    DatasetValidationError,
    _decode_payload,
    normalize_record,
)


class DatasetIngestTests(unittest.TestCase):
    def test_decode_single_and_double_encoded_payloads(self) -> None:
        payload = {"status": "firing", "labels": {"alertname": "CPU Usage"}}
        self.assertEqual(_decode_payload(json.dumps(payload)), payload)
        self.assertEqual(_decode_payload(json.dumps(json.dumps(payload))), payload)

    def test_normalization_omits_network_identifiers_and_empty_end(self) -> None:
        row = pd.Series(
            {
                "payload": json.dumps(
                    {
                        "status": "firing",
                        "labels": {
                            "alertname": "CPU Usage",
                            "type": "usage",
                            "ip": "192.0.2.10",
                            "instance": "192.0.2.10:9100",
                        },
                        "startsAt": "2024-11-11T23:12:00Z",
                        "endsAt": "0001-01-01T00:00:00Z",
                        "annotations": {
                            "summary": "CPU high from 192.0.2.10",
                            "description": "Above limit",
                        },
                    }
                ),
                "created_at": pd.Timestamp("2024-11-11 23:12:30"),
                "type": "usage",
                "acknowledged_time": 1.25,
                "completion_time": 2.5,
                "send_analysis_time": 0.5,
            }
        )

        result = normalize_record(row, excel_row=2)

        self.assertEqual(result["source_record_id"], "Datos finales:2")
        self.assertEqual(result["alert_name"], "CPU Usage")
        self.assertEqual(result["ends_at"], None)
        self.assertEqual(result["labels"], {"alertname": "CPU Usage", "type": "usage"})
        self.assertNotIn("192.0.2.10", json.dumps(result))
        self.assertIn("[IP masquée]", result["summary"])

    def test_invalid_payload_is_rejected(self) -> None:
        with self.assertRaises(DatasetValidationError):
            _decode_payload("not-json")


if __name__ == "__main__":
    unittest.main()
