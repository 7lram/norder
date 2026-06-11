import json
import unittest
from pathlib import Path

from app.normalizers.sentry_event_normalizer import normalize_sentry_event
from app.detectors import injection


BASE_DIR = Path(__file__).resolve().parents[1]


class PipelineTest(unittest.TestCase):
    def test_sentry_event_normalizer(self):
        raw = json.loads((BASE_DIR / "data" / "sample_sentry_events.jsonl").read_text(encoding="utf-8").splitlines()[0])
        event = normalize_sentry_event(raw)
        self.assertEqual(event.source, "sentry")
        self.assertEqual(event.event_type, "sms_error")
        self.assertEqual(event.endpoint, "/norder/api/common/sms/request")

    def test_injection_detector(self):
        raw = {
            "event_id": "evt-test",
            "issue_id": "ISSUE-TEST",
            "timestamp": "2026-06-10T09:00:00+09:00",
            "message": "SQL error near UNION SELECT",
            "endpoint": "/search",
            "method": "GET",
            "status_code": 500,
            "source_ip": "192.0.2.1",
            "payload": "q=' UNION SELECT password FROM users--",
            "exception_type": "DatabaseException"
        }
        event = normalize_sentry_event(raw)
        alerts = injection.detect([event], {
            "patterns": {
                "sqli": ["union select", "or 1=1", "sleep(", "--"],
                "xss": ["<script", "javascript:", "onerror=", "alert("]
            }
        })
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "PAYLOAD-001")


if __name__ == "__main__":
    unittest.main()
