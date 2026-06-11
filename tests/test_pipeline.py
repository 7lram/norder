import json
import unittest
from pathlib import Path

from app.ai.llm_client import _parse_json_response
from app.normalizers.sentry_event_normalizer import normalize_sentry_event
from app.detectors import semantic_error, sms_abuse, stadium_context, version_downgrade


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
        from app.detectors import injection
        alerts = injection.detect([event], {
            "patterns": {
                "sqli": ["union select", "or 1=1", "sleep(", "--"],
                "xss": ["<script", "javascript:", "onerror=", "alert("]
            }
        })
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "PAYLOAD-001")

    def test_ai_json_parser_accepts_markdown_fenced_json(self):
        parsed = _parse_json_response(
            """```json
            {"summary":"test","risk_reason":"reason","recommended_playbook":"sms_abuse"}
            ```"""
        )
        self.assertEqual(parsed["recommended_playbook"], "sms_abuse")

    def test_stadium_order_entry_flow_bypass_detector(self):
        raw = {
            "event_id": "evt-stadium",
            "issue_id": "ISSUE-STADIUM",
            "timestamp": "2026-06-10T09:05:00+09:00",
            "message": "Order state update reached API without entry context",
            "endpoint": "/norder/api/v1/orders/status",
            "method": "POST",
            "status_code": 403,
            "source_ip": "10.20.1.44",
            "payload": "",
            "exception_type": "OrderFlowException",
            "contexts": {
                "norder": {
                    "game_phase": "cleaning_time",
                    "seat_block": "A103",
                    "network_type": "stadium_wifi",
                    "qr_scan_id": None
                }
            }
        }
        event = normalize_sentry_event(raw)
        alerts = stadium_context.detect([event], {
            "thresholds": {
                "seat_block_hop_threshold": 2,
                "stadium_peak_error_threshold": 3
            },
            "stadium": {
                "peak_phases": ["pre_game", "inning_break", "cleaning_time", "post_game"],
                "allowed_entry_channels": ["qr", "kakao_app"],
                "state_change_paths": ["/orders", "/payments", "/cart"]
            }
        })
        self.assertEqual(alerts[0].rule_id, "STADIUM-001")

    def test_stadium_kakao_app_entry_does_not_trigger_bypass(self):
        raw = {
            "event_id": "evt-kakao",
            "issue_id": "ISSUE-KAKAO",
            "timestamp": "2026-06-10T09:07:00+09:00",
            "message": "Order status update from Kakao app entry flow",
            "endpoint": "/norder/api/v1/orders/status",
            "method": "POST",
            "status_code": 200,
            "source_ip": "10.20.2.55",
            "user_id": "user-kakao-1",
            "session_id": "sess-kakao-1",
            "payload": "",
            "exception_type": "",
            "contexts": {
                "norder": {
                    "game_phase": "cleaning_time",
                    "seat_block": "B205",
                    "network_type": "stadium_lte",
                    "entry_channel": "kakao_app",
                    "kakao_session_id": "kakao-session-1",
                    "venue_id": "jamsil-baseball",
                    "store_id": "store-12",
                    "qr_scan_id": None
                }
            }
        }
        event = normalize_sentry_event(raw)
        alerts = stadium_context.detect([event], {
            "thresholds": {
                "seat_block_hop_threshold": 2,
                "stadium_peak_error_threshold": 3
            },
            "stadium": {
                "peak_phases": ["pre_game", "inning_break", "cleaning_time", "post_game"],
                "allowed_entry_channels": ["qr", "kakao_app"],
                "state_change_paths": ["/orders", "/payments", "/cart"]
            }
        })
        self.assertEqual(alerts, [])

    def test_sms_server_cloud_or_bot_client_triggers_alert(self):
        raw = {
            "event_id": "evt-sms",
            "issue_id": "ISSUE-SMS",
            "timestamp": "2026-06-10T03:00:00+09:00",
            "message": "SMS request processed without auth context",
            "endpoint": "/norder/api/common/sms/request",
            "method": "POST",
            "status_code": 500,
            "source_ip": "192.0.2.44",
            "user_agent": "python-requests/2.31",
            "payload": "{\"user_phone\":\"sha256:phone-a\"}",
            "exception_type": "SmsVerificationException",
            "contexts": {"norder": {"game_phase": "late_night", "network_type": "server_cloud"}}
        }
        event = normalize_sentry_event(raw)
        alerts = sms_abuse.detect([event], {
            "thresholds": {
                "sms_abuse_threshold": 3,
                "sms_entry_time_threshold": 10,
                "sms_off_hours_threshold": 2,
                "sms_same_phone_threshold": 2
            }
        })
        self.assertEqual(alerts[0].rule_id, "SMS-001")

    def test_v2_block_then_v1_success_detector(self):
        raw_events = [
            {
                "event_id": "evt-v2",
                "issue_id": "ISSUE-VERSION",
                "timestamp": "2026-06-10T09:08:00+09:00",
                "message": "Forbidden on v2 protected order API",
                "endpoint": "/norder/api/v2/orders/status",
                "method": "POST",
                "status_code": 403,
                "source_ip": "198.51.100.77",
                "user_id": "user-version-test",
                "session_id": "sess-version-test",
                "payload": "",
                "exception_type": "AuthException"
            },
            {
                "event_id": "evt-v1",
                "issue_id": "ISSUE-VERSION",
                "timestamp": "2026-06-10T09:08:20+09:00",
                "message": "Legacy v1 order status API returned success",
                "endpoint": "/norder/api/v1/orders/status",
                "method": "POST",
                "status_code": 200,
                "source_ip": "198.51.100.77",
                "user_id": "user-version-test",
                "session_id": "sess-version-test",
                "payload": "",
                "exception_type": ""
            }
        ]
        events = [normalize_sentry_event(raw) for raw in raw_events]
        alerts = version_downgrade.detect(events, {})
        self.assertTrue(any(alert.rule_id == "VERSION-002" for alert in alerts))

    def test_http_200_semantic_error_detector(self):
        raw = {
            "event_id": "evt-semantic",
            "issue_id": "ISSUE-SEMANTIC",
            "timestamp": "2026-06-10T03:10:00+09:00",
            "message": "not found for invalid venue FAKEVENUE",
            "endpoint": "/norder/api/v1/venues/FAKEVENUE/menu",
            "method": "GET",
            "status_code": 200,
            "source_ip": "192.0.2.44",
            "payload": "",
            "exception_type": "SyntheticException",
            "contexts": {"norder": {"game_phase": "late_night", "network_type": "server_cloud", "venue_id": "FAKEVENUE"}}
        }
        event = normalize_sentry_event(raw)
        alerts = semantic_error.detect([event], {
            "stadium": {"known_venues": ["jamsil-baseball"]},
            "patterns": {"semantic_error_tokens": ["not found", "invalid venue"]}
        })
        self.assertEqual(alerts[0].rule_id, "SEMANTIC-001")

    def test_simultaneous_multi_venue_detector(self):
        raw_events = [
            {
                "event_id": "evt-venue-a",
                "issue_id": "ISSUE-MULTI-VENUE",
                "timestamp": "2026-06-10T18:10:00+09:00",
                "message": "User opened venue menu",
                "endpoint": "/norder/api/v2/venues/jamsil-baseball/menu",
                "method": "GET",
                "status_code": 200,
                "source_ip": "10.20.3.10",
                "user_id": "user-multi",
                "session_id": "sess-multi",
                "payload": "",
                "exception_type": "",
                "contexts": {"norder": {"venue_id": "jamsil-baseball", "network_type": "stadium_lte"}}
            },
            {
                "event_id": "evt-venue-b",
                "issue_id": "ISSUE-MULTI-VENUE",
                "timestamp": "2026-06-10T18:12:00+09:00",
                "message": "User opened venue menu",
                "endpoint": "/norder/api/v2/venues/gocheok-sky-dome/menu",
                "method": "GET",
                "status_code": 200,
                "source_ip": "10.20.3.10",
                "user_id": "user-multi",
                "session_id": "sess-multi",
                "payload": "",
                "exception_type": "",
                "contexts": {"norder": {"venue_id": "gocheok-sky-dome", "network_type": "stadium_lte"}}
            }
        ]
        events = [normalize_sentry_event(raw) for raw in raw_events]
        alerts = stadium_context.detect(events, {"thresholds": {"simultaneous_venue_window_seconds": 600}})
        self.assertTrue(any(alert.rule_id == "STADIUM-004" for alert in alerts))

    def test_direct_payment_without_prior_flow_detector(self):
        raw = {
            "event_id": "evt-payment",
            "issue_id": "ISSUE-PAYMENT",
            "timestamp": "2026-06-10T18:20:00+09:00",
            "message": "Payment request appeared without cart or order flow",
            "endpoint": "/norder/api/v2/payments/approve",
            "method": "POST",
            "status_code": 403,
            "source_ip": "198.51.100.120",
            "user_id": "user-payment",
            "session_id": "sess-payment",
            "payload": "",
            "exception_type": "PaymentFlowException",
            "contexts": {"norder": {"network_type": "vpn", "venue_id": "jamsil-baseball"}}
        }
        event = normalize_sentry_event(raw)
        alerts = stadium_context.detect([event], {})
        self.assertTrue(any(alert.rule_id == "STADIUM-008" for alert in alerts))


if __name__ == "__main__":
    unittest.main()
