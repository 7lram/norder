import json
from collections import defaultdict
from app.models.incident import Incident
from app.correlation.risk_scoring import score_alerts


def correlate(alert_rows):
    grouped = defaultdict(list)
    for row in alert_rows:
        grouped[(row["rule_id"], row["source_ip"], row["endpoint"])].append(row)

    incidents = []
    for (_, source_ip, endpoint), rows in grouped.items():
        alerts = [_row_to_alert_like(row) for row in rows]
        _, severity = score_alerts(alerts)
        first = rows[0]
        evidence = [json.loads(row["evidence_json"] or "{}") for row in rows]
        issue_ids = sorted(_collect_issue_ids(evidence))
        incidents.append(Incident(
            incident_type=_incident_type(first["rule_id"]),
            severity=severity,
            title=first["title"],
            source_ip=source_ip,
            endpoint=endpoint,
            alert_ids=[row["id"] for row in rows],
            sentry_issue_ids=issue_ids,
            event_count=len(rows),
            summary=f"{first['title']} detected from {source_ip or endpoint}.",
            recommended_playbook=_playbook(first["rule_id"]),
        ))
    return incidents


class _row_to_alert_like:
    def __init__(self, row):
        self.rule_id = row["rule_id"]
        self.severity = row["severity"]


def _incident_type(rule_id):
    return {
        "AUTH-001": "credential_or_auth_attack",
        "SMS-001": "sms_abuse",
        "PAYLOAD-001": "payload_attack",
        "ADMIN-001": "admin_path_scan",
        "LEAK-001": "sensitive_error_leak",
        "ENDPOINT-001": "endpoint_error_spike",
        "IP-001": "ip_error_burst",
        "STADIUM-001": "stadium_order_flow_abuse",
        "STADIUM-002": "stadium_seat_block_anomaly",
        "STADIUM-003": "stadium_peak_error_cluster",
        "VERSION-001": "legacy_api_bypass",
        "VERSION-002": "legacy_api_bypass",
        "SENTRY-001": "sentry_event_poisoning",
        "SENTRY-002": "sentry_event_poisoning",
        "SEMANTIC-001": "semantic_error_probing",
        "STADIUM-004": "stadium_context_violation",
        "STADIUM-005": "stadium_context_violation",
        "STADIUM-006": "stadium_context_violation",
        "STADIUM-007": "stadium_context_violation",
        "STADIUM-008": "direct_payment_bypass",
    }.get(rule_id, "security_incident")


def _playbook(rule_id):
    return {
        "AUTH-001": "credential_or_auth_attack",
        "SMS-001": "sms_abuse",
        "PAYLOAD-001": "payload_attack",
        "ADMIN-001": "admin_path_scan",
        "LEAK-001": "sensitive_error_leak",
        "ENDPOINT-001": "endpoint_error_spike",
        "IP-001": "credential_or_auth_attack",
        "STADIUM-001": "stadium_order_flow_abuse",
        "STADIUM-002": "stadium_order_flow_abuse",
        "STADIUM-003": "stadium_peak_error_cluster",
        "VERSION-001": "legacy_api_bypass",
        "VERSION-002": "legacy_api_bypass",
        "SENTRY-001": "sentry_event_poisoning",
        "SENTRY-002": "sentry_event_poisoning",
        "SEMANTIC-001": "semantic_error_probing",
        "STADIUM-004": "stadium_context_violation",
        "STADIUM-005": "stadium_context_violation",
        "STADIUM-006": "stadium_context_violation",
        "STADIUM-007": "stadium_context_violation",
        "STADIUM-008": "direct_payment_bypass",
    }.get(rule_id, "endpoint_error_spike")


def _collect_issue_ids(evidence_items):
    issue_ids = set()
    for item in evidence_items:
        if item.get("issue_id"):
            issue_ids.add(item["issue_id"])
        for issue_id in item.get("issue_ids", []):
            if issue_id:
                issue_ids.add(issue_id)
    return issue_ids
