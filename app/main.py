import argparse
import json
from pathlib import Path

from app.collectors.jsonl_collector import collect_jsonl
from app.normalizers.sentry_event_normalizer import normalize_sentry_event
from app.storage.db import connect, init_db
from app.storage.repositories import save_event, save_alert, save_incident, save_ai_analysis
from app.detectors import (
    admin_discovery,
    auth_errors,
    endpoint_spike,
    injection,
    ip_error_burst,
    semantic_error,
    sensitive_error,
    sentry_poisoning,
    sms_abuse,
    stadium_context,
    version_downgrade,
)
from app.correlation.incident_correlator import correlate
from app.correlation.risk_scoring import score_alerts
from app.ai.incident_analyzer import analyze_incident
from app.env_loader import load_env_file
from app.responders.action_router import run_playbook


BASE_DIR = Path(__file__).resolve().parents[1]


def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def run_pipeline(args):
    config = load_config(args.config)
    conn = connect(args.db)
    init_db(conn, args.schema)

    events = []
    for raw in collect_jsonl(args.input):
        event = normalize_sentry_event(raw)
        save_event(conn, event)
        events.append(event)
    conn.commit()

    detectors = [
        auth_errors,
        sms_abuse,
        injection,
        admin_discovery,
        sensitive_error,
        endpoint_spike,
        ip_error_burst,
        stadium_context,
        version_downgrade,
        sentry_poisoning,
        semantic_error,
    ]
    alerts = []
    for detector in detectors:
        alerts.extend(detector.detect(events, config))
    alerts = suppress_overlapping_alerts(alerts)

    for alert in alerts:
        save_alert(conn, alert)
    conn.commit()

    alert_rows = conn.execute("SELECT * FROM alerts ORDER BY id").fetchall()
    incidents = correlate(alert_rows)
    for incident in incidents:
        risk_score, _ = score_alerts([_alert_like(row) for row in alert_rows if row["id"] in incident.alert_ids])
        analysis = analyze_incident(incident, risk_score, args.external_ai)
        incident.summary = analysis["summary"]
        incident.recommended_playbook = analysis["recommended_playbook"]
        incident_id = save_incident(conn, incident)
        save_ai_analysis(
            conn,
            incident_id,
            risk_score,
            analysis["risk_reason"],
            incident.summary,
            incident.recommended_playbook,
        )
    conn.commit()

    incident_rows = conn.execute("SELECT * FROM incidents WHERE status = 'open' ORDER BY id").fetchall()
    for incident_row in incident_rows:
        run_playbook(conn, incident_row, config)
    conn.commit()

    print(f"Events imported: {len(events)}")
    print(f"Alerts created: {len(alerts)}")
    print(f"Incidents created: {len(incidents)}")
    print(f"SOAR playbooks executed: {len(incident_rows)}")
    print_summary(conn)


class _alert_like:
    def __init__(self, row):
        self.rule_id = row["rule_id"]
        self.severity = row["severity"]


def suppress_overlapping_alerts(alerts):
    grouped = {}
    passthrough = []
    for alert in alerts:
        key = _alert_issue_key(alert)
        if not key:
            passthrough.append(alert)
            continue
        grouped.setdefault(key, []).append(alert)

    selected = []
    for items in grouped.values():
        selected.append(sorted(items, key=_alert_priority, reverse=True)[0])
    selected.extend(passthrough)
    return sorted(selected, key=lambda alert: alert.dedup_key)


def _alert_issue_key(alert):
    issue_ids = alert.evidence.get("issue_ids")
    if issue_ids:
        return tuple(sorted(issue_ids))
    issue_id = alert.evidence.get("issue_id")
    if issue_id:
        return (issue_id,)
    return None


def _alert_priority(alert):
    priorities = {
        "VERSION-002": 100,
        "STADIUM-008": 95,
        "SENTRY-001": 90,
        "SEMANTIC-001": 85,
        "PAYLOAD-001": 80,
        "VERSION-001": 75,
        "STADIUM-004": 72,
        "SMS-001": 70,
        "SMS-002": 68,
        "LEAK-001": 65,
        "ADMIN-001": 60,
        "AUTH-001": 55,
        "STADIUM-001": 50,
        "STADIUM-002": 45,
        "STADIUM-003": 42,
        "STADIUM-005": 40,
        "STADIUM-006": 35,
        "STADIUM-007": 30,
        "SENTRY-002": 25,
        "ENDPOINT-001": 20,
        "IP-001": 10,
    }
    return priorities.get(alert.rule_id, 0)


def print_summary(conn):
    print("\n== Incidents ==")
    for row in conn.execute("SELECT id, severity, incident_type, title, recommended_playbook, status FROM incidents ORDER BY id"):
        print(f"[{row['id']}] {row['severity'].upper()} {row['incident_type']} -> {row['recommended_playbook']} status={row['status']}")
        print(f"    {row['title']}")

    print("\n== AI Analysis ==")
    for row in conn.execute("SELECT incident_id, risk_score, risk_reason, analyst_summary FROM ai_analysis_results ORDER BY id"):
        source = "external_ai"
        if "External AI fallback reason:" in row["risk_reason"]:
            source = "local_fallback"
        elif "Rule severity, event volume, and attack indicators were considered." in row["risk_reason"]:
            source = "local"
        print(f"[incident {row['incident_id']}] source={source} risk_score={row['risk_score']}")
        print(f"    {row['analyst_summary']}")

    print("\n== Response Actions ==")
    for row in conn.execute("SELECT incident_id, action_type, target_type, target_value, status, result_message FROM response_actions ORDER BY id"):
        print(f"[incident {row['incident_id']}] {row['action_type']} {row['target_type']}={row['target_value']} {row['status']} - {row['result_message']}")


def main():
    load_env_file(BASE_DIR / ".env")

    parser = argparse.ArgumentParser(description="Norder Sentry SIEM/SOAR Platform MVP")
    parser.add_argument("--db", default=str(BASE_DIR / "norder_siem_soar.db"))
    parser.add_argument("--schema", default=str(BASE_DIR / "sql" / "schema.sql"))
    parser.add_argument("--config", default=str(BASE_DIR / "config.json"))
    parser.add_argument("--input", default=str(BASE_DIR / "data" / "sample_sentry_events.jsonl"))
    parser.add_argument("--external-ai", action="store_true", help="Use external AI API through AI_PROVIDER and API key environment variables")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    run_pipeline(args)


if __name__ == "__main__":
    main()
