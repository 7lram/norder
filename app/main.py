import argparse
import json
from pathlib import Path

from app.collectors.jsonl_collector import collect_jsonl
from app.normalizers.sentry_event_normalizer import normalize_sentry_event
from app.storage.db import connect, init_db
from app.storage.repositories import save_event, save_alert, save_incident, save_ai_analysis
from app.detectors import auth_errors, sms_abuse, injection, admin_discovery, sensitive_error, endpoint_spike, ip_error_burst
from app.correlation.incident_correlator import correlate
from app.correlation.risk_scoring import score_alerts
from app.ai.incident_analyzer import explain_incident
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
    ]
    alerts = []
    for detector in detectors:
        alerts.extend(detector.detect(events, config))

    for alert in alerts:
        save_alert(conn, alert)
    conn.commit()

    alert_rows = conn.execute("SELECT * FROM alerts ORDER BY id").fetchall()
    incidents = correlate(alert_rows)
    for incident in incidents:
        incident.summary = explain_incident(incident)
        incident_id = save_incident(conn, incident)
        risk_score, _ = score_alerts([_alert_like(row) for row in alert_rows if row["id"] in incident.alert_ids])
        save_ai_analysis(
            conn,
            incident_id,
            risk_score,
            f"Risk score={risk_score}. Rule severity, event volume, and attack indicators were considered.",
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


def print_summary(conn):
    print("\n== Incidents ==")
    for row in conn.execute("SELECT id, severity, incident_type, title, recommended_playbook, status FROM incidents ORDER BY id"):
        print(f"[{row['id']}] {row['severity'].upper()} {row['incident_type']} -> {row['recommended_playbook']} status={row['status']}")
        print(f"    {row['title']}")

    print("\n== Response Actions ==")
    for row in conn.execute("SELECT incident_id, action_type, target_type, target_value, status, result_message FROM response_actions ORDER BY id"):
        print(f"[incident {row['incident_id']}] {row['action_type']} {row['target_type']}={row['target_value']} {row['status']} - {row['result_message']}")


def main():
    parser = argparse.ArgumentParser(description="Norder Sentry SIEM/SOAR Platform MVP")
    parser.add_argument("--db", default=str(BASE_DIR / "norder_siem_soar.db"))
    parser.add_argument("--schema", default=str(BASE_DIR / "sql" / "schema.sql"))
    parser.add_argument("--config", default=str(BASE_DIR / "config.json"))
    parser.add_argument("--input", default=str(BASE_DIR / "data" / "sample_sentry_events.jsonl"))
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    run_pipeline(args)


if __name__ == "__main__":
    main()
