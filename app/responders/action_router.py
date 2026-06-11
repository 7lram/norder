import json
from app.storage.repositories import save_response_action


def run_playbook(conn, incident_row, config):
    actions = config["playbooks"].get(incident_row["recommended_playbook"], ["notify_security_channel"])
    for action_type in actions:
        execute_action(conn, incident_row, action_type)
    conn.execute("UPDATE incidents SET status = 'dry_run_completed' WHERE id = ?", (incident_row["id"],))


def execute_action(conn, incident_row, action_type):
    if action_type == "notify_security_channel":
        _notify(conn, incident_row)
    elif action_type == "comment_sentry_issue":
        _comment_sentry(conn, incident_row)
    elif action_type == "dry_run_ip_block":
        _block_candidate(conn, incident_row)
    elif action_type == "recommend_rate_limit":
        _rate_limit(conn, incident_row)
    elif action_type == "suggest_waf_rule":
        _waf_rule(conn, incident_row)
    else:
        _task(conn, incident_row, action_type)


def _notify(conn, incident):
    message = f"[{incident['severity'].upper()}] {incident['title']} - {incident['summary']}"
    conn.execute(
        "INSERT INTO notifications (incident_id, channel, message, status) VALUES (?, ?, ?, ?)",
        (incident["id"], "slack_or_discord", message, "dry_run_created"),
    )
    save_response_action(conn, incident["id"], "notify_security_channel", "channel", "slack_or_discord", "dry_run_created", "Notification record created")


def _comment_sentry(conn, incident):
    issue_ids = json.loads(incident["sentry_issue_ids"] or "[]")
    body = (
        "[Security response note]\n"
        f"- Incident: {incident['title']}\n"
        f"- Severity: {incident['severity']}\n"
        f"- Summary: {incident['summary']}\n"
        f"- Recommended playbook: {incident['recommended_playbook']}\n"
        "- Action mode: dry-run\n"
    )
    for issue_id in issue_ids:
        conn.execute(
            "INSERT INTO sentry_issue_comments (incident_id, issue_id, comment_body, status) VALUES (?, ?, ?, ?)",
            (incident["id"], issue_id, body, "dry_run_created"),
        )
    save_response_action(conn, incident["id"], "comment_sentry_issue", "sentry_issue", ",".join(issue_ids), "dry_run_created", "Sentry issue response note recorded")


def _block_candidate(conn, incident):
    target = incident["source_ip"] or "unknown_ip"
    conn.execute(
        "INSERT INTO watchlist (watch_type, value, reason, source_incident_id) VALUES (?, ?, ?, ?)",
        ("ip", target, "IP block candidate", incident["id"]),
    )
    save_response_action(conn, incident["id"], "dry_run_ip_block", "ip", target, "dry_run_created", "IP block candidate recorded")


def _rate_limit(conn, incident):
    target = incident["endpoint"] or incident["source_ip"] or "unknown"
    save_response_action(conn, incident["id"], "recommend_rate_limit", "target", target, "dry_run_created", "Rate limit recommendation recorded")


def _waf_rule(conn, incident):
    target = incident["endpoint"] or incident["source_ip"] or "unknown"
    save_response_action(conn, incident["id"], "suggest_waf_rule", "target", target, "dry_run_created", "WAF rule suggestion recorded")


def _task(conn, incident, action_type):
    target = incident["endpoint"] or incident["incident_type"]
    save_response_action(conn, incident["id"], action_type, "task", target, "dry_run_created", f"{action_type} task recorded")
