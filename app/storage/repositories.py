import json


def save_event(conn, event):
    data = event.to_dict()
    cursor = conn.execute(
        """
        INSERT INTO events (
          source, source_event_id, source_issue_id, timestamp, event_type,
          source_ip, user_id_hash, session_id_hash, endpoint, method,
          status_code, user_agent, payload, exception_type, message, raw_event
        ) VALUES (
          :source, :source_event_id, :source_issue_id, :timestamp, :event_type,
          :source_ip, :user_id_hash, :session_id_hash, :endpoint, :method,
          :status_code, :user_agent, :payload, :exception_type, :message, :raw_event
        )
        """,
        data,
    )
    return cursor.lastrowid


def save_alert(conn, alert):
    cursor = conn.execute(
        """
        INSERT INTO alerts (
          rule_id, rule_name, severity, source_ip, endpoint, title,
          description, evidence_json, dedup_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.rule_id,
            alert.rule_name,
            alert.severity,
            alert.source_ip,
            alert.endpoint,
            alert.title,
            alert.description,
            json.dumps(alert.evidence, ensure_ascii=False),
            alert.dedup_key,
        ),
    )
    return cursor.lastrowid


def save_incident(conn, incident):
    cursor = conn.execute(
        """
        INSERT INTO incidents (
          incident_type, severity, title, source_ip, endpoint, alert_ids,
          sentry_issue_ids, event_count, summary, recommended_playbook
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident.incident_type,
            incident.severity,
            incident.title,
            incident.source_ip,
            incident.endpoint,
            json.dumps(incident.alert_ids),
            json.dumps(incident.sentry_issue_ids),
            incident.event_count,
            incident.summary,
            incident.recommended_playbook,
        ),
    )
    return cursor.lastrowid


def save_ai_analysis(conn, incident_id, risk_score, risk_reason, analyst_summary, recommended_playbook):
    conn.execute(
        """
        INSERT INTO ai_analysis_results (
          incident_id, risk_score, risk_reason, analyst_summary, recommended_playbook
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (incident_id, risk_score, risk_reason, analyst_summary, recommended_playbook),
    )


def save_response_action(conn, incident_id, action_type, target_type, target_value, status, message):
    conn.execute(
        """
        INSERT INTO response_actions (
          incident_id, action_type, target_type, target_value, status, result_message
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (incident_id, action_type, target_type, target_value, status, message),
    )
