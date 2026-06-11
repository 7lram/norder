from app.models.alert import Alert
import json


def make_alert(rule_id, rule_name, severity, source_ip, endpoint, title, description, evidence, dedup_key):
    return Alert(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        source_ip=source_ip,
        endpoint=endpoint,
        title=title,
        description=description,
        evidence=evidence,
        dedup_key=dedup_key,
    )


def raw_event(event):
    try:
        return json.loads(event.raw_event or "{}")
    except json.JSONDecodeError:
        return {}


def norder_context(event):
    return raw_event(event).get("contexts", {}).get("norder", {})


def payload_json(event):
    if not event.payload:
        return {}
    try:
        return json.loads(event.payload)
    except (TypeError, json.JSONDecodeError):
        return {}


def network_type(event):
    return norder_context(event).get("network_type")


def is_server_or_cloud(event):
    return network_type(event) in {"server_cloud", "aws", "gcp", "azure", "idc"}


def is_stadium_shared_network(event):
    return network_type(event) in {"stadium_wifi", "stadium_nat"}


def is_bot_user_agent(event):
    user_agent = (event.user_agent or "").lower()
    bot_tokens = ["python-requests", "curl", "sqlmap", "bot", "headless", "scrapy"]
    return any(token in user_agent for token in bot_tokens)
