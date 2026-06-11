import json
from app.models.event import Event


def normalize_sentry_event(raw):
    return Event(
        source="sentry",
        source_event_id=raw.get("event_id"),
        source_issue_id=raw.get("issue_id"),
        timestamp=raw.get("timestamp"),
        event_type=infer_event_type(raw),
        source_ip=raw.get("source_ip"),
        user_id_hash=raw.get("user_id"),
        session_id_hash=raw.get("session_id"),
        endpoint=raw.get("endpoint"),
        method=raw.get("method"),
        status_code=raw.get("status_code"),
        user_agent=raw.get("user_agent"),
        payload=raw.get("payload"),
        exception_type=raw.get("exception_type"),
        message=raw.get("message"),
        raw_event=json.dumps(raw, ensure_ascii=False),
    )


def infer_event_type(raw):
    endpoint = raw.get("endpoint") or ""
    text = f"{raw.get('title') or ''} {raw.get('message') or ''} {raw.get('exception_type') or ''}".lower()
    if endpoint == "/norder/api/common/sms/request":
        return "sms_error"
    if "auth" in text or raw.get("status_code") in (401, 403):
        return "auth_error"
    if raw.get("status_code") == 404:
        return "not_found"
    if raw.get("status_code", 0) >= 500:
        return "server_error"
    return "sentry_error"
