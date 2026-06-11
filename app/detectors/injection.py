from app.detectors.common import make_alert


def detect(events, config):
    patterns = config["patterns"]["sqli"] + config["patterns"]["xss"]
    alerts = []
    for event in events:
        text = f"{event.endpoint or ''} {event.message or ''} {event.payload or ''}".lower()
        matched = [pattern for pattern in patterns if pattern in text]
        if not matched:
            continue
        is_sqli = any(pattern in matched for pattern in config["patterns"]["sqli"])
        alerts.append(make_alert(
            "PAYLOAD-001",
            "SQL/XSS payload exception",
            "critical" if is_sqli else "high",
            event.source_ip,
            event.endpoint,
            "SQL/XSS 페이로드 포함 요청으로 인한 예외",
            "Sentry 이벤트에서 SQLi 또는 XSS 의심 페이로드가 발견되었습니다.",
            {"matched_patterns": matched, "issue_id": event.source_issue_id, "payload": event.payload},
            f"PAYLOAD-001:{event.source_ip}:{event.endpoint}:{event.source_issue_id}",
        ))
    return alerts
