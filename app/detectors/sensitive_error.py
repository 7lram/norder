from app.detectors.common import make_alert


def detect(events, config):
    keywords = config["patterns"]["sensitive_keywords"]
    leak_indicators = ("exposed", "leak", "token=", "secret=", "authorization:")
    alerts = []
    for event in events:
        text = f"{event.message or ''}".lower()
        matched = [keyword for keyword in keywords if keyword in text]
        if not matched or not any(indicator in text for indicator in leak_indicators):
            continue
        alerts.append(make_alert(
            "LEAK-001",
            "Sensitive error exposure",
            "critical",
            event.source_ip,
            event.endpoint,
            "민감 정보가 포함된 에러 메시지",
            "Sentry 에러 메시지에 token/secret 계열 민감정보 노출 징후가 있습니다.",
            {"matched_keywords": matched, "issue_id": event.source_issue_id},
            f"LEAK-001:{event.source_issue_id}",
        ))
    return alerts
