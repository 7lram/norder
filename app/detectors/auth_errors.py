from collections import defaultdict
from app.detectors.common import make_alert


def detect(events, config):
    threshold = config["thresholds"]["auth_error_repeated"]
    grouped = defaultdict(list)
    for event in events:
        if event.event_type == "auth_error":
            grouped[event.source_ip].append(event)

    alerts = []
    for source_ip, items in grouped.items():
        if source_ip and len(items) >= threshold:
            alerts.append(make_alert(
                "AUTH-001",
                "Repeated authentication errors",
                "high",
                source_ip,
                None,
                "로그인/인증 관련 에러 반복",
                "같은 IP에서 인증 관련 Sentry 이벤트가 반복되었습니다.",
                {"event_count": len(items), "issue_ids": sorted({e.source_issue_id for e in items if e.source_issue_id})},
                f"AUTH-001:{source_ip}",
            ))
    return alerts
