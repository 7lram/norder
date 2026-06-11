from collections import defaultdict
from app.detectors.common import make_alert


def detect(events, config):
    threshold = config["thresholds"]["sms_abuse_threshold"]
    grouped = defaultdict(list)
    for event in events:
        if event.event_type == "sms_error":
            grouped[event.source_ip].append(event)

    alerts = []
    for source_ip, items in grouped.items():
        if source_ip and len(items) >= threshold:
            alerts.append(make_alert(
                "SMS-001",
                "SMS API abuse candidate",
                "high",
                source_ip,
                "/norder/api/common/sms/request",
                "SMS 인증 API 남용 의심",
                "SMS 인증 API에서 같은 IP의 오류 이벤트가 반복되었습니다.",
                {"event_count": len(items), "issue_ids": sorted({e.source_issue_id for e in items if e.source_issue_id})},
                f"SMS-001:{source_ip}",
            ))
    return alerts
