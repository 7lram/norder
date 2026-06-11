from collections import defaultdict
from app.detectors.common import make_alert


def detect(events, config):
    threshold = config["thresholds"]["ip_error_burst"]
    grouped = defaultdict(list)
    for event in events:
        if event.source_ip and (event.status_code and event.status_code >= 400):
            grouped[event.source_ip].append(event)

    alerts = []
    for source_ip, items in grouped.items():
        if len(items) >= threshold:
            alerts.append(make_alert(
                "IP-001",
                "IP error burst",
                "high",
                source_ip,
                None,
                "동일 IP의 4xx/5xx 오류 급증",
                "같은 IP에서 오류 이벤트가 짧은 시간 내 반복되었습니다.",
                {"event_count": len(items), "endpoints": sorted({e.endpoint for e in items if e.endpoint})},
                f"IP-001:{source_ip}",
            ))
    return alerts
