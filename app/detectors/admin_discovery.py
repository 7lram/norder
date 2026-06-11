from collections import defaultdict
from app.detectors.common import make_alert


def detect(events, config):
    threshold = config["thresholds"]["admin_scan_threshold"]
    admin_paths = config["patterns"]["admin_paths"]
    grouped = defaultdict(list)
    for event in events:
        endpoint = event.endpoint or ""
        if any(endpoint.startswith(path) for path in admin_paths):
            grouped[event.source_ip].append(event)

    alerts = []
    for source_ip, items in grouped.items():
        if source_ip and len(items) >= threshold:
            alerts.append(make_alert(
                "ADMIN-001",
                "Admin path discovery",
                "high",
                source_ip,
                None,
                "관리자/숨겨진 경로 스캔",
                "같은 IP에서 관리자 후보 경로 접근이 반복되었습니다.",
                {"paths": [e.endpoint for e in items], "issue_ids": sorted({e.source_issue_id for e in items if e.source_issue_id})},
                f"ADMIN-001:{source_ip}",
            ))
    return alerts
