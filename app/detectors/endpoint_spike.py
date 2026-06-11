from collections import defaultdict
from app.detectors.common import make_alert


def detect(events, config):
    threshold = config["thresholds"]["endpoint_error_spike"]
    grouped = defaultdict(list)
    for event in events:
        if event.endpoint and (event.status_code and event.status_code >= 400):
            grouped[event.endpoint].append(event)

    alerts = []
    for endpoint, items in grouped.items():
        if len(items) >= threshold:
            alerts.append(make_alert(
                "ENDPOINT-001",
                "Endpoint error spike",
                "medium",
                None,
                endpoint,
                "특정 endpoint 오류율 급증",
                "같은 endpoint에서 Sentry 오류 이벤트가 반복되었습니다.",
                {
                    "event_count": len(items),
                    "source_ips": sorted({e.source_ip for e in items if e.source_ip}),
                    "issue_ids": sorted({e.source_issue_id for e in items if e.source_issue_id}),
                },
                f"ENDPOINT-001:{endpoint}",
            ))
    return alerts
