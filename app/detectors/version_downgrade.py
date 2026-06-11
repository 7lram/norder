from collections import defaultdict

from app.detectors.common import is_server_or_cloud, make_alert, norder_context


def detect(events, config):
    alerts = []
    alerts.extend(_detect_v1_sensitive_success(events))
    alerts.extend(_detect_v2_block_then_v1_success(events))
    return alerts


def _detect_v1_sensitive_success(events):
    alerts = []
    sensitive_paths = ["/orders", "/payments", "/users", "/auth"]
    for event in events:
        endpoint = event.endpoint or ""
        if "/api/v1/" not in endpoint:
            continue
        if not any(path in endpoint for path in sensitive_paths):
            continue
        if event.status_code and event.status_code >= 400:
            continue

        context = norder_context(event)
        severity = "critical" if is_server_or_cloud(event) or context.get("game_phase") in {"off_day", "late_night"} else "high"
        alerts.append(make_alert(
            "VERSION-001",
            "Legacy v1 API sensitive success",
            severity,
            event.source_ip,
            event.endpoint,
            "구버전 v1 민감 API 접근 성공",
            "The current app is expected to use v2, so successful access to a sensitive v1 API is suspicious.",
            {
                "issue_id": event.source_issue_id,
                "status_code": event.status_code,
                "network_type": context.get("network_type"),
                "game_phase": context.get("game_phase"),
            },
            f"VERSION-001:{event.source_ip}:{event.endpoint}:{event.source_event_id}",
        ))
    return alerts


def _detect_v2_block_then_v1_success(events):
    by_identity = defaultdict(list)
    for event in events:
        identity = event.session_id_hash or event.user_id_hash or event.source_ip
        if identity:
            by_identity[identity].append(event)

    alerts = []
    for identity, items in by_identity.items():
        blocked_v2 = [
            event for event in items
            if "/api/v2/" in (event.endpoint or "") and event.status_code in {401, 403}
        ]
        successful_v1 = [
            event for event in items
            if "/api/v1/" in (event.endpoint or "") and (event.status_code is None or event.status_code < 400)
        ]
        if not blocked_v2 or not successful_v1:
            continue

        first = successful_v1[0]
        alerts.append(make_alert(
            "VERSION-002",
            "v2 blocked then v1 success",
            "critical",
            first.source_ip,
            first.endpoint,
            "v2 차단 직후 v1 우회 성공",
            "The same identity was blocked on v2 and then succeeded through a legacy v1 path.",
            {
                "identity": identity,
                "blocked_v2_endpoints": sorted({event.endpoint for event in blocked_v2 if event.endpoint}),
                "successful_v1_endpoints": sorted({event.endpoint for event in successful_v1 if event.endpoint}),
                "issue_ids": sorted({event.source_issue_id for event in items if event.source_issue_id}),
            },
            f"VERSION-002:{identity}",
        ))
    return alerts
