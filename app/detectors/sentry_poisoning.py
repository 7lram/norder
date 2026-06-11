from collections import defaultdict

from app.detectors.common import is_server_or_cloud, make_alert, norder_context, raw_event


def detect(events, config):
    alerts = []
    alerts.extend(_detect_cloud_dominated_error_source(events, config))
    alerts.extend(_detect_invalid_stadium_context(events, config))
    return alerts


def _detect_cloud_dominated_error_source(events, config):
    threshold = config["thresholds"].get("sentry_cloud_error_threshold", 3)
    grouped = defaultdict(list)
    for event in events:
        if is_server_or_cloud(event):
            grouped[event.source_ip].append(event)

    alerts = []
    for source_ip, items in grouped.items():
        if source_ip and len(items) >= threshold:
            alerts.append(make_alert(
                "SENTRY-001",
                "Sentry event poisoning candidate",
                "high",
                source_ip,
                None,
                "Sentry 가짜 에러 주입 의심",
                "A server or cloud network generated a concentrated volume of Sentry events.",
                {
                    "event_count": len(items),
                    "network_type": norder_context(items[0]).get("network_type"),
                    "issue_ids": sorted({event.source_issue_id for event in items if event.source_issue_id}),
                },
                f"SENTRY-001:{source_ip}",
            ))
    return alerts


def _detect_invalid_stadium_context(events, config):
    known_venues = set(config.get("stadium", {}).get("known_venues", []))
    known_blocks = set(config.get("stadium", {}).get("known_seat_blocks", []))
    if not known_venues and not known_blocks:
        return []

    alerts = []
    for event in events:
        context = norder_context(event)
        venue_id = context.get("venue_id")
        seat_block = context.get("seat_block")
        invalid_venue = venue_id and known_venues and venue_id not in known_venues
        invalid_block = seat_block and known_blocks and seat_block not in known_blocks
        if not invalid_venue and not invalid_block:
            continue

        raw = raw_event(event)
        alerts.append(make_alert(
            "SENTRY-002",
            "Invalid stadium context in Sentry event",
            "medium",
            event.source_ip,
            event.endpoint,
            "존재하지 않는 구장/좌석 컨텍스트 포함 이벤트",
            "The Sentry event references a venue or seat block outside the configured Norder stadium catalog.",
            {
                "issue_id": event.source_issue_id,
                "event_id": raw.get("event_id"),
                "venue_id": venue_id,
                "seat_block": seat_block,
                "invalid_venue": bool(invalid_venue),
                "invalid_block": bool(invalid_block),
            },
            f"SENTRY-002:{event.source_ip}:{venue_id}:{seat_block}:{event.source_event_id}",
        ))
    return alerts
