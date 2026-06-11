import re
from collections import defaultdict

from app.detectors.common import is_server_or_cloud, make_alert, norder_context


VENUE_PATTERN = re.compile(r"/venues/([^/?#]+)", re.IGNORECASE)


def detect(events, config):
    known_venues = set(config.get("stadium", {}).get("known_venues", []))
    error_tokens = config.get("patterns", {}).get("semantic_error_tokens", ["not found", "invalid venue", "no static resource"])
    grouped = defaultdict(list)

    for event in events:
        text = f"{event.message or ''} {event.payload or ''}".lower()
        if not any(token in text for token in error_tokens):
            continue
        venue_id = _extract_venue_id(event.endpoint or "")
        normalized = _normalize_endpoint(event.endpoint or "")
        grouped[(event.source_ip, normalized)].append((event, venue_id))

    alerts = []
    for (source_ip, normalized), items in grouped.items():
        fake_venue_items = [
            (event, venue_id) for event, venue_id in items
            if venue_id and known_venues and venue_id not in known_venues
        ]
        if not fake_venue_items:
            continue

        first_event, first_venue = fake_venue_items[0]
        context = norder_context(first_event)
        severity = "critical" if is_server_or_cloud(first_event) or len(fake_venue_items) >= 2 else "high"
        alerts.append(make_alert(
            "SEMANTIC-001",
            "HTTP 200 semantic error probing",
            severity,
            source_ip,
            normalized,
            "HTTP 200 응답 내부의 없는 구장 탐색",
            "The response status can look successful, but the body/error message indicates probing for non-existing venues.",
            {
                "normalized_endpoint": normalized,
                "fake_venue_ids": sorted({venue_id for _, venue_id in fake_venue_items}),
                "event_count": len(fake_venue_items),
                "network_type": context.get("network_type"),
                "game_phase": context.get("game_phase"),
                "issue_ids": sorted({event.source_issue_id for event, _ in fake_venue_items if event.source_issue_id}),
            },
            f"SEMANTIC-001:{source_ip}:{normalized}",
        ))
    return alerts


def _extract_venue_id(endpoint):
    match = VENUE_PATTERN.search(endpoint)
    if not match:
        return None
    return match.group(1)


def _normalize_endpoint(endpoint):
    return VENUE_PATTERN.sub("/venues/{venue_id}", endpoint)
