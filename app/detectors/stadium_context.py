import json
from collections import defaultdict
from datetime import datetime

from app.detectors.common import make_alert


def detect(events, config):
    alerts = []
    alerts.extend(_detect_order_entry_flow_bypass(events, config))
    alerts.extend(_detect_seat_block_hop(events, config))
    alerts.extend(_detect_peak_error_cluster(events, config))
    alerts.extend(_detect_simultaneous_venue_access(events, config))
    alerts.extend(_detect_ghost_venue_access(events, config))
    alerts.extend(_detect_outside_game_schedule_activity(events, config))
    alerts.extend(_detect_untrusted_network_activity(events, config))
    alerts.extend(_detect_direct_payment_without_prior_flow(events))
    return alerts


def _detect_order_entry_flow_bypass(events, config):
    alerts = []
    for event in events:
        context = _stadium_context(event)
        if not _is_peak_phase(context, config):
            continue
        if not _is_state_changing_order_request(event, config):
            continue
        if _has_valid_order_entry_context(context, config):
            continue

        alerts.append(make_alert(
            "STADIUM-001",
            "Order entry flow bypass during stadium peak time",
            "high",
            event.source_ip,
            event.endpoint,
            "정상 주문 진입 경로 없는 상태 변경 요청",
            "A state-changing order request occurred during a stadium peak phase without a valid QR or Kakao app entry context.",
            {
                "issue_id": event.source_issue_id,
                "game_phase": context.get("game_phase"),
                "seat_block": context.get("seat_block"),
                "network_type": context.get("network_type"),
                "entry_channel": context.get("entry_channel"),
                "qr_scan_id": context.get("qr_scan_id"),
                "kakao_session_id": context.get("kakao_session_id"),
            },
            f"stadium-entry-bypass:{event.source_ip}:{event.endpoint}",
        ))
    return alerts


def _detect_seat_block_hop(events, config):
    grouped = defaultdict(list)
    for event in events:
        if "/orders" not in (event.endpoint or ""):
            continue
        context = _stadium_context(event)
        seat_block = context.get("seat_block")
        if not seat_block:
            continue
        identity = event.session_id_hash or event.user_id_hash or event.source_ip
        grouped[identity].append((event, context))

    threshold = config.get("thresholds", {}).get("seat_block_hop_threshold", 2)
    alerts = []
    for identity, items in grouped.items():
        seat_blocks = sorted({context.get("seat_block") for _, context in items if context.get("seat_block")})
        if len(seat_blocks) < threshold:
            continue

        timestamps = [_parse_timestamp(event.timestamp) for event, _ in items if event.timestamp]
        timestamps = [value for value in timestamps if value is not None]
        if timestamps and (max(timestamps) - min(timestamps)).total_seconds() > 300:
            continue

        first_event, first_context = items[0]
        alerts.append(make_alert(
            "STADIUM-002",
            "Seat block movement anomaly",
            "medium",
            first_event.source_ip,
            first_event.endpoint,
            "짧은 시간 내 비정상 좌석 블록 이동",
            "The same user, session, or IP generated order events from multiple seat blocks within five minutes.",
            {
                "issue_ids": sorted({event.source_issue_id for event, _ in items if event.source_issue_id}),
                "identity": identity,
                "seat_blocks": seat_blocks,
                "game_phase": first_context.get("game_phase"),
                "network_type": first_context.get("network_type"),
            },
            f"stadium-seat-hop:{identity}",
        ))
    return alerts


def _detect_peak_error_cluster(events, config):
    groups = defaultdict(list)
    for event in events:
        context = _stadium_context(event)
        if not _is_peak_phase(context, config):
            continue
        if event.status_code is None or event.status_code < 400:
            continue
        key = (context.get("game_phase"), context.get("network_type"), event.endpoint)
        groups[key].append((event, context))

    threshold = config.get("thresholds", {}).get("stadium_peak_error_threshold", 3)
    alerts = []
    for (game_phase, network_type, endpoint), items in groups.items():
        if len(items) < threshold:
            continue

        first_event, _ = items[0]
        seat_blocks = sorted({context.get("seat_block") for _, context in items if context.get("seat_block")})
        alerts.append(make_alert(
            "STADIUM-003",
            "Stadium peak endpoint error cluster",
            "high",
            first_event.source_ip,
            endpoint,
            "경기장 피크 시간대 특정 API 오류 급증",
            "Errors increased on the same endpoint during a stadium-specific traffic peak such as inning break or cleaning time.",
            {
                "issue_ids": sorted({event.source_issue_id for event, _ in items if event.source_issue_id}),
                "event_count": len(items),
                "game_phase": game_phase,
                "network_type": network_type,
                "seat_blocks": seat_blocks,
            },
            f"stadium-peak-errors:{game_phase}:{network_type}:{endpoint}",
        ))
    return alerts


def _detect_simultaneous_venue_access(events, config):
    grouped = defaultdict(list)
    for event in events:
        context = _stadium_context(event)
        venue_id = context.get("venue_id")
        if not venue_id:
            continue
        identity = event.session_id_hash or event.user_id_hash
        if identity:
            grouped[identity].append((event, context))

    window_seconds = config.get("thresholds", {}).get("simultaneous_venue_window_seconds", 600)
    alerts = []
    for identity, items in grouped.items():
        venues = sorted({context.get("venue_id") for _, context in items if context.get("venue_id")})
        if len(venues) < 2:
            continue

        timestamps = [_parse_timestamp(event.timestamp) for event, _ in items if event.timestamp]
        timestamps = [value for value in timestamps if value is not None]
        if timestamps and (max(timestamps) - min(timestamps)).total_seconds() > window_seconds:
            continue

        first_event, first_context = items[0]
        alerts.append(make_alert(
            "STADIUM-004",
            "Simultaneous multi-venue access",
            "critical",
            first_event.source_ip,
            first_event.endpoint,
            "짧은 시간 내 서로 다른 구장 접근",
            "The same user or session accessed multiple venues within a short window.",
            {
                "identity": identity,
                "venues": venues,
                "window_seconds": window_seconds,
                "network_type": first_context.get("network_type"),
                "issue_ids": sorted({event.source_issue_id for event, _ in items if event.source_issue_id}),
            },
            f"STADIUM-004:{identity}",
        ))
    return alerts


def _detect_ghost_venue_access(events, config):
    known_venues = set(config.get("stadium", {}).get("known_venues", []))
    if not known_venues:
        return []

    alerts = []
    for event in events:
        context = _stadium_context(event)
        venue_id = context.get("venue_id")
        if not venue_id or venue_id in known_venues:
            continue
        alerts.append(make_alert(
            "STADIUM-005",
            "Ghost venue access",
            "high",
            event.source_ip,
            event.endpoint,
            "화이트리스트에 없는 유령 구장 접근",
            "The request references a venue that is not in the configured valid venue whitelist.",
            {
                "issue_id": event.source_issue_id,
                "venue_id": venue_id,
                "known_venues": sorted(known_venues),
                "network_type": context.get("network_type"),
            },
            f"STADIUM-005:{event.source_ip}:{venue_id}:{event.source_event_id}",
        ))
    return alerts


def _detect_outside_game_schedule_activity(events, config):
    alerts = []
    for event in events:
        if _inside_game_schedule(event.timestamp, config):
            continue
        if not _is_sensitive_game_request(event):
            continue

        context = _stadium_context(event)
        severity = "critical" if context.get("network_type") in {"server_cloud", "vpn", "overseas"} else "high"
        alerts.append(make_alert(
            "STADIUM-006",
            "Outside game schedule activity",
            severity,
            event.source_ip,
            event.endpoint,
            "경기 일정 밖 민감 요청",
            "A sensitive Norder request occurred outside the configured game schedule.",
            {
                "issue_id": event.source_issue_id,
                "timestamp": event.timestamp,
                "network_type": context.get("network_type"),
                "game_phase": context.get("game_phase"),
            },
            f"STADIUM-006:{event.source_ip}:{event.endpoint}:{event.source_event_id}",
        ))
    return alerts


def _detect_untrusted_network_activity(events, config):
    untrusted = set(config.get("network", {}).get("untrusted_network_types", ["server_cloud", "vpn", "overseas", "unknown"]))
    alerts = []
    for event in events:
        context = _stadium_context(event)
        if context.get("network_type") not in untrusted:
            continue
        if not _is_sensitive_game_request(event):
            continue
        alerts.append(make_alert(
            "STADIUM-007",
            "Untrusted network sensitive request",
            "high",
            event.source_ip,
            event.endpoint,
            "신뢰 대역 밖 민감 요청",
            "A sensitive request came from a stubbed untrusted network type such as cloud, VPN, overseas, or unknown.",
            {
                "issue_id": event.source_issue_id,
                "network_type": context.get("network_type"),
                "trusted_network_types": config.get("network", {}).get("trusted_network_types", []),
            },
            f"STADIUM-007:{event.source_ip}:{event.endpoint}:{event.source_event_id}",
        ))
    return alerts


def _detect_direct_payment_without_prior_flow(events):
    grouped = defaultdict(list)
    for event in events:
        identity = event.session_id_hash or event.user_id_hash or event.source_ip
        if identity:
            grouped[identity].append(event)

    alerts = []
    for identity, items in grouped.items():
        sorted_items = sorted(items, key=lambda event: event.timestamp or "")
        seen_prior_order_flow = False
        for event in sorted_items:
            endpoint = event.endpoint or ""
            if any(path in endpoint for path in ["/cart", "/orders"]):
                seen_prior_order_flow = True
            if "/payments" not in endpoint:
                continue
            if seen_prior_order_flow:
                continue

            context = _stadium_context(event)
            alerts.append(make_alert(
                "STADIUM-008",
                "Direct payment without prior order flow",
                "critical",
                event.source_ip,
                event.endpoint,
                "선행 주문 단계 없는 결제 API 직접 호출",
                "A payment API was called before cart or order flow appeared for the same user, session, or IP.",
                {
                    "identity": identity,
                    "issue_id": event.source_issue_id,
                    "entry_channel": context.get("entry_channel"),
                    "network_type": context.get("network_type"),
                    "venue_id": context.get("venue_id"),
                },
                f"STADIUM-008:{identity}:{event.endpoint}",
            ))
    return alerts


def _stadium_context(event):
    try:
        raw = json.loads(event.raw_event or "{}")
    except json.JSONDecodeError:
        raw = {}
    contexts = raw.get("contexts", {})
    return contexts.get("norder", {})


def _is_peak_phase(context, config):
    peak_phases = config.get("stadium", {}).get("peak_phases", ["pre_game", "inning_break", "cleaning_time", "post_game"])
    return context.get("game_phase") in peak_phases


def _inside_game_schedule(timestamp, config):
    parsed = _parse_timestamp(timestamp)
    if parsed is None:
        return True
    schedules = config.get("stadium", {}).get("game_schedules", [])
    if not schedules:
        return True
    for schedule in schedules:
        start = _parse_timestamp(schedule.get("start"))
        end = _parse_timestamp(schedule.get("end"))
        if start and end and start <= parsed <= end:
            return True
    return False


def _is_sensitive_game_request(event):
    endpoint = event.endpoint or ""
    if any(path in endpoint for path in ["/sms", "/auth", "/orders", "/payments", "/cart", "/venues"]):
        return True
    return event.status_code is not None and event.status_code >= 400


def _is_state_changing_order_request(event, config):
    methods = {"POST", "PUT", "PATCH", "DELETE"}
    if (event.method or "").upper() not in methods:
        return False
    endpoint = event.endpoint or ""
    protected_paths = config.get("stadium", {}).get("state_change_paths", ["/orders", "/payments", "/cart"])
    return any(path in endpoint for path in protected_paths)


def _has_valid_order_entry_context(context, config):
    entry_channel = context.get("entry_channel")
    if context.get("qr_scan_id"):
        return True

    allowed_channels = config.get("stadium", {}).get("allowed_entry_channels", ["qr", "kakao_app"])
    if entry_channel not in allowed_channels:
        return False

    if entry_channel == "qr":
        return bool(context.get("qr_scan_id"))

    if entry_channel == "kakao_app":
        return bool(context.get("kakao_session_id") and (context.get("venue_id") or context.get("store_id")))

    return True


def _parse_timestamp(value):
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
