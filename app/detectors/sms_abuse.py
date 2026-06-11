from collections import defaultdict
from app.detectors.common import (
    is_bot_user_agent,
    is_server_or_cloud,
    is_stadium_shared_network,
    make_alert,
    norder_context,
    payload_json,
)


def detect(events, config):
    thresholds = config["thresholds"]
    by_ip = defaultdict(list)
    by_phone = defaultdict(list)
    for event in events:
        if event.event_type == "sms_error":
            by_ip[event.source_ip].append(event)
            phone = payload_json(event).get("user_phone")
            if phone:
                by_phone[phone].append(event)

    alerts = []
    for event in events:
        if event.event_type != "sms_error":
            continue
        if is_server_or_cloud(event) or is_bot_user_agent(event):
            alerts.append(make_alert(
                "SMS-001",
                "SMS API abuse candidate",
                "high",
                event.source_ip,
                event.endpoint,
                "SMS 인증 API 남용 의심",
                "SMS request came from an automation-like client or server/cloud network.",
                {
                    "issue_id": event.source_issue_id,
                    "network_type": norder_context(event).get("network_type"),
                    "user_agent": event.user_agent,
                    "reason": "server_or_cloud_or_bot_client",
                },
                f"SMS-001:{event.source_ip}:{event.source_event_id}",
            ))

    for source_ip, items in by_ip.items():
        if not source_ip:
            continue
        if is_stadium_shared_network(items[0]):
            continue
        threshold = _sms_threshold(items[0], thresholds)
        if len(items) >= threshold:
            alerts.append(make_alert(
                "SMS-001",
                "SMS API abuse candidate",
                "high",
                source_ip,
                "/norder/api/common/sms/request",
                "SMS 인증 API 남용 의심",
                "SMS 인증 API에서 같은 IP의 오류 이벤트가 시간대 기준치를 초과했습니다.",
                {
                    "event_count": len(items),
                    "threshold": threshold,
                    "network_type": norder_context(items[0]).get("network_type"),
                    "game_phase": norder_context(items[0]).get("game_phase"),
                    "issue_ids": sorted({e.source_issue_id for e in items if e.source_issue_id}),
                },
                f"SMS-001:ip:{source_ip}",
            ))

    phone_threshold = thresholds.get("sms_same_phone_threshold", 2)
    for phone, items in by_phone.items():
        if len(items) >= phone_threshold:
            source_ips = sorted({item.source_ip for item in items if item.source_ip})
            alerts.append(make_alert(
                "SMS-002",
                "Repeated SMS to same phone",
                "high",
                source_ips[0] if source_ips else None,
                "/norder/api/common/sms/request",
                "동일 전화번호 대상 SMS 반복 요청",
                "Stadium Wi-Fi can share one IP, so repeated SMS to the same phone number is treated as the stronger signal.",
                {
                    "phone_hash": phone,
                    "event_count": len(items),
                    "source_ips": source_ips,
                    "issue_ids": sorted({e.source_issue_id for e in items if e.source_issue_id}),
                },
                f"SMS-002:phone:{phone}",
            ))
    return alerts


def _sms_threshold(event, thresholds):
    phase = norder_context(event).get("game_phase")
    if phase in {"pre_game", "entry_time"}:
        return thresholds.get("sms_entry_time_threshold", thresholds["sms_abuse_threshold"])
    if phase in {"off_day", "late_night"}:
        return thresholds.get("sms_off_hours_threshold", 2)
    return thresholds["sms_abuse_threshold"]
