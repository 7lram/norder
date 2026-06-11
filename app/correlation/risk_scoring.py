SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def score_alerts(alerts):
    base = max(SEVERITY_ORDER.get(alert.severity, 1) for alert in alerts) * 20
    volume = min(len(alerts) * 5, 25)
    boost = 0
    rule_ids = {alert.rule_id for alert in alerts}
    if "PAYLOAD-001" in rule_ids or "LEAK-001" in rule_ids:
        boost += 25
    if "SMS-001" in rule_ids or "ADMIN-001" in rule_ids:
        boost += 15
    score = min(base + volume + boost, 100)
    severity = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"
    return score, severity
