from app.models.alert import Alert


def make_alert(rule_id, rule_name, severity, source_ip, endpoint, title, description, evidence, dedup_key):
    return Alert(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        source_ip=source_ip,
        endpoint=endpoint,
        title=title,
        description=description,
        evidence=evidence,
        dedup_key=dedup_key,
    )
