from app.ai.llm_client import analyze_with_external_ai


def explain_incident(incident):
    return (
        f"{incident.title} was classified as {incident.incident_type}. "
        f"Severity={incident.severity}, events={incident.event_count}, "
        f"recommended_playbook={incident.recommended_playbook}."
    )


def analyze_incident(incident, risk_score, use_external_ai=False):
    fallback = {
        "summary": explain_incident(incident),
        "risk_reason": f"Risk score={risk_score}. Rule severity, event volume, and attack indicators were considered.",
        "recommended_playbook": incident.recommended_playbook,
        "source": "local",
        "fallback_reason": "",
    }

    if not use_external_ai:
        return fallback

    try:
        result = analyze_with_external_ai(incident, risk_score)
    except Exception as exc:
        fallback["source"] = "local_fallback"
        fallback["fallback_reason"] = str(exc)
        fallback["risk_reason"] += f" External AI fallback reason: {exc}"
        return fallback

    return {
        "summary": result.get("summary") or fallback["summary"],
        "risk_reason": result.get("risk_reason") or fallback["risk_reason"],
        "recommended_playbook": result.get("recommended_playbook") or fallback["recommended_playbook"],
        "source": "external_ai",
        "fallback_reason": "",
    }
