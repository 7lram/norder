def explain_incident(incident):
    return (
        f"{incident.title} was classified as {incident.incident_type}. "
        f"Severity={incident.severity}, events={incident.event_count}, "
        f"recommended_playbook={incident.recommended_playbook}."
    )
