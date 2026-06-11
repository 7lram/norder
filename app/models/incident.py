from dataclasses import dataclass, asdict
from typing import Optional, List


@dataclass
class Incident:
    incident_type: str
    severity: str
    title: str
    source_ip: Optional[str]
    endpoint: Optional[str]
    alert_ids: List[int]
    sentry_issue_ids: List[str]
    event_count: int
    summary: str
    recommended_playbook: str

    def to_dict(self):
        return asdict(self)
