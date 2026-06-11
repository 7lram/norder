from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Event:
    source: str
    source_event_id: str
    source_issue_id: Optional[str]
    timestamp: str
    event_type: str
    source_ip: Optional[str]
    user_id_hash: Optional[str]
    session_id_hash: Optional[str]
    endpoint: Optional[str]
    method: Optional[str]
    status_code: Optional[int]
    user_agent: Optional[str]
    payload: Optional[str]
    exception_type: Optional[str]
    message: Optional[str]
    raw_event: str

    def to_dict(self):
        return asdict(self)
