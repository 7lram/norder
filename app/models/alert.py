from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str
    source_ip: Optional[str]
    endpoint: Optional[str]
    title: str
    description: str
    evidence: Dict[str, Any]
    dedup_key: str

    def to_dict(self):
        return asdict(self)
