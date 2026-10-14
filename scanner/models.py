from dataclasses import dataclass, field


@dataclass
class Finding:
    id: str
    title: str
    severity: str  
    description: str
    remediation: str
    accounts: list = field(default_factory=list)