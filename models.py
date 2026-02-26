"""
Data models for emails and threat results.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class ThreatType(str, Enum):
    PHISHING          = "Phishing"
    MALWARE_LINK      = "Malware Link"
    MALICIOUS_ATTACH  = "Malicious Attachment"
    SPOOFED_SENDER    = "Spoofed Sender"
    SPAM              = "Spam"
    SOCIAL_ENGINEERING = "Social Engineering"
    CLEAN             = "Clean"


class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"   # score >= 0.9
    HIGH     = "HIGH"       # score >= 0.7
    MEDIUM   = "MEDIUM"     # score >= 0.5
    LOW      = "LOW"        # score >= 0.3
    NONE     = "NONE"       # score < 0.3

    @classmethod
    def from_score(cls, score: float) -> "ThreatSeverity":
        if score >= 0.9: return cls.CRITICAL
        if score >= 0.7: return cls.HIGH
        if score >= 0.5: return cls.MEDIUM
        if score >= 0.3: return cls.LOW
        return cls.NONE


@dataclass
class Attachment:
    filename: str
    content_type: str
    size_bytes: int
    data: bytes = field(repr=False, default=b"")
    sha256: str = ""
    md5: str = ""


@dataclass
class EmailMessage:
    message_id: str
    subject: str
    sender: str
    sender_name: str
    recipients: list[str]
    date: Optional[datetime]
    body_text: str
    body_html: str
    headers: dict[str, str]
    attachments: list[Attachment] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    raw: Any = field(repr=False, default=None)
    provider: str = ""


@dataclass
class ThreatIndicator:
    threat_type: ThreatType
    score: float                     # 0.0 – 1.0
    description: str
    evidence: dict = field(default_factory=dict)
    source: str = ""                 # Which detector/API raised this


@dataclass
class EmailThreatResult:
    email: EmailMessage
    indicators: list[ThreatIndicator] = field(default_factory=list)
    overall_score: float = 0.0
    severity: ThreatSeverity = ThreatSeverity.NONE
    primary_threat: ThreatType = ThreatType.CLEAN
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    error: Optional[str] = None

    def compute_overall(self):
        """Compute overall threat score as weighted max of indicators."""
        if not self.indicators:
            self.overall_score = 0.0
        else:
            # Weighted: max score + average boost
            scores = [i.score for i in self.indicators]
            self.overall_score = min(1.0, max(scores) * 0.7 + (sum(scores) / len(scores)) * 0.3)
        self.severity = ThreatSeverity.from_score(self.overall_score)
        if self.indicators:
            top = max(self.indicators, key=lambda i: i.score)
            self.primary_threat = top.threat_type
        else:
            self.primary_threat = ThreatType.CLEAN

    @property
    def is_threat(self) -> bool:
        return self.overall_score >= 0.5

    @property
    def threat_types(self) -> list[ThreatType]:
        return list({i.threat_type for i in self.indicators})
