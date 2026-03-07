"""
Email Threat Detection Package
──────────────────────────────
Integrates phishing, spam, social engineering, malware link,
attachment scanning, and sender spoofing detectors into the
KavachNet Backend.
"""

from email_threat.threat_models import (
    EmailMessage, EmailThreatResult, ThreatIndicator,
    ThreatType, ThreatSeverity, Attachment
)
from email_threat.core import ThreatConfig, THREAT_CFG
from email_threat.orchestrator import ThreatOrchestrator

__all__ = [
    "EmailMessage", "EmailThreatResult", "ThreatIndicator",
    "ThreatType", "ThreatSeverity", "Attachment",
    "ThreatConfig", "THREAT_CFG",
    "ThreatOrchestrator",
]
