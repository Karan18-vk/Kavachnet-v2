"""
=============================================================
  EMAIL THREAT DETECTION SYSTEM — config.py
  Central configuration: API keys, thresholds, model paths
=============================================================
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class APIConfig:
    # ── VirusTotal ──────────────────────────────────────────
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VT_KEY")
    virustotal_url_scan: str = "https://www.virustotal.com/api/v3/urls"
    virustotal_file_scan: str = "https://www.virustotal.com/api/v3/files"
    virustotal_analysis: str = "https://www.virustotal.com/api/v3/analyses"

    # ── AbuseIPDB ───────────────────────────────────────────
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "YOUR_ABUSEIPDB_KEY")
    abuseipdb_url: str = "https://api.abuseipdb.com/api/v2/check"

    # ── PhishTank ───────────────────────────────────────────
    phishtank_api_key: str = os.getenv("PHISHTANK_API_KEY", "YOUR_PHISHTANK_KEY")
    phishtank_url: str = "https://checkurl.phishtank.com/checkurl/"

    # ── Google OAuth (Gmail API) ────────────────────────────
    gmail_credentials_file: str = os.getenv("GMAIL_CREDENTIALS_FILE", "credentials.json")
    gmail_token_file: str = "token.json"
    gmail_scopes: list = field(default_factory=lambda: [
        "https://www.googleapis.com/auth/gmail.readonly"
    ])

    # ── Microsoft Graph (Outlook) ───────────────────────────
    ms_client_id: str = os.getenv("MS_CLIENT_ID", "YOUR_MS_CLIENT_ID")
    ms_client_secret: str = os.getenv("MS_CLIENT_SECRET", "YOUR_MS_SECRET")
    ms_tenant_id: str = os.getenv("MS_TENANT_ID", "YOUR_MS_TENANT_ID")
    ms_authority: str = field(init=False)
    ms_scope: list = field(default_factory=lambda: ["https://graph.microsoft.com/.default"])

    def __post_init__(self):
        self.ms_authority = f"https://login.microsoftonline.com/{self.ms_tenant_id}"


@dataclass
class IMAPConfig:
    host: str = os.getenv("IMAP_HOST", "imap.gmail.com")
    port: int = 993
    username: str = os.getenv("EMAIL_USER", "")
    password: str = os.getenv("EMAIL_PASS", "")
    use_ssl: bool = True
    mailbox: str = "INBOX"
    fetch_limit: int = 50        # max emails to fetch per run


@dataclass
class POPConfig:
    host: str = os.getenv("POP_HOST", "pop.gmail.com")
    port: int = 995
    username: str = os.getenv("EMAIL_USER", "")
    password: str = os.getenv("EMAIL_PASS", "")


@dataclass
class ThreatConfig:
    # Scoring thresholds (0–100)
    phishing_threshold: float = 0.65
    spam_threshold: float = 0.70
    malware_threshold: int = 1       # VirusTotal detections needed to flag
    ip_abuse_threshold: int = 25     # AbuseIPDB confidence score
    link_scan_timeout: int = 10      # seconds per URL
    max_attachment_size_mb: int = 25

    # Suspicious TLDs often abused in phishing
    suspicious_tlds: list = field(default_factory=lambda: [
        "xyz", "top", "club", "online", "site", "work",
        "tk", "ml", "ga", "cf", "gq", "pw", "buzz"
    ])

    # Keywords common in social-engineering attacks
    social_engineering_keywords: list = field(default_factory=lambda: [
        "urgent", "verify your account", "click here immediately",
        "you have won", "suspended", "unusual activity",
        "confirm your identity", "wire transfer", "gift card",
        "limited time", "act now", "your password", "invoice attached",
        "dear customer", "billing information", "update your payment"
    ])

    # Dangerous attachment extensions
    dangerous_extensions: list = field(default_factory=lambda: [
        ".exe", ".bat", ".cmd", ".scr", ".vbs", ".js",
        ".jar", ".ps1", ".sh", ".msi", ".dll", ".hta",
        ".docm", ".xlsm", ".pptm", ".lnk", ".iso", ".img"
    ])


@dataclass
class NLPConfig:
    model_name: str = "distilbert-base-uncased-finetuned-sst-2-english"
    # For a fine-tuned phishing model, swap with a HuggingFace hub path:
    # model_name: str = "ealvaradob/bert-finetuned-phishing"
    max_length: int = 512
    use_gpu: bool = False


# ── Singleton instances used across modules ─────────────────
API_CFG = APIConfig()
IMAP_CFG = IMAPConfig()
POP_CFG = POPConfig()
THREAT_CFG = ThreatConfig()
NLP_CFG = NLPConfig()
