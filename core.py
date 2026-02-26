"""
=============================================================
  EMAIL THREAT DETECTION SYSTEM — core.py
  Core configuration data and constants
=============================================================
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class ThreatConfig:
    # ── Threat Intelligence APIs ───────────────────────────
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    phishtank_api_key: str = os.getenv("PHISHTANK_API_KEY", "")

    # ── Gmail (OAuth 2.0) ──────────────────────────────────
    gmail_credentials_path: str = "credentials/gmail_credentials.json"
    gmail_token_path: str = "credentials/gmail_token.json"

    # ── Microsoft Outlook (MSAL / Graph API) ───────────────
    ms_client_id: str = os.getenv("MS_CLIENT_ID", "")
    ms_tenant_id: str = os.getenv("MS_TENANT_ID", "common")
    ms_client_secret: str = os.getenv("MS_CLIENT_SECRET", "")

    # ── IMAP / POP3 ────────────────────────────────────────
    imap_host: str = os.getenv("IMAP_HOST", "")
    imap_port: int = 993
    imap_use_ssl: bool = True
    pop3_host: str = os.getenv("POP3_HOST", "")
    pop3_port: int = 995
    pop3_use_ssl: bool = True

    # ── Detection settings ─────────────────────────────────
    threshold: float = 0.6
    limit: int = 50
    use_nlp: bool = True
    nlp_model: str = "distilbert-base-uncased-finetuned-sst-2-english"
    use_gpu: bool = False

    # ── Attachment scanning ────────────────────────────────
    scan_attachments: bool = True
    max_attachment_size_mb: int = 25

    # ── ClamAV ─────────────────────────────────────────────
    clamav_host: str = os.getenv("CLAMAV_HOST", "127.0.0.1")
    clamav_port: int = 3310

    # ── Cache ──────────────────────────────────────────────
    cache_dir: str = ".cache"
    cache_ttl_seconds: int = 3600


# Default instances
THREAT_CFG = ThreatConfig()