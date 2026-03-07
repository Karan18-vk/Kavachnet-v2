"""
Attachment Scanner
──────────────────
Multi-layer attachment analysis:
  1. File type validation via python-magic (MIME sniffing — never trust extensions)
  2. SHA-256 hash lookup on VirusTotal
  3. ClamAV real-time AV scan via pyclamd
  4. Dangerous extension / content-type detection
  5. Macro-enabled Office document detection
"""
import asyncio
import time
import logging
from typing import List

import requests

from email_threat.core import ThreatConfig as Config
from email_threat.threat_models import EmailMessage, Attachment, ThreatIndicator, ThreatType
from email_threat.cache import APICache


DANGEROUS_EXTENSIONS = {
    ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".vbe",
    ".js",  ".jse", ".ws",  ".wsf", ".wsc", ".wsh", ".ps1", ".ps2",
    ".msi", ".msp", ".jar", ".hta", ".cpl", ".inf", ".reg",
    ".lnk", ".url", ".dll", ".sys", ".drv", ".ocx",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xltm"}

DANGEROUS_MAGIC = {
    "application/x-dosexec",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-sh",
    "application/x-csh",
    "application/x-msdos-program",
}


class AttachmentScanner:
    def __init__(self, config: Config):
        self.config = config
        self.cache = APICache(config.cache_dir, config.cache_ttl_seconds)
        self.logger = logging.getLogger(__name__)
        self._clamav = None
        self._vt_last_req = 0.0

    async def scan(self, email: EmailMessage) -> List[ThreatIndicator]:
        if not email.attachments:
            return []
        indicators = []
        for att in email.attachments:
            indicators.extend(await self._scan_one(att))
        return indicators

    async def _scan_one(self, att: Attachment) -> List[ThreatIndicator]:
        indicators = []
        import os
        ext = os.path.splitext(att.filename or "")[1].lower()

        # ── 1. Extension check ────────────────────────────────────────────────
        if ext in DANGEROUS_EXTENSIONS:
            indicators.append(ThreatIndicator(
                threat_type=ThreatType.MALICIOUS_ATTACH,
                score=0.90,
                description=f"Dangerous file type: {att.filename}",
                evidence={"filename": att.filename, "extension": ext},
                source="ExtensionCheck"
            ))
        elif ext in MACRO_EXTENSIONS:
            indicators.append(ThreatIndicator(
                threat_type=ThreatType.MALICIOUS_ATTACH,
                score=0.65,
                description=f"Macro-enabled Office doc: {att.filename}",
                evidence={"filename": att.filename, "extension": ext},
                source="MacroCheck"
            ))

        # ── 2. MIME magic sniffing ─────────────────────────────────────────────
        if att.data:
            actual_type = self._detect_mime(att.data)
            if actual_type in DANGEROUS_MAGIC:
                indicators.append(ThreatIndicator(
                    threat_type=ThreatType.MALICIOUS_ATTACH,
                    score=0.93,
                    description=f"Executable disguised as {att.filename}",
                    evidence={"claimed": att.content_type, "actual": actual_type},
                    source="MagicMIME"
                ))
            elif actual_type and actual_type != att.content_type:
                indicators.append(ThreatIndicator(
                    threat_type=ThreatType.MALICIOUS_ATTACH,
                    score=0.45,
                    description=f"MIME type mismatch in {att.filename}",
                    evidence={"claimed": att.content_type, "actual": actual_type},
                    source="MIMEMismatch"
                ))

        # ── 3. VirusTotal hash lookup ─────────────────────────────────────────
        if att.sha256 and self.config.virustotal_api_key:
            vt = await self._vt_hash(att.sha256)
            if vt.get("malicious", 0) > 0:
                score = min(1.0, vt["malicious"] / max(1, vt.get("total", 70)) * 3)
                indicators.append(ThreatIndicator(
                    threat_type=ThreatType.MALICIOUS_ATTACH,
                    score=score,
                    description=f"VirusTotal: {vt['malicious']}/{vt.get('total',70)} engines detected malware",
                    evidence={"filename": att.filename, "sha256": att.sha256, **vt},
                    source="VirusTotalHash"
                ))

        # ── 4. ClamAV live scan ────────────────────────────────────────────────
        if att.data and att.size_bytes <= self.config.max_attachment_size_mb * 1024 * 1024:
            sig = await self._clam_scan(att.data)
            if sig:
                indicators.append(ThreatIndicator(
                    threat_type=ThreatType.MALICIOUS_ATTACH,
                    score=0.97,
                    description=f"ClamAV detected: {sig}",
                    evidence={"filename": att.filename, "signature": sig},
                    source="ClamAV"
                ))

        return indicators

    def _detect_mime(self, data: bytes) -> str:
        try:
            import magic  # type: ignore
            return magic.from_buffer(data, mime=True)
        except ImportError:
            self.logger.debug("python-magic not installed")
        except Exception as e:
            self.logger.debug(f"MIME detect error: {e}")
        return ""

    async def _vt_hash(self, sha256: str) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._vt_hash_sync, sha256)

    def _vt_hash_sync(self, sha256: str) -> dict:
        cached = self.cache.get(f"vt:hash:{sha256}")
        if cached:
            return cached
        elapsed = time.time() - self._vt_last_req
        if elapsed < 15:
            time.sleep(15 - elapsed)
        self._vt_last_req = time.time()
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": self.config.virustotal_api_key},
                timeout=15
            )
            if r.status_code == 200:
                stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                result = {
                    "malicious": stats.get("malicious",0),
                    "suspicious": stats.get("suspicious",0),
                    "harmless": stats.get("harmless",0),
                    "total": sum(stats.values())
                }
                self.cache.set(f"vt:hash:{sha256}", result)
                return result
        except Exception as e:
            self.logger.debug(f"VT hash error: {e}")
        return {}

    async def _clam_scan(self, data: bytes) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._clam_sync, data)

    def _clam_sync(self, data: bytes) -> str:
        try:
            import pyclamd  # type: ignore
            if self._clamav is None:
                try:
                    self._clamav = pyclamd.ClamdNetworkSocket(
                        host=self.config.clamav_host, port=self.config.clamav_port
                    )
                    if not self._clamav.ping():
                        self._clamav = None
                        return ""
                except Exception:
                    self._clamav = None
                    return ""
            result = self._clamav.instream(data)
            if result and result.get("stream"):
                status, sig = result["stream"]
                if status == "FOUND":
                    return sig
        except ImportError:
            self.logger.debug("pyclamd not installed")
        except Exception as e:
            self.logger.debug(f"ClamAV error: {e}")
        return ""
