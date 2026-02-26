"""
Spoofed Sender Detector
───────────────────────
Detects sender spoofing via:
  1. SPF header validation (Received-SPF / Authentication-Results)
  2. DKIM signature verification
  3. DMARC header inspection
  4. Display name vs actual domain mismatch (e.g., "PayPal <attacker@evil.com>")
  5. Reply-To / Return-Path anomalies
  6. Live DNS SPF record lookup via dnspython
"""
import re
import asyncio
import logging
from email.utils import parseaddr
from typing import List, Optional

from config import Config
from models import EmailMessage, ThreatIndicator, ThreatType
from base_detector import BaseDetector


KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "hotmail.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "instagram": ["instagram.com"],
    "irs": ["irs.gov"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "wellsfargo": ["wellsfargo.com"],
    "chase": ["chase.com", "jpmorgan.com"],
    "bankofamerica": ["bankofamerica.com"],
}


class SpoofedSenderDetector(BaseDetector):
    def __init__(self, config: Config):
        super().__init__(config)

    async def analyze(self, email: EmailMessage) -> List[ThreatIndicator]:
        indicators = []
        headers = {k.lower(): v for k, v in email.headers.items()}

        # ── 1. Authentication-Results header ──────────────────────────────────
        auth_result = headers.get("authentication-results", "")
        spf_pass   = self._check_auth_result(auth_result, "spf")
        dkim_pass  = self._check_auth_result(auth_result, "dkim")
        dmarc_pass = self._check_auth_result(auth_result, "dmarc")

        failed = [label for label, ok in [("SPF", spf_pass), ("DKIM", dkim_pass), ("DMARC", dmarc_pass)] if ok is False]
        if failed:
            score = 0.3 * len(failed)
            indicators.append(ThreatIndicator(
                threat_type=ThreatType.SPOOFED_SENDER,
                score=min(1.0, score),
                description=f"Email authentication failed: {', '.join(failed)}",
                evidence={
                    "spf": spf_pass, "dkim": dkim_pass, "dmarc": dmarc_pass,
                    "auth_results": auth_result
                },
                source="EmailAuthentication"
            ))

        # ── 2. Display-name spoofing ───────────────────────────────────────────
        display_spoof = self._check_display_name_spoof(email)
        if display_spoof:
            indicators.append(ThreatIndicator(
                threat_type=ThreatType.SPOOFED_SENDER,
                score=0.85,
                description=display_spoof["description"],
                evidence=display_spoof,
                source="DisplayNameSpoof"
            ))

        # ── 3. Reply-To / Return-Path mismatch ───────────────────────────────
        reply_to    = headers.get("reply-to", "")
        return_path = headers.get("return-path", "")
        from_addr   = email.sender

        from_domain   = self._extract_domain(from_addr)
        reply_domain  = self._extract_domain(reply_to) if reply_to else None
        return_domain = self._extract_domain(return_path) if return_path else None

        if reply_domain and reply_domain != from_domain:
            indicators.append(ThreatIndicator(
                threat_type=ThreatType.SPOOFED_SENDER,
                score=0.65,
                description=f"Reply-To domain differs from From domain",
                evidence={
                    "from_domain": from_domain,
                    "reply_to_domain": reply_domain,
                    "reply_to": reply_to
                },
                source="ReplyToMismatch"
            ))

        if return_domain and return_domain != from_domain:
            indicators.append(ThreatIndicator(
                threat_type=ThreatType.SPOOFED_SENDER,
                score=0.55,
                description=f"Return-Path domain differs from From domain",
                evidence={
                    "from_domain": from_domain,
                    "return_path_domain": return_domain
                },
                source="ReturnPathMismatch"
            ))

        # ── 4. Live DNS SPF lookup ─────────────────────────────────────────────
        if from_domain:
            spf_dns = await self._lookup_spf(from_domain)
            if spf_dns is False:
                indicators.append(ThreatIndicator(
                    threat_type=ThreatType.SPOOFED_SENDER,
                    score=0.4,
                    description=f"Sender domain {from_domain} has no SPF DNS record",
                    evidence={"domain": from_domain},
                    source="DNSSPFCheck"
                ))

        return indicators

    def _check_auth_result(self, auth_header: str, protocol: str) -> Optional[bool]:
        """Parse Authentication-Results header for SPF/DKIM/DMARC pass/fail."""
        if not auth_header:
            return None
        pattern = re.compile(rf"{protocol}=(\S+)", re.IGNORECASE)
        match = pattern.search(auth_header)
        if not match:
            return None
        result = match.group(1).lower().strip(";")
        if result.startswith("pass"):   return True
        if result.startswith("fail"):   return False
        if result.startswith("none"):   return None
        return None

    def _check_display_name_spoof(self, email: EmailMessage) -> Optional[dict]:
        """Detect brand name in display-name while actual email is from other domain."""
        display_name, addr = parseaddr(email.sender)
        display_lower = display_name.lower()

        for brand, legit_domains in KNOWN_BRANDS.items():
            if brand in display_lower:
                actual_domain = self._extract_domain(addr)
                if actual_domain and not any(
                    actual_domain.endswith(d) for d in legit_domains
                ):
                    return {
                        "description": (
                            f"Display name '{display_name}' impersonates '{brand}' "
                            f"but email is from '{actual_domain}'"
                        ),
                        "brand": brand,
                        "display_name": display_name,
                        "actual_address": addr,
                        "actual_domain": actual_domain,
                        "expected_domains": legit_domains
                    }
        return None

    def _extract_domain(self, address: str) -> str:
        """Extract domain from an email address or display-name string."""
        _, addr = parseaddr(address)
        if "@" in addr:
            return addr.split("@", 1)[1].lower().strip(">")
        return ""

    async def _lookup_spf(self, domain: str) -> Optional[bool]:
        """Check if domain has an SPF TXT record in DNS."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._dns_spf_sync, domain)

    def _dns_spf_sync(self, domain: str) -> Optional[bool]:
        try:
            import dns.resolver  # type: ignore
            answers = dns.resolver.resolve(domain, "TXT")
            for rdata in answers:
                for string in rdata.strings:
                    if string.startswith(b"v=spf1"):
                        return True
            return False
        except Exception:
            return None
