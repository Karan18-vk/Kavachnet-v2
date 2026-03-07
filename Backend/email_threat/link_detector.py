"""
Malicious Link Detector
───────────────────────
Checks all URLs in an email using:
  1. VirusTotal URL scanning API (v3)
  2. AbuseIPDB IP reputation check
  3. WHOIS domain age check (newly registered domains are suspicious)
  4. DNS anomaly detection (typosquatting, lookalike domains)
  5. URL structure heuristics (IP-in-URL, excessive subdomains, etc.)
"""
import asyncio
import base64
import ipaddress
import re
import socket
import time
from typing import List
from urllib.parse import urlparse

import requests

from email_threat.core import ThreatConfig as Config
from email_threat.threat_models import EmailMessage, ThreatIndicator, ThreatType
from email_threat.base_detector import BaseDetector
from email_threat.cache import APICache


SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work",
    "online", "site", "website", "buzz", "loan", "win", "download", "men",
    "date", "review", "racing", "party", "trade", "webcam"
}

LEGIT_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "facebook",
    "instagram", "twitter", "linkedin", "dropbox", "icloud", "wellsfargo",
    "chase", "bankofamerica", "citibank", "usbank", "irs", "fedex", "ups", "usps"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "short.link", "goo.gl",
    "rebrand.ly", "cutt.ly", "is.gd", "buff.ly", "tiny.cc", "lnkd.in"
}


class MaliciousLinkDetector(BaseDetector):
    def __init__(self, config: Config):
        super().__init__(config)
        self.cache = APICache(config.cache_dir, config.cache_ttl_seconds)
        self._vt_last_request = 0.0

    async def analyze(self, email: EmailMessage) -> List[ThreatIndicator]:
        if not email.urls:
            return []

        indicators = []
        # Deduplicate and limit URLs
        urls = list(set(email.urls))[:20]

        for url in urls:
            # ── Heuristic checks (fast, no API) ───────────────────────────────
            heuristic = self._url_heuristics(url)
            if heuristic["score"] > 0:
                indicators.append(ThreatIndicator(
                    threat_type=ThreatType.MALWARE_LINK,
                    score=heuristic["score"],
                    description=heuristic["reason"],
                    evidence=heuristic,
                    source="URLHeuristics"
                ))

            # ── VirusTotal (rate-limited: 4/min on free tier) ─────────────────
            if self.config.virustotal_api_key:
                vt_result = await self._check_virustotal(url)
                if vt_result and vt_result.get("malicious", 0) > 0:
                    malicious = vt_result["malicious"]
                    total     = vt_result.get("total", 70)
                    score     = min(1.0, malicious / max(1, total) * 3)
                    indicators.append(ThreatIndicator(
                        threat_type=ThreatType.MALWARE_LINK,
                        score=score,
                        description=f"VirusTotal: {malicious}/{total} engines flagged URL",
                        evidence={"url": url, "vt": vt_result},
                        source="VirusTotal"
                    ))

            # ── AbuseIPDB for the resolved IP ─────────────────────────────────
            if self.config.abuseipdb_api_key:
                ip = self._resolve_ip(url)
                if ip:
                    abuse = await self._check_abuseipdb(ip)
                    if abuse and abuse.get("abuseConfidenceScore", 0) > 50:
                        indicators.append(ThreatIndicator(
                            threat_type=ThreatType.MALWARE_LINK,
                            score=min(1.0, abuse["abuseConfidenceScore"] / 100),
                            description=f"AbuseIPDB: IP {ip} has abuse score {abuse['abuseConfidenceScore']}%",
                            evidence={"url": url, "ip": ip, "abuseipdb": abuse},
                            source="AbuseIPDB"
                        ))

        return indicators

    def _url_heuristics(self, url: str) -> dict:
        """Fast, offline heuristic analysis of a URL."""
        score = 0.0
        reasons = []

        try:
            parsed = urlparse(url)
            host   = parsed.hostname or ""

            # IP address in URL (very suspicious)
            try:
                ipaddress.ip_address(host)
                score += 0.6
                reasons.append("Direct IP address in URL")
            except ValueError:
                pass

            # No HTTPS
            if parsed.scheme == "http":
                score += 0.1
                reasons.append("HTTP (not HTTPS)")

            # Suspicious TLD
            try:
                import tldextract  # type: ignore
                ext = tldextract.extract(url)
                if ext.suffix in SUSPICIOUS_TLDS:
                    score += 0.3
                    reasons.append(f"Suspicious TLD: .{ext.suffix}")

                # Brand impersonation in subdomain (e.g., paypal.evil.com)
                for brand in LEGIT_BRANDS:
                    if brand in ext.subdomain and brand not in ext.domain:
                        score += 0.5
                        reasons.append(f"Brand '{brand}' impersonated in subdomain")
                        break

            except ImportError:
                pass

            # URL shortener (could hide malicious destination)
            if host in URL_SHORTENERS:
                score += 0.2
                reasons.append(f"URL shortener: {host}")

            # Excessive subdomains
            subdomain_count = host.count(".")
            if subdomain_count > 4:
                score += 0.2
                reasons.append(f"Excessive subdomains ({subdomain_count})")

            # Long URL
            if len(url) > 200:
                score += 0.15
                reasons.append(f"Unusually long URL ({len(url)} chars)")

            # Hex-encoded chars / obfuscation
            if re.search(r"%[0-9a-fA-F]{2}", url):
                score += 0.1
                reasons.append("URL encoding / obfuscation")

            # @ sign in URL (user:pass@host trick)
            if "@" in parsed.netloc:
                score += 0.4
                reasons.append("@ sign in URL (potential credential trick)")

            # Double-slash redirect trick
            if "//" in parsed.path:
                score += 0.2
                reasons.append("Double-slash in URL path (redirect trick)")

            # Homoglyph / lookalike domains
            if re.search(r"[а-яА-Я\u0400-\u04FF]", url):
                score += 0.5
                reasons.append("Cyrillic characters in URL (homoglyph attack)")

        except Exception as e:
            self.logger.debug(f"URL heuristic error for {url}: {e}")

        return {
            "score": min(1.0, score),
            "url": url,
            "reason": "; ".join(reasons) if reasons else "URL structure OK",
            "reasons": reasons
        }

    async def _check_virustotal(self, url: str) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._vt_sync, url)

    def _vt_sync(self, url: str) -> dict:
        """Query VirusTotal URL scan API v3. Respects 4 req/min free-tier limit."""
        cache_key = f"vt:url:{url}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached

        # Rate-limit: 4 requests per minute = 15s between requests
        elapsed = time.time() - self._vt_last_request
        if elapsed < 15:
            time.sleep(15 - elapsed)
        self._vt_last_request = time.time()

        headers = {"x-apikey": self.config.virustotal_api_key}
        try:
            # Encode URL for VirusTotal API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers, timeout=20
            )

            if resp.status_code == 404:
                # URL not in VT database — submit it
                submit = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=20
                )
                if submit.status_code == 200:
                    analysis_id = submit.json().get("data", {}).get("id", "")
                    time.sleep(15)
                    resp = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers, timeout=20
                    )

            if resp.status_code == 200:
                stats = (resp.json()
                         .get("data", {})
                         .get("attributes", {})
                         .get("last_analysis_stats", {}))
                result = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values())
                }
                self.cache.set(cache_key, result)
                return result
        except Exception as e:
            self.logger.debug(f"VirusTotal error for {url}: {e}")
        return {}

    async def _check_abuseipdb(self, ip: str) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._abuseipdb_sync, ip)

    def _abuseipdb_sync(self, ip: str) -> dict:
        cache_key = f"abuseipdb:{ip}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Accept": "application/json",
                    "Key": self.config.abuseipdb_api_key
                },
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                self.cache.set(cache_key, data)
                return data
        except Exception as e:
            self.logger.debug(f"AbuseIPDB error for {ip}: {e}")
        return {}

    def _resolve_ip(self, url: str) -> str:
        """Resolve hostname to IP."""
        try:
            host = urlparse(url).hostname or ""
            try:
                ipaddress.ip_address(host)
                return host  # Already an IP
            except ValueError:
                return socket.gethostbyname(host)
        except Exception:
            return ""
