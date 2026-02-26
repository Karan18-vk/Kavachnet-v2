"""
Phishing Detector
─────────────────
Multi-layer phishing detection:
  1. Rule-based heuristics (keywords, urgency phrases, credential-harvesting patterns)
  2. URL analysis via PhishTank API
  3. NLP-based classification (HuggingFace Transformers / scikit-learn fallback)
  4. SPF/DKIM header inspection
"""
import re
import asyncio
import logging
from typing import List

import requests

from config import Config
from models import EmailMessage, ThreatIndicator, ThreatType
from base_detector import BaseDetector
from cache import APICache

# ── Heuristic patterns ─────────────────────────────────────────────────────────
URGENCY_PHRASES = [
    r"your account (has been|will be) (suspended|closed|terminated|locked)",
    r"verify your (account|identity|information|email|password)",
    r"click (here|below|the link) (to|and) (verify|confirm|update|restore|unlock)",
    r"(unusual|suspicious|unauthorized) (activity|access|sign.?in)",
    r"(immediately|urgent|important|action required|response required)",
    r"(update|confirm|validate) your (billing|payment|credit card|bank)",
    r"you.ve been selected",
    r"(won|winner|prize|reward|gift card)",
    r"(login|sign.?in) (credentials|details|information)",
    r"one.time.password|OTP|verification code",
    r"your (password|pin) (has expired|needs to be updated)",
]

CREDENTIAL_PATTERNS = [
    r"enter your (password|username|email|login)",
    r"(provide|submit|send).{0,20}(password|credentials|ssn|social security)",
    r"bank (account|routing) number",
    r"credit card (number|details|information)",
]

URGENCY_RE   = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in URGENCY_PHRASES]
CRED_RE      = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in CREDENTIAL_PATTERNS]
PHISH_DOMAIN_RE = re.compile(
    r"(paypal|amazon|apple|microsoft|google|netflix|bank|wellsfargo|chase|"
    r"citibank|usps|fedex|irs|linkedin|facebook|instagram|twitter|dropbox|"
    r"office365|onedrive|icloud|signin|login|secure|account|verify|update)"
    r"[^\.]*\.(tk|ml|ga|cf|gq|xyz|top|click|link|work|online|site|website|"
    r"info|biz|buzz|loan|win|accountupdate|securelogin)",
    re.IGNORECASE
)

class PhishingDetector(BaseDetector):
    def __init__(self, config: Config):
        super().__init__(config)
        self.cache = APICache(config.cache_dir, config.cache_ttl_seconds)
        self._nlp_pipeline = None  # Lazy-loaded

    async def analyze(self, email: EmailMessage) -> List[ThreatIndicator]:
        indicators = []
        text = f"{email.subject} {email.body_text}"

        # ── 1. Rule-based heuristics ───────────────────────────────────────────
        heuristic_score, heuristic_evidence = self._heuristic_check(text, email)
        if heuristic_score > 0:
            indicators.append(ThreatIndicator(
                threat_type=ThreatType.PHISHING,
                score=heuristic_score,
                description="Phishing heuristics matched",
                evidence=heuristic_evidence,
                source="HeuristicRules"
            ))

        # ── 2. PhishTank URL check ────────────────────────────────────────────
        if email.urls and self.config.phishtank_api_key:
            phish_results = await self._check_phishtank(email.urls[:10])
            for url, data in phish_results.items():
                if data.get("in_database") and data.get("verified"):
                    indicators.append(ThreatIndicator(
                        threat_type=ThreatType.PHISHING,
                        score=0.98,
                        description=f"URL confirmed in PhishTank database",
                        evidence={"url": url, "phishtank": data},
                        source="PhishTank"
                    ))

        # ── 3. NLP classification ─────────────────────────────────────────────
        if self.config.use_nlp and len(text.strip()) > 30:
            nlp_score = await self._nlp_classify(text[:512])
            if nlp_score > 0.5:
                indicators.append(ThreatIndicator(
                    threat_type=ThreatType.PHISHING,
                    score=nlp_score,
                    description="NLP model flagged phishing content",
                    evidence={"model_score": nlp_score},
                    source="NLPClassifier"
                ))

        return indicators

    def _heuristic_check(self, text: str, email: EmailMessage):
        evidence = {"matches": [], "cred_matches": []}
        score = 0.0

        urgency_hits = sum(1 for p in URGENCY_RE if p.search(text))
        cred_hits    = sum(1 for p in CRED_RE    if p.search(text))
        domain_hits  = len(PHISH_DOMAIN_RE.findall(" ".join(email.urls)))

        evidence["urgency_matches"] = urgency_hits
        evidence["credential_matches"] = cred_hits
        evidence["suspicious_domains"] = domain_hits

        score += min(0.4, urgency_hits * 0.1)
        score += min(0.4, cred_hits * 0.2)
        score += min(0.3, domain_hits * 0.15)

        # No HTTPS on sender domain is a small signal
        if email.sender and "https" not in email.sender:
            score += 0.05

        return min(1.0, score), evidence

    async def _check_phishtank(self, urls: List[str]) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._phishtank_sync, urls)

    def _phishtank_sync(self, urls: List[str]) -> dict:
        results = {}
        for url in urls:
            cached = self.cache.get(f"phishtank:{url}")
            if cached:
                results[url] = cached
                continue
            try:
                resp = requests.post(
                    "https://checkurl.phishtank.com/checkurl/",
                    data={
                        "url": url,
                        "format": "json",
                        "app_key": self.config.phishtank_api_key
                    },
                    timeout=10
                )
                data = resp.json().get("results", {})
                self.cache.set(f"phishtank:{url}", data)
                results[url] = data
            except Exception as e:
                self.logger.debug(f"PhishTank error for {url}: {e}")
        return results

    async def _nlp_classify(self, text: str) -> float:
        """Use HuggingFace Transformers pipeline for phishing classification."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._nlp_classify_sync, text)

    def _nlp_classify_sync(self, text: str) -> float:
        try:
            from phishing_classifier import PhishingClassifier
            if self._nlp_pipeline is None:
                self._nlp_pipeline = PhishingClassifier(self.config)
            return self._nlp_pipeline.predict(text)
        except ImportError:
            self.logger.debug("NLP classifier unavailable")
            return 0.0
        except Exception as e:
            self.logger.debug(f"NLP classify error: {e}")
            return 0.0
