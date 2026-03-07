"""
Spam Detector
─────────────
Rule-based spam detection using:
  1. Spam keyword patterns (classic Bayesian-style signals)
  2. HTML/text ratio analysis
  3. Excessive caps / punctuation
  4. Bulk-sending header signals (Precedence, X-Mailer, List-Unsubscribe)
  5. SpamAssassin-style scoring
"""
import re
from typing import List

from email_threat.core import ThreatConfig as Config
from email_threat.threat_models import EmailMessage, ThreatIndicator, ThreatType
from email_threat.base_detector import BaseDetector


SPAM_KEYWORDS = [
    # Commercial / promotional spam
    r"\bfree\b.{0,30}\b(offer|trial|gift|shipping|download|access)\b",
    r"\b(buy|order|purchase).{0,20}\b(now|today|online|here)\b",
    r"\b(discount|sale|% off|deal|clearance|promo code)\b",
    r"\b(make money|earn.{0,20}(per day|per week|per hour|fast))\b",
    r"\b(weight loss|lose weight|burn fat|diet pill)\b",
    r"\b(casino|gambling|poker|lottery|jackpot)\b",
    r"\b(enlargement|enhancement|libido|erectile)\b",
    r"\b(viagra|cialis|levitra|pharmacy|prescription)\b",
    r"\b(work from home|home based|home business|be your own boss)\b",
    r"\b(million.{0,10}(dollar|pound|euro|usd))\b",
    r"\b(inheritance|barrister|attorney|next of kin|deceased)\b",
    r"\b(click (here|now|below)|unsubscribe|opt.?out)\b",
]

EXCESSIVE_CAPS_RE = re.compile(r"\b[A-Z]{5,}\b")
EXCESSIVE_PUNCT_RE = re.compile(r"[!?]{2,}")
SPAM_KEYWORD_RE = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in SPAM_KEYWORDS]


class SpamDetector(BaseDetector):
    def __init__(self, config: Config):
        super().__init__(config)

    async def analyze(self, email: EmailMessage) -> List[ThreatIndicator]:
        indicators = []
        text = f"{email.subject} {email.body_text}"

        score, evidence = self._score(text, email)
        if score > 0:
            indicators.append(ThreatIndicator(
                threat_type=ThreatType.SPAM,
                score=min(1.0, score),
                description="Spam signals detected in email content",
                evidence=evidence,
                source="SpamHeuristics"
            ))

        return indicators

    def _score(self, text: str, email: EmailMessage) -> tuple:
        score = 0.0
        evidence = {}

        # ── Keyword matches ───────────────────────────────────────────────────
        hits = [p.pattern[:40] for p in SPAM_KEYWORD_RE if p.search(text)]
        evidence["keyword_hits"] = len(hits)
        evidence["matched_patterns"] = hits[:5]
        score += min(0.5, len(hits) * 0.08)

        # ── Excessive CAPS ────────────────────────────────────────────────────
        caps_words = EXCESSIVE_CAPS_RE.findall(text)
        evidence["caps_words"] = len(caps_words)
        if len(caps_words) > 3:
            score += min(0.2, len(caps_words) * 0.03)

        # ── Excessive punctuation ─────────────────────────────────────────────
        excl_count = len(EXCESSIVE_PUNCT_RE.findall(text))
        evidence["excessive_punctuation"] = excl_count
        score += min(0.15, excl_count * 0.03)

        # ── Bulk email headers ────────────────────────────────────────────────
        headers = {k.lower(): v for k, v in email.headers.items()}
        if "list-unsubscribe" in headers:
            score += 0.1
            evidence["has_list_unsubscribe"] = True
        if headers.get("precedence", "").lower() == "bulk":
            score += 0.2
            evidence["precedence_bulk"] = True

        # ── Subject line checks ───────────────────────────────────────────────
        subject = email.subject or ""
        if re.search(r"\[?(ADV|ADVERTISEMENT|SPONSORED)\]?", subject, re.IGNORECASE):
            score += 0.3
            evidence["ad_subject_tag"] = True
        if re.search(r"FW:|Fwd:|forward", subject, re.IGNORECASE):
            score += 0.05
            evidence["forwarded_subject"] = True

        # ── HTML-only with no text ────────────────────────────────────────────
        if email.body_html and not email.body_text.strip():
            score += 0.1
            evidence["html_only"] = True

        # ── Very high URL-to-text ratio ───────────────────────────────────────
        text_len = len(email.body_text)
        url_count = len(email.urls)
        if text_len > 0 and url_count / max(1, text_len / 100) > 0.5:
            score += 0.15
            evidence["high_url_density"] = True

        return score, evidence
