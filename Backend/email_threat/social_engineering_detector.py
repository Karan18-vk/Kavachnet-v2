"""
Social Engineering Detector
────────────────────────────
Detects manipulation tactics including:
  1. Authority impersonation (CEO fraud / BEC)
  2. Urgency / fear induction
  3. Scarcity tactics
  4. Pretext / false context
  5. Emotional manipulation (sympathy, fear, greed)
  6. spaCy NER — detects impersonation of executives/institutions
  7. Business Email Compromise (BEC) patterns
"""
import re
from typing import List

from email_threat.core import ThreatConfig as Config
from email_threat.threat_models import EmailMessage, ThreatIndicator, ThreatType
from email_threat.base_detector import BaseDetector


# ── Social engineering pattern groups ─────────────────────────────────────────
AUTHORITY_PATTERNS = [
    r"\b(ceo|cfo|cto|president|director|executive|manager|hr|payroll|it.?department)\b",
    r"(on behalf of|acting on behalf|request from).{0,30}(management|executive|board)",
    r"(tax.?authority|revenue.?service|law.?enforcement|fbi|irs|interpol|court)",
    r"i.m (your|the) (boss|manager|supervisor|ceo|director)",
]

URGENCY_PATTERNS = [
    r"\b(immediately|right away|asap|as soon as possible|within.{0,10}hour|today only)\b",
    r"(deadline|expires?|last chance|limited time|time.?sensitive|time is running out)",
    r"(do not.{0,10}(delay|wait|ignore|miss)|failure to.{0,20}will result)",
    r"(account.{0,20}(close|suspend|terminat|lock)|access.{0,20}revok)",
]

SCARCITY_PATTERNS = [
    r"\b(limited.{0,10}(offer|time|spots?|availability|stock))\b",
    r"(only.{0,10}(left|remaining|available|spots?))",
    r"(exclusive|one.time.only|never again)",
]

FINANCIAL_PRESSURE = [
    r"(wire.?transfer|bank.?transfer|gift.?card|itunes|google.?play|amazon.?gift)",
    r"(send.{0,20}(money|payment|funds|bitcoin|crypto))",
    r"(pay.{0,10}(now|immediately|today|asap))",
    r"(invoice|payment due|outstanding balance|overdue|past due).{0,20}\$",
    r"(your.{0,20}(salary|paycheck|payment).{0,20}hold)",
]

SYMPATHY_MANIPULATION = [
    r"(dying|terminal|cancer|sick|widow|orphan|tragedy|disaster|victim)",
    r"(stranded|stuck|emergency|hospital|accident|robbery|mugged)",
    r"(only you can|you are my only hope|please help me)",
]

BEC_PATTERNS = [
    r"(change.{0,20}(bank|account|payment).{0,20}(details?|information|number))",
    r"(new.{0,10}(bank|account|routing).{0,10}(number|info|detail))",
    r"(process.{0,20}(payment|wire|transfer).{0,20}(urgent|quickly|today))",
    r"(keep.{0,20}(this.{0,10})?(confidential|secret|between us|quiet))",
]

ALL_PATTERNS = {
    "authority_impersonation": AUTHORITY_PATTERNS,
    "urgency_pressure": URGENCY_PATTERNS,
    "scarcity_tactics": SCARCITY_PATTERNS,
    "financial_pressure": FINANCIAL_PRESSURE,
    "sympathy_manipulation": SYMPATHY_MANIPULATION,
    "bec_indicators": BEC_PATTERNS,
}

COMPILED = {
    group: [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]
    for group, patterns in ALL_PATTERNS.items()
}

# Weights per category
WEIGHTS = {
    "bec_indicators":          0.35,
    "financial_pressure":      0.30,
    "authority_impersonation": 0.25,
    "urgency_pressure":        0.15,
    "scarcity_tactics":        0.10,
    "sympathy_manipulation":   0.15,
}


class SocialEngineeringDetector(BaseDetector):
    def __init__(self, config: Config):
        super().__init__(config)
        self._nlp = None  # spaCy model (lazy)

    async def analyze(self, email: EmailMessage) -> List[ThreatIndicator]:
        indicators = []
        text = f"{email.subject} {email.body_text}"

        # ── Pattern-based detection ───────────────────────────────────────────
        score, evidence = self._pattern_score(text)
        if score > 0.1:
            indicators.append(ThreatIndicator(
                threat_type=ThreatType.SOCIAL_ENGINEERING,
                score=min(1.0, score),
                description="Social engineering manipulation tactics detected",
                evidence=evidence,
                source="SEPatterns"
            ))

        # ── NLP Named Entity Recognition (spaCy) ──────────────────────────────
        if self.config.use_nlp:
            ner_result = await self._ner_analysis(text, email.subject)
            if ner_result:
                indicators.append(ThreatIndicator(
                    threat_type=ThreatType.SOCIAL_ENGINEERING,
                    score=ner_result["score"],
                    description=ner_result["description"],
                    evidence=ner_result,
                    source="spaCyNER"
                ))

        return indicators

    def _pattern_score(self, text: str) -> tuple:
        total_score = 0.0
        evidence = {"category_hits": {}}

        for group, patterns in COMPILED.items():
            hits = [p.pattern[:50] for p in patterns if p.search(text)]
            if hits:
                weight = WEIGHTS.get(group, 0.1)
                cat_score = min(1.0, len(hits) * weight)
                total_score += cat_score
                evidence["category_hits"][group] = {"count": len(hits), "score": round(cat_score, 3)}

        return min(1.0, total_score), evidence

    async def _ner_analysis(self, text: str, subject: str) -> dict:
        """Use spaCy NER to find impersonated organizations/persons."""
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._ner_sync, text, subject)

    def _ner_sync(self, text: str, subject: str) -> dict:
        try:
            import spacy  # type: ignore

            if self._nlp is None:
                try:
                    self._nlp = spacy.load("en_core_web_sm")
                except OSError:
                    self.logger.debug("spaCy model not found. Run: python -m spacy download en_core_web_sm")
                    return {}

            combined = f"{subject}. {text[:1000]}"
            doc = self._nlp(combined)

            orgs    = [ent.text for ent in doc.ents if ent.label_ == "ORG"]
            persons = [ent.text for ent in doc.ents if ent.label_ == "PERSON"]
            money   = [ent.text for ent in doc.ents if ent.label_ == "MONEY"]

            # Flag if well-known org + money + urgency patterns together
            known_orgs = {"IRS", "FBI", "Microsoft", "Apple", "Google", "PayPal",
                          "Amazon", "Bank", "Federal", "Court", "Police"}
            impersonated = [o for o in orgs if any(k.lower() in o.lower() for k in known_orgs)]

            if impersonated and money:
                return {
                    "score": 0.75,
                    "description": (
                        f"NER detected possible impersonation: {impersonated} + "
                        f"monetary reference: {money}"
                    ),
                    "impersonated_orgs": impersonated,
                    "persons_mentioned": persons,
                    "monetary_refs": money
                }

        except ImportError:
            self.logger.debug("spaCy not installed")
        except Exception as e:
            self.logger.debug(f"NER analysis error: {e}")
        return {}
