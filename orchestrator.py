"""
Threat Orchestrator
Coordinates all detection modules and aggregates results.
"""
import asyncio
import logging
from typing import List
from tqdm import tqdm  # type: ignore

from config import Config
from models import EmailMessage, EmailThreatResult, ThreatIndicator, ThreatType
from phishing_detector import PhishingDetector
from link_detector import MaliciousLinkDetector
from sender_detector import SpoofedSenderDetector
from spam_detector import SpamDetector
from social_engineering_detector import SocialEngineeringDetector
from attachment_scanner import AttachmentScanner


class ThreatOrchestrator:
    """
    Runs all detectors concurrently on each email and aggregates results.
    """

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger

        # ── Initialize all detection modules ───────────────────────────────────
        self.detectors = [
            PhishingDetector(config),
            MaliciousLinkDetector(config),
            SpoofedSenderDetector(config),
            SpamDetector(config),
            SocialEngineeringDetector(config),
        ]

        if config.scan_attachments:
            self.attachment_scanner = AttachmentScanner(config)
        else:
            self.attachment_scanner = None

        self.logger.info(
            f"Orchestrator ready: {len(self.detectors)} detectors"
            + (", attachment scanning ON" if self.attachment_scanner else "")
        )

    async def analyze_single(self, email: EmailMessage) -> EmailThreatResult:
        """Run all detectors on a single email concurrently."""
        result = EmailThreatResult(email=email)

        try:
            # Run all detectors in parallel
            tasks = [detector.analyze(email) for detector in self.detectors]

            if self.attachment_scanner and email.attachments:
                tasks.append(self.attachment_scanner.scan(email))

            indicator_lists = await asyncio.gather(*tasks, return_exceptions=True)

            for item in indicator_lists:
                if isinstance(item, Exception):
                    self.logger.warning(f"Detector error for {email.message_id}: {item}")
                elif isinstance(item, list):
                    result.indicators.extend(item)

            # Filter indicators below threshold
            result.indicators = [
                i for i in result.indicators
                if i.score >= self.config.threshold
            ]

            result.compute_overall()

        except Exception as e:
            result.error = str(e)
            self.logger.error(f"Failed to analyze email {email.message_id}: {e}")

        return result

    async def analyze_batch(self, emails: List[EmailMessage]) -> List[EmailThreatResult]:
        """Analyze a list of emails with progress tracking."""
        results = []
        sem = asyncio.Semaphore(5)  # Max 5 concurrent analyses

        async def bounded_analyze(email):
            async with sem:
                return await self.analyze_single(email)

        tasks = [bounded_analyze(e) for e in emails]

        self.logger.info(f"Starting analysis of {len(emails)} emails...")
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks),
                         desc="Analyzing", unit="email"):
            result = await coro
            results.append(result)

        # Sort: threats first, then by score descending
        results.sort(key=lambda r: r.overall_score, reverse=True)
        self._log_summary(results)
        return results

    def _log_summary(self, results: List[EmailThreatResult]):
        threats = [r for r in results if r.is_threat]
        self.logger.info(
            f"Analysis complete: {len(results)} emails scanned, "
            f"{len(threats)} threats detected "
            f"({len(results) - len(threats)} clean)"
        )
