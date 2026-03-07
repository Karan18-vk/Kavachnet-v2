"""
Base Detector Class
Provides common initialization and utilities for all detectors.
"""
import logging
from typing import List

from email_threat.core import ThreatConfig as Config
from email_threat.threat_models import ThreatIndicator


class BaseDetector:
    """Base class for all threat detectors."""

    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)

    async def analyze(self, email) -> List[ThreatIndicator]:
        """
        Analyze an email and return threat indicators.
        Must be implemented by subclasses.
        """
        raise NotImplementedError("Subclasses must implement analyze()")
