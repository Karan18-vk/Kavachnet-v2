# Backend/utils/email_providers.py

import os
import json
from abc import ABC, abstractmethod
from typing import Tuple

from config import Config
from utils.email_service import send_email_with_retry
from utils.json_logger import json_metrics_logger

class BaseEmailProvider(ABC):
    @abstractmethod
    def send_email(self, recipient: str, subject: str, html_body: str, text_body: str, max_attempts: int = 3) -> Tuple[bool, int, str]:
        """
        Sends an email payload asynchronously.
        Returns: (success_bool, attempts_made_int, last_error_str)
        """
        pass

class SmtpEmailProvider(BaseEmailProvider):
    def send_email(self, recipient: str, subject: str, html_body: str, text_body: str, max_attempts: int = 3) -> Tuple[bool, int, str]:
        # Employs the existing robust SMTP engine with exponential backoff
        return send_email_with_retry(
            to_email=recipient,
            subject=subject,
            html_content=html_body,
            text_content=text_body,
            max_attempts=max_attempts
        )

class MockEmailProvider(BaseEmailProvider):
    def send_email(self, recipient: str, subject: str, html_body: str, text_body: str, max_attempts: int = 3) -> Tuple[bool, int, str]:
        # Dev/Staging mock provider: serializes to STDOUT without network latency
        payload = {
            "mock_dispatch": True,
            "recipient": recipient,
            "subject": subject,
            "body_length": len(html_body)
        }
        json_metrics_logger.info("MOCK_PROVIDER_DISPATCH", extra={"metrics": payload})
        return True, 1, ""
        
class SesEmailProvider(BaseEmailProvider):
    def send_email(self, recipient: str, subject: str, html_body: str, text_body: str, max_attempts: int = 3) -> Tuple[bool, int, str]:
        # Placeholder for AWS SES Boto3 integration
        last_error = "AWS SES Provider not yet configured with Boto3 credentials."
        json_metrics_logger.error(last_error)
        return False, 1, last_error

def get_email_provider() -> BaseEmailProvider:
    """Factory evaluating the zero-trust environmental configuration."""
    if Config.EMAIL_DRY_RUN or Config.EMAIL_PROVIDER == 'mock':
        return MockEmailProvider()
    elif Config.EMAIL_PROVIDER == 'ses':
        return SesEmailProvider()
    else:
        return SmtpEmailProvider()
