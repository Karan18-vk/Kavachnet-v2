"""
Authentication Manager
Handles OAuth 2.0 (Gmail), MSAL (Microsoft), and credential-based (IMAP/POP3) auth.
"""
import logging
from typing import Optional
from config import Config


class AuthManager:
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)

    async def get_connector(self, provider: str, host: Optional[str] = None,
                            port: Optional[int] = None, user: Optional[str] = None,
                            folder: str = "INBOX"):
        """Factory: returns the appropriate connector for the given provider."""
        if provider == "gmail":
            from gmail_connector import GmailConnector
            return GmailConnector(self.config, folder=folder)

        elif provider == "outlook":
            from outlook_connector import OutlookConnector
            return OutlookConnector(self.config, folder=folder)

        elif provider == "imap":
            from imap_connector import IMAPConnector
            _host = host or self.config.imap_host
            _port = port or self.config.imap_port
            if not _host:
                raise ValueError("IMAP host is required (--host or imap_host in config)")
            if not user:
                user = input("IMAP username: ")
            import getpass
            password = getpass.getpass("IMAP password: ")
            return IMAPConnector(self.config, host=_host, port=_port,
                                 user=user, password=password, folder=folder)

        elif provider == "pop3":
            from pop3_connector import POP3Connector
            _host = host or self.config.pop3_host
            _port = port or self.config.pop3_port
            if not _host:
                raise ValueError("POP3 host is required")
            if not user:
                user = input("POP3 username: ")
            import getpass
            password = getpass.getpass("POP3 password: ")
            return POP3Connector(self.config, host=_host, port=_port,
                                 user=user, password=password)

        else:
            raise ValueError(f"Unknown provider: {provider}")
