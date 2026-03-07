"""
POP3 Connector — uses Python's built-in poplib.
Note: POP3 has no folder support; it always reads the main mailbox.
"""
import email
import logging
import poplib
from typing import List, Optional

from email_threat.core import ThreatConfig as Config
from email_threat.threat_models import EmailMessage
from email_threat.email_parser import parse_email_body, extract_urls_from_html, extract_urls_from_text


class POP3Connector:
    def __init__(self, config: Config, host: str, port: int,
                 user: str, password: str):
        self.config   = config
        self.host     = host
        self.port     = port
        self.user     = user
        self.password = password
        self.logger   = logging.getLogger(__name__)

    def _connect(self) -> poplib.POP3_SSL:
        self.logger.info(f"Connecting to POP3 {self.host}:{self.port}")
        conn = poplib.POP3_SSL(self.host, self.port)
        conn.user(self.user)
        conn.pass_(self.password)
        self.logger.info(f"POP3 login successful")
        return conn

    async def fetch_emails(self, limit: int = 50,
                           since: Optional[str] = None) -> List[EmailMessage]:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._fetch_sync, limit, since)

    def _fetch_sync(self, limit: int, since: Optional[str]) -> List[EmailMessage]:
        conn = self._connect()
        try:
            num_messages = len(conn.list()[1])
            self.logger.info(f"POP3 mailbox has {num_messages} messages")

            start = max(1, num_messages - limit + 1)
            emails = []
            for i in range(num_messages, start - 1, -1):
                try:
                    raw_lines = conn.retr(i)[1]
                    raw_bytes = b"\n".join(raw_lines)
                    parsed = email.message_from_bytes(raw_bytes)
                    emails.append(self._convert(str(i), parsed))
                except Exception as e:
                    self.logger.warning(f"Failed to parse message {i}: {e}")

            return emails
        finally:
            try:
                conn.quit()
            except Exception:
                pass

    def _convert(self, uid: str, msg: email.message.Message) -> EmailMessage:
        body_text, body_html, attachments = parse_email_body(msg)
        urls = extract_urls_from_html(body_html) + extract_urls_from_text(body_text)

        date_str = msg.get("Date", "")
        try:
            from email.utils import parsedate_to_datetime
            date = parsedate_to_datetime(date_str)
        except Exception:
            date = None

        return EmailMessage(
            message_id=uid,
            subject=msg.get("Subject", "(No Subject)"),
            sender=msg.get("From", ""),
            sender_name=msg.get("From", "").split("<")[0].strip().strip('"'),
            recipients=[msg.get("To", "")],
            date=date,
            body_text=body_text,
            body_html=body_html,
            headers=dict(msg.items()),
            attachments=attachments,
            urls=list(set(urls)),
            raw=msg,
            provider="pop3"
        )
