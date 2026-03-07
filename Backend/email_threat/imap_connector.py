"""
IMAP Connector — uses Python's built-in imaplib.
Supports SSL/TLS and STARTTLS. Works with any IMAP-compatible server
(Gmail IMAP, Yahoo, Exchange, Dovecot, etc.)
"""
import email
import imaplib
import logging
from datetime import datetime
from typing import List, Optional

from email_threat.core import ThreatConfig as Config
from email_threat.threat_models import EmailMessage
from email_threat.email_parser import parse_email_body, extract_urls_from_html, extract_urls_from_text


class IMAPConnector:
    def __init__(self, config: Config, host: str, port: int,
                 user: str, password: str, folder: str = "INBOX"):
        self.config  = config
        self.host    = host
        self.port    = port
        self.user    = user
        self.password = password
        self.folder  = folder
        self.logger  = logging.getLogger(__name__)

    def _connect(self) -> imaplib.IMAP4_SSL:
        self.logger.info(f"Connecting to IMAP {self.host}:{self.port} as {self.user}")
        if self.config.imap_use_ssl:
            conn = imaplib.IMAP4_SSL(self.host, self.port)
        else:
            conn = imaplib.IMAP4(self.host, self.port)
            conn.starttls()
        conn.login(self.user, self.password)
        self.logger.info("IMAP login successful")
        return conn

    async def fetch_emails(self, limit: int = 50,
                           since: Optional[str] = None) -> List[EmailMessage]:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._fetch_sync, limit, since)

    def _fetch_sync(self, limit: int, since: Optional[str]) -> List[EmailMessage]:
        conn = self._connect()
        try:
            conn.select(self.folder, readonly=True)

            # Build search criteria
            criteria = "ALL"
            if since:
                # IMAP date format: DD-Mon-YYYY
                dt = datetime.strptime(since, "%Y-%m-%d")
                imap_date = dt.strftime("%d-%b-%Y")
                criteria = f'SINCE "{imap_date}"'

            typ, data = conn.search(None, criteria)
            if typ != "OK":
                raise RuntimeError(f"IMAP search failed: {typ}")

            all_ids = data[0].split()
            # Take the most recent `limit` messages
            msg_ids = all_ids[-limit:]
            self.logger.info(f"Fetching {len(msg_ids)} of {len(all_ids)} messages")

            emails = []
            for uid in reversed(msg_ids):   # Newest first
                try:
                    typ2, msg_data = conn.fetch(uid, "(RFC822)")
                    if typ2 != "OK":
                        continue
                    raw = msg_data[0][1]
                    parsed = email.message_from_bytes(raw)
                    emails.append(self._convert(uid.decode(), parsed))
                except Exception as e:
                    self.logger.warning(f"Failed to parse message {uid}: {e}")

            return emails
        finally:
            try:
                conn.close()
                conn.logout()
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
            provider="imap"
        )
