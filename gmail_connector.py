"""
Gmail Connector — OAuth 2.0 via google-auth + google-api-python-client
Reads emails using the Gmail REST API (no IMAP needed).

Setup:
  1. Create a project at console.cloud.google.com
  2. Enable Gmail API
  3. Create OAuth 2.0 credentials → download as credentials/gmail_credentials.json
  4. First run: browser opens for consent; token cached to credentials/gmail_token.json
"""
import base64
import email
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from config import Config
from models import EmailMessage, Attachment
from email_parser import parse_email_body, extract_urls_from_html, extract_urls_from_text


class GmailConnector:
    SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

    def __init__(self, config: Config, folder: str = "INBOX"):
        self.config = config
        self.folder = folder
        self.service = None
        self.logger = logging.getLogger(__name__)

    def _authenticate(self):
        """OAuth 2.0 flow — opens browser on first run, uses cached token after."""
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build

        creds = None
        token_path = Path(self.config.gmail_token_path)
        creds_path = Path(self.config.gmail_credentials_path)

        if token_path.exists():
            creds = Credentials.from_authorized_user_file(str(token_path), self.SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not creds_path.exists():
                    raise FileNotFoundError(
                        f"Gmail credentials not found at {creds_path}. "
                        "Download from Google Cloud Console → APIs & Services → Credentials."
                    )
                flow = InstalledAppFlow.from_client_secrets_file(str(creds_path), self.SCOPES)
                creds = flow.run_local_server(port=0)

            token_path.parent.mkdir(parents=True, exist_ok=True)
            token_path.write_text(creds.to_json())

        self.service = build("gmail", "v1", credentials=creds)
        self.logger.info("Gmail API authenticated successfully")

    async def fetch_emails(self, limit: int = 50,
                           since: Optional[str] = None) -> List[EmailMessage]:
        """Fetch emails from Gmail using the API."""
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._fetch_sync, limit, since)

    def _fetch_sync(self, limit: int, since: Optional[str]) -> List[EmailMessage]:
        self._authenticate()

        query = f"in:{self.folder.lower()}"
        if since:
            query += f" after:{since}"

        results = self.service.users().messages().list(
            userId="me", q=query, maxResults=limit
        ).execute()

        messages_meta = results.get("messages", [])
        self.logger.info(f"Found {len(messages_meta)} messages in Gmail")

        emails = []
        for meta in messages_meta:
            try:
                msg_data = self.service.users().messages().get(
                    userId="me", id=meta["id"], format="raw"
                ).execute()
                raw_bytes = base64.urlsafe_b64decode(msg_data["raw"])
                parsed = email.message_from_bytes(raw_bytes)
                emails.append(self._convert(meta["id"], parsed))
            except Exception as e:
                self.logger.warning(f"Failed to parse message {meta['id']}: {e}")

        return emails

    def _convert(self, msg_id: str, msg: email.message.Message) -> EmailMessage:
        """Convert a raw email.message.Message into our EmailMessage model."""
        body_text, body_html, attachments = parse_email_body(msg)
        urls = extract_urls_from_html(body_html) + extract_urls_from_text(body_text)

        date_str = msg.get("Date", "")
        try:
            from email.utils import parsedate_to_datetime
            date = parsedate_to_datetime(date_str)
        except Exception:
            date = None

        headers = {k: v for k, v in msg.items()}

        return EmailMessage(
            message_id=msg_id,
            subject=msg.get("Subject", "(No Subject)"),
            sender=msg.get("From", ""),
            sender_name=msg.get("From", "").split("<")[0].strip().strip('"'),
            recipients=[msg.get("To", "")],
            date=date,
            body_text=body_text,
            body_html=body_html,
            headers=headers,
            attachments=attachments,
            urls=list(set(urls)),
            raw=msg,
            provider="gmail"
        )
