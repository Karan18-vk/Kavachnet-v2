"""
Microsoft Outlook Connector — Microsoft Graph API via MSAL
Uses device code flow (no browser redirect required).

Setup:
  1. Register an app at portal.azure.com → Azure Active Directory → App registrations
  2. Add permissions: Mail.Read (Microsoft Graph → Delegated)
  3. Set MS_CLIENT_ID, MS_TENANT_ID in config / env vars
"""
import logging
from datetime import datetime
from typing import List, Optional

import requests

from config import Config
from models import EmailMessage, Attachment
from email_parser import extract_urls_from_html, extract_urls_from_text


GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class OutlookConnector:
    def __init__(self, config: Config, folder: str = "Inbox"):
        self.config = config
        self.folder = folder
        self.access_token = None
        self.logger = logging.getLogger(__name__)

    def _authenticate(self):
        """Device code flow — prints a URL+code for the user to authenticate."""
        import msal

        if not self.config.ms_client_id:
            raise ValueError(
                "ms_client_id is required for Outlook. "
                "Set MS_CLIENT_ID env variable or in config.yaml."
            )

        authority = f"https://login.microsoftonline.com/{self.config.ms_tenant_id or 'common'}"
        app = msal.PublicClientApplication(
            client_id=self.config.ms_client_id,
            authority=authority
        )

        # Try silent first (cached accounts)
        accounts = app.get_accounts()
        if accounts:
            result = app.acquire_token_silent(self.config.ms_scopes, account=accounts[0])
            if result and "access_token" in result:
                self.access_token = result["access_token"]
                self.logger.info("Microsoft Graph: using cached token")
                return

        # Device code flow
        flow = app.initiate_device_flow(scopes=self.config.ms_scopes)
        if "user_code" not in flow:
            raise ValueError(f"Device flow failed: {flow.get('error_description')}")

        print(f"\n{'='*60}")
        print("Microsoft Authentication Required:")
        print(f"  URL : {flow['verification_uri']}")
        print(f"  Code: {flow['user_code']}")
        print("Open the URL, enter the code, and sign in.")
        print(f"{'='*60}\n")

        result = app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            raise ValueError(f"Authentication failed: {result.get('error_description')}")

        self.access_token = result["access_token"]
        self.logger.info("Microsoft Graph: authenticated successfully")

    def _graph_get(self, endpoint: str, params: dict = None) -> dict:
        headers = {"Authorization": f"Bearer {self.access_token}"}
        resp = requests.get(f"{GRAPH_BASE}{endpoint}", headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()

    async def fetch_emails(self, limit: int = 50,
                           since: Optional[str] = None) -> List[EmailMessage]:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._fetch_sync, limit, since)

    def _fetch_sync(self, limit: int, since: Optional[str]) -> List[EmailMessage]:
        self._authenticate()

        params = {
            "$top": min(limit, 999),
            "$select": "id,subject,from,toRecipients,receivedDateTime,"
                       "body,internetMessageHeaders,hasAttachments",
            "$orderby": "receivedDateTime desc",
        }
        if since:
            params["$filter"] = f"receivedDateTime ge {since}T00:00:00Z"

        data = self._graph_get(f"/me/mailFolders/{self.folder}/messages", params)
        messages = data.get("value", [])
        self.logger.info(f"Found {len(messages)} messages in Outlook/{self.folder}")

        emails = []
        for msg in messages:
            try:
                emails.append(self._convert(msg))
            except Exception as e:
                self.logger.warning(f"Failed to convert message {msg.get('id')}: {e}")

        return emails

    def _convert(self, msg: dict) -> EmailMessage:
        body_html = msg.get("body", {}).get("content", "")
        body_type  = msg.get("body", {}).get("contentType", "text")
        body_text  = body_html if body_type == "text" else ""

        urls = extract_urls_from_html(body_html) + extract_urls_from_text(body_text)

        sender_obj = msg.get("from", {}).get("emailAddress", {})
        sender_addr = sender_obj.get("address", "")
        sender_name = sender_obj.get("name", "")

        date = None
        date_str = msg.get("receivedDateTime", "")
        if date_str:
            try:
                date = datetime.fromisoformat(date_str.rstrip("Z"))
            except Exception:
                pass

        headers = {
            h["name"]: h["value"]
            for h in msg.get("internetMessageHeaders", [])
        }

        return EmailMessage(
            message_id=msg.get("id", ""),
            subject=msg.get("subject", "(No Subject)"),
            sender=f'{sender_name} <{sender_addr}>',
            sender_name=sender_name,
            recipients=[r["emailAddress"]["address"] for r in msg.get("toRecipients", [])],
            date=date,
            body_text=body_text,
            body_html=body_html,
            headers=headers,
            attachments=[],         # Fetched separately if needed
            urls=list(set(urls)),
            raw=msg,
            provider="outlook"
        )
