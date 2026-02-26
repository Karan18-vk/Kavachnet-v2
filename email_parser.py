"""
Utility: Email body parsing, URL extraction, and MIME handling.
"""
import re, hashlib, logging
from html.parser import HTMLParser
from typing import Tuple, List
from models import Attachment

logger = logging.getLogger(__name__)
URL_RE = re.compile(r"https?://[^\s\"'<>\)\]\|\\,;]+", re.IGNORECASE)


class _HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text_parts, self.urls, self._in_skip = [], [], 0
        self._skip_tags = {"script","style","head"}

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self._skip_tags: self._in_skip += 1
        if tag.lower() == "a":
            href = dict(attrs).get("href","")
            if href.startswith("http"): self.urls.append(href)

    def handle_endtag(self, tag):
        if tag.lower() in self._skip_tags and self._in_skip: self._in_skip -= 1

    def handle_data(self, data):
        if not self._in_skip: self.text_parts.append(data)

    @property
    def text(self): return " ".join(self.text_parts)


def parse_email_body(msg) -> Tuple[str, str, List[Attachment]]:
    """Walk MIME message → plaintext, HTML, attachments."""
    body_text = body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = str(part.get("Content-Disposition",""))
            if "attachment" in disposition or (part.get_filename() and ctype not in ("text/plain","text/html")):
                filename = part.get_filename() or "unnamed"
                try:
                    data = part.get_payload(decode=True) or b""
                    attachments.append(Attachment(
                        filename=filename, content_type=ctype, size_bytes=len(data),
                        data=data, sha256=hashlib.sha256(data).hexdigest(),
                        md5=hashlib.md5(data).hexdigest()
                    ))
                except Exception as e:
                    logger.debug(f"Attachment read error {filename}: {e}")
            elif ctype == "text/plain" and not body_text:
                p = part.get_payload(decode=True)
                if p: body_text = p.decode(part.get_content_charset() or "utf-8", errors="replace")
            elif ctype == "text/html" and not body_html:
                p = part.get_payload(decode=True)
                if p: body_html = p.decode(part.get_content_charset() or "utf-8", errors="replace")
    else:
        ctype = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
            if ctype == "text/html": body_html = text
            else: body_text = text

    if body_html and not body_text:
        try:
            ex = _HTMLTextExtractor(); ex.feed(body_html); body_text = ex.text
        except Exception: pass

    return body_text, body_html, attachments


def extract_urls_from_html(html: str) -> List[str]:
    if not html: return []
    try:
        ex = _HTMLTextExtractor(); ex.feed(html)
        return list(set(ex.urls + URL_RE.findall(html)))
    except Exception:
        return URL_RE.findall(html)


def extract_urls_from_text(text: str) -> List[str]:
    return URL_RE.findall(text or "")
