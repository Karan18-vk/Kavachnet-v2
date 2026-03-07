"""
=============================================================
  EMAIL THREAT DETECTION SYSTEM — main.py
  Entry point: CLI interface + report generation
=============================================================

Usage:
    python main.py --source imap
    python main.py --source gmail
    python main.py --source outlook
    python main.py --source pop3
    python main.py --source imap --limit 100 --output json
    python main.py --source imap --output html
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List

from email_threat.threat_config import IMAP_CFG, THREAT_CFG
from email_threat.gmail_connector import GmailConnector
from email_threat.imap_connector import IMAPConnector
from email_threat.outlook_connector import OutlookConnector
from email_threat.pop3_connector import POP3Connector
from email_threat.threat_models import EmailMessage, EmailThreatResult
from email_threat.orchestrator import ThreatOrchestrator

# ── Logging setup ────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("email_threat_scan.log"),
    ],
)
logger = logging.getLogger("main")

# ANSI colors for terminal
_COLORS = {
    "CRITICAL": "\033[1;31m",  # Bold red
    "HIGH":     "\033[31m",    # Red
    "MEDIUM":   "\033[33m",    # Yellow
    "LOW":      "\033[32m",    # Green
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "CYAN":     "\033[36m",
    "WHITE":    "\033[97m",
}


# ─────────────────────────────────────────────────────────────
#  Console Report Printer
# ─────────────────────────────────────────────────────────────

def _color(text: str, color: str) -> str:
    return f"{_COLORS.get(color, '')}{text}{_COLORS['RESET']}"


def print_banner():
    banner = r"""
  ███████╗███╗   ███╗ █████╗ ██╗██╗  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
  ██╔════╝████╗ ████║██╔══██╗██║██║  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
  █████╗  ██╔████╔██║███████║██║██║     ██║   ███████║██████╔╝█████╗  ███████║   ██║
  ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
  ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝
           Email Cybersecurity Threat Detection System v1.0
    """
    print(_color(banner, "CYAN"))


def print_report(report: EmailThreatResult, verbose: bool = False) -> None:
    risk = report.severity.value
    color = risk if risk in _COLORS else "WHITE"

    sep = "─" * 72
    print(f"\n{sep}")
    print(_color(f"  [{risk}] UID: {report.email_uid}", color))
    print(f"  Subject : {report.subject[:80]}")
    print(f"  From    : {report.sender[:60]}")
    print(f"  Source  : {report.source.upper()}")
    print()

    # Threat flags
    flags = {
        "Phishing":              report.is_phishing,
        "Malware Links":         report.has_malware,
        "Malicious Attachments": report.has_malicious_attachments,
        "Spoofed Sender":        report.is_spoofed,
        "Spam":                  report.is_spam,
        "Social Engineering":    report.is_social_engineering,
    }
    for label, active in flags.items():
        icon = "⚠ " if active else "✓ "
        c = "HIGH" if active else "LOW"
        print(_color(f"  {icon} {label}", c))

    # Scores
    print(f"\n  NLP Scores:")
    print(f"    Phishing          : {report.phishing_score:.2%}")
    print(f"    Spam              : {report.spam_score:.2%}")
    print(f"    Social Eng.       : {report.social_engineering_score:.2%}")

    # Summary
    print(f"\n  Findings:")
    for s in report.summary:
        print(f"    • {s}")

    # Verbose: URL / attachment details
    if verbose:
        if report.url_threats:
            print(f"\n  URL Analysis ({len(report.url_threats)} URLs scanned):")
            for ut in report.url_threats:
                flags_str = ", ".join(
                    f for f, v in [
                        ("Phishing", ut.is_phishing),
                        ("Malware", ut.is_malware),
                        ("SuspTLD", ut.suspicious_tld),
                        ("AbuseIP", ut.ip_abusive),
                        ("PhishTank", ut.phishtank_flagged),
                    ] if v
                ) or "CLEAN"
                vt = ut.virustotal_positives
                print(f"    [{flags_str}] VT:{vt:>3}  {ut.url[:70]}")

        if report.attachment_threats:
            print(f"\n  Attachment Analysis ({len(report.attachment_threats)} files):")
            for at in report.attachment_threats:
                print(f"    {at.filename}")
                print(f"      SHA256  : {at.sha256}")
                print(f"      MIME    : {at.mime_type}")
                print(f"      ClamAV  : {at.clamav_verdict}")
                print(f"      VT hits : {at.virustotal_positives}")
                if at.dangerous_extension:
                    print(f"      ⚠ DANGEROUS EXTENSION")

        if report.sender_threat:
            st = report.sender_threat
            print(f"\n  Sender Authentication:")
            print(f"    SPF   : {'✓ PASS' if st.spf_pass else '✗ FAIL'}")
            print(f"    DKIM  : {'✓ PRESENT' if st.dkim_present else '✗ MISSING'}")
            print(f"    DMARC : {'✓ PASS' if st.dmarc_pass else '✗ FAIL'}")
            if st.domain_age_days is not None:
                print(f"    Domain age: {st.domain_age_days} days")
            if st.display_name_mismatch:
                print(f"    ⚠ DISPLAY NAME MISMATCH detected")

    print(sep)


# ─────────────────────────────────────────────────────────────
#  JSON / HTML report export
# ─────────────────────────────────────────────────────────────

def reports_to_json(reports: List[EmailThreatResult], path: str) -> None:
    def _serialize(r: EmailThreatResult) -> dict:
        return {
            "uid": r.email_uid,
            "subject": r.subject,
            "sender": r.sender,
            "source": r.source,
            "risk": r.overall_risk(),
            "flags": {
                "phishing": r.is_phishing,
                "malware": r.has_malware,
                "malicious_attachments": r.has_malicious_attachments,
                "spoofed": r.is_spoofed,
                "spam": r.is_spam,
                "social_engineering": r.is_social_engineering,
            },
            "scores": {
                "phishing": round(r.phishing_score, 4),
                "spam": round(r.spam_score, 4),
                "social_engineering": round(r.social_engineering_score, 4),
            },
            "url_threats": [
                {
                    "url": u.url,
                    "is_phishing": u.is_phishing,
                    "is_malware": u.is_malware,
                    "virustotal_positives": u.virustotal_positives,
                    "phishtank": u.phishtank_flagged,
                    "suspicious_tld": u.suspicious_tld,
                    "ip_abusive": u.ip_abusive,
                }
                for u in r.url_threats
            ],
            "attachment_threats": [
                {
                    "filename": a.filename,
                    "sha256": a.sha256,
                    "mime_type": a.mime_type,
                    "clamav": a.clamav_verdict,
                    "vt_positives": a.virustotal_positives,
                    "dangerous_ext": a.dangerous_extension,
                }
                for a in r.attachment_threats
            ],
            "sender_threat": {
                "spf": r.sender_threat.spf_pass if r.sender_threat else None,
                "dkim": r.sender_threat.dkim_present if r.sender_threat else None,
                "dmarc": r.sender_threat.dmarc_pass if r.sender_threat else None,
                "display_name_mismatch": r.sender_threat.display_name_mismatch if r.sender_threat else None,
                "domain_age_days": r.sender_threat.domain_age_days if r.sender_threat else None,
                "details": r.sender_threat.details if r.sender_threat else "",
            },
            "summary": r.summary,
        }

    with open(path, "w") as f:
        json.dump([_serialize(r) for r in reports], f, indent=2)
    logger.info("JSON report saved to %s", path)


def reports_to_html(reports: List[EmailThreatResult], path: str) -> None:
    RISK_COLOR = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#2ecc71"}
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = []
    for r in reports:
        risk = r.overall_risk()
        color = RISK_COLOR.get(risk, "#95a5a6")
        flags = []
        if r.is_phishing:            flags.append("Phishing")
        if r.has_malware:            flags.append("Malware")
        if r.has_malicious_attachments: flags.append("Bad Attachment")
        if r.is_spoofed:             flags.append("Spoofed")
        if r.is_spam:                flags.append("Spam")
        if r.is_social_engineering:  flags.append("Social Eng.")
        flags_html = " ".join(
            f'<span class="badge">{f}</span>' for f in flags
        ) or '<span class="badge safe">Clean</span>'

        rows.append(f"""
        <tr>
          <td><code style="font-size:0.8em">{r.email_uid[:16]}…</code></td>
          <td>{r.subject[:60]}</td>
          <td>{r.sender[:40]}</td>
          <td style="color:{color};font-weight:bold">{risk}</td>
          <td>{flags_html}</td>
          <td>{r.phishing_score:.0%} / {r.spam_score:.0%}</td>
          <td>{len(r.url_threats)} / {len(r.attachment_threats)}</td>
        </tr>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Email Threat Scan Report</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
    h1   {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
    p.meta {{ color: #8b949e; font-size: 0.9em; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th    {{ background: #161b22; color: #58a6ff; padding: 10px 14px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; }}
    td    {{ padding: 10px 14px; border-bottom: 1px solid #21262d; font-size: 0.9em; }}
    tr:hover td {{ background: #161b22; }}
    .badge {{ display: inline-block; background: #e74c3c; color: #fff; border-radius: 4px;
              padding: 2px 8px; font-size: 0.75em; margin: 2px; }}
    .badge.safe {{ background: #2ecc71; }}
    .summary {{ background: #161b22; border-radius: 8px; padding: 16px; margin-top: 30px; }}
    .summary h2 {{ color: #58a6ff; margin-top: 0; }}
    .stat {{ display: inline-block; margin: 8px 16px 8px 0; }}
    .stat span {{ font-size: 1.8em; font-weight: bold; }}
    .crit {{ color: #e74c3c; }} .high {{ color: #e67e22; }}
    .med  {{ color: #f1c40f; }} .low  {{ color: #2ecc71; }}
  </style>
</head>
<body>
  <h1>🔒 Email Threat Detection Report</h1>
  <p class="meta">Generated: {ts} &nbsp;|&nbsp; Emails analysed: {len(reports)}</p>

  <div class="summary">
    <h2>Scan Summary</h2>
    {''.join(f'<div class="stat"><span class="crit">{sum(1 for r in reports if r.is_phishing)}</span><br>Phishing</div>')}
    {''.join(f'<div class="stat"><span class="high">{sum(1 for r in reports if r.has_malware)}</span><br>Malware Links</div>')}
    {''.join(f'<div class="stat"><span class="high">{sum(1 for r in reports if r.has_malicious_attachments)}</span><br>Bad Attachments</div>')}
    {''.join(f'<div class="stat"><span class="med">{sum(1 for r in reports if r.is_spoofed)}</span><br>Spoofed</div>')}
    {''.join(f'<div class="stat"><span class="med">{sum(1 for r in reports if r.is_spam)}</span><br>Spam</div>')}
    {''.join(f'<div class="stat"><span class="low">{sum(1 for r in reports if r.overall_risk()=="LOW")}</span><br>Clean</div>')}
  </div>

  <table>
    <thead>
      <tr>
        <th>UID</th><th>Subject</th><th>From</th>
        <th>Risk</th><th>Threats</th><th>Ph/Spam %</th><th>URLs/Att.</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    logger.info("HTML report saved to %s", path)


# ─────────────────────────────────────────────────────────────
#  Email source factory
# ─────────────────────────────────────────────────────────────

def get_emails(source: str, limit: int) -> List[EmailMessage]:
    if source == "imap":
        connector = IMAPConnector(THREAT_CFG, host=THREAT_CFG.imap_host, port=THREAT_CFG.imap_port, user="user", password="pass")
        return connector.fetch(limit=limit)
    elif source == "pop3":
        connector = POP3Connector(THREAT_CFG, host=THREAT_CFG.pop3_host, port=THREAT_CFG.pop3_port, user="user", password="pass")
        return connector.fetch(limit=limit)
    elif source == "gmail":
        connector = GmailConnector(THREAT_CFG)
        return connector.fetch(limit=limit)
    elif source == "outlook":
        connector = OutlookConnector(THREAT_CFG)
        return connector.fetch(limit=limit)
    else:
        raise ValueError(f"Unknown source: {source}")


# ─────────────────────────────────────────────────────────────
#  CLI entry point
# ─────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Email Cybersecurity Threat Detection System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--source",
        choices=["imap", "pop3", "gmail", "outlook"],
        default="imap",
        help="Email source protocol / API",
    )
    p.add_argument("--limit", type=int, default=50, help="Max emails to scan")
    p.add_argument(
        "--output",
        choices=["console", "json", "html", "all"],
        default="console",
        help="Report output format",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Show per-URL/attachment details")
    p.add_argument("--outdir", default=".", help="Directory for output files")
    return p.parse_args()


def main():
    args = parse_args()
    print_banner()

    # ── Fetch emails ─────────────────────────────────────────
    logger.info("Fetching emails from: %s (limit=%d)", args.source, args.limit)
    emails = get_emails(args.source, args.limit)
    logger.info("Fetched %d emails. Starting threat analysis…", len(emails))

    # ── Analyse ──────────────────────────────────────────────
    import asyncio
    from email_threat.core import THREAT_CFG
    detector = ThreatOrchestrator(THREAT_CFG, logger)
    reports: List[EmailThreatResult] = []

    for i, em in enumerate(emails, 1):
        logger.info("[%d/%d] Analysing: %s", i, len(emails), em.subject[:60])
        try:
            report = detector.analyze(em)
            reports.append(report)
            if args.output in ("console", "all"):
                print_report(report, verbose=args.verbose)
        except Exception as exc:
            logger.error("Analysis failed for uid %s: %s", em.uid, exc)

    # ── Generate summary stats ───────────────────────────────
    critical = sum(1 for r in reports if r.overall_risk() == "CRITICAL")
    high = sum(1 for r in reports if r.overall_risk() == "HIGH")
    medium = sum(1 for r in reports if r.overall_risk() == "MEDIUM")
    low = sum(1 for r in reports if r.overall_risk() == "LOW")

    print(f"\n{'═'*72}")
    print(f"  SCAN COMPLETE — {len(reports)} emails analysed")
    print(f"  CRITICAL: {critical}  |  HIGH: {high}  |  MEDIUM: {medium}  |  LOW (CLEAN): {low}")
    print(f"{'═'*72}\n")

    # ── Save reports ─────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)

    if args.output in ("json", "all"):
        reports_to_json(reports, str(out / f"threat_report_{ts}.json"))

    if args.output in ("html", "all"):
        reports_to_html(reports, str(out / f"threat_report_{ts}.html"))

    return 0 if critical == 0 and high == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
