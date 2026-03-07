"""
Report Generator — HTML, JSON, and console output formats.
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List

from email_threat.core import ThreatConfig as Config
from email_threat.threat_models import EmailThreatResult, ThreatSeverity, ThreatType


SEV_COLORS = {
    ThreatSeverity.CRITICAL: "#dc2626",
    ThreatSeverity.HIGH:     "#ea580c",
    ThreatSeverity.MEDIUM:   "#d97706",
    ThreatSeverity.LOW:      "#65a30d",
    ThreatSeverity.NONE:     "#16a34a",
}


class ReportGenerator:
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def generate(self, results: List[EmailThreatResult],
                 output_path: str, fmt: str = "html") -> str:
        path = Path(output_path)
        if fmt == "json":
            path = path.with_suffix(".json")
            self._write_json(results, path)
        elif fmt == "console":
            self._print_console(results)
            return "console"
        else:
            path = path.with_suffix(".html")
            self._write_html(results, path)
        return str(path)

    # ── JSON ──────────────────────────────────────────────────────────────────
    def _write_json(self, results: List[EmailThreatResult], path: Path):
        data = [{
            "message_id": r.email.message_id,
            "subject": r.email.subject,
            "sender": r.email.sender,
            "date": r.email.date.isoformat() if r.email.date else None,
            "overall_score": round(r.overall_score, 4),
            "severity": r.severity.value,
            "primary_threat": r.primary_threat.value,
            "is_threat": r.is_threat,
            "indicators": [{
                "type": i.threat_type.value,
                "score": round(i.score, 4),
                "description": i.description,
                "source": i.source,
            } for i in r.indicators]
        } for r in results]

        path.write_text(json.dumps({
            "generated_at": datetime.utcnow().isoformat(),
            "total": len(results),
            "threats": len([r for r in results if r.is_threat]),
            "results": data
        }, indent=2))
        self.logger.info(f"JSON report: {path}")

    # ── HTML ──────────────────────────────────────────────────────────────────
    def _write_html(self, results: List[EmailThreatResult], path: Path):
        threats = [r for r in results if r.is_threat]
        clean   = [r for r in results if not r.is_threat]
        now     = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        def badge(sev: ThreatSeverity) -> str:
            c = SEV_COLORS.get(sev, "#6b7280")
            return (f'<span style="background:{c};color:white;padding:2px 10px;'
                    f'border-radius:9999px;font-size:.75rem;font-weight:700">'
                    f'{sev.value}</span>')

        def indicator_rows(r: EmailThreatResult) -> str:
            rows = ""
            for ind in sorted(r.indicators, key=lambda x: x.score, reverse=True):
                c = "#dc2626" if ind.score >= .8 else "#d97706" if ind.score >= .5 else "#6b7280"
                rows += (f'<tr style="border-bottom:1px solid #f1f5f9">'
                         f'<td style="padding:6px 12px;color:{c};font-weight:600">{ind.threat_type.value}</td>'
                         f'<td style="padding:6px 12px;color:#6b7280;font-size:.8rem">{ind.source}</td>'
                         f'<td style="padding:6px 12px">{ind.description[:80]}</td>'
                         f'<td style="padding:6px 12px;font-weight:700;color:{c}">{ind.score:.0%}</td></tr>')
            return rows

        def threat_card(r: EmailThreatResult) -> str:
            c     = SEV_COLORS.get(r.severity, "#6b7280")
            subj  = (r.email.subject or "(No Subject)")[:60]
            date  = r.email.date.strftime("%Y-%m-%d %H:%M") if r.email.date else "—"
            uid   = f"d{abs(hash(r.email.message_id)) % 99999}"
            return f"""
<div style="background:white;border:1px solid #e5e7eb;border-left:4px solid {c};
            border-radius:8px;margin-bottom:12px;overflow:hidden">
  <div style="padding:14px 16px;cursor:pointer;display:flex;align-items:center;gap:10px"
       onclick="var d=document.getElementById('{uid}');d.style.display=d.style.display==='none'?'block':'none'">
    <b style="font-size:1.3rem;color:{c}">{r.overall_score:.0%}</b>
    {badge(r.severity)}
    <span style="color:#6b7280;font-size:.85rem">{r.primary_threat.value}</span>
    <div style="margin-left:auto;text-align:right">
      <div style="font-weight:600;font-size:.9rem">{subj}</div>
      <div style="font-size:.75rem;color:#9ca3af">{r.email.sender[:45]} &bull; {date}</div>
    </div>
    <span style="color:#d1d5db">▾</span>
  </div>
  <div id="{uid}" style="display:none;border-top:1px solid #f1f5f9">
    <table style="width:100%;border-collapse:collapse">
      <tr style="background:#f8fafc">
        <th style="padding:7px 12px;text-align:left;font-size:.75rem;color:#6b7280">THREAT TYPE</th>
        <th style="padding:7px 12px;text-align:left;font-size:.75rem;color:#6b7280">SOURCE</th>
        <th style="padding:7px 12px;text-align:left;font-size:.75rem;color:#6b7280">DESCRIPTION</th>
        <th style="padding:7px 12px;text-align:left;font-size:.75rem;color:#6b7280">SCORE</th>
      </tr>
      {indicator_rows(r)}
    </table>
  </div>
</div>"""

        # Type breakdown
        type_counts = {}
        for r in threats:
            for i in r.indicators:
                k = i.threat_type.value
                type_counts[k] = type_counts.get(k, 0) + 1
        type_rows = "".join(
            f'<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f1f5f9;font-size:.875rem">'
            f'<span>{k}</span><b>{v}</b></div>'
            for k, v in sorted(type_counts.items(), key=lambda x: -x[1])
        )

        # Severity breakdown bars
        sev_cnt = {}
        for r in threats:
            sev_cnt[r.severity.value] = sev_cnt.get(r.severity.value, 0) + 1
        sev_bars = "".join(
            f'<div style="display:flex;align-items:center;gap:8px;margin:6px 0">'
            f'<span style="width:75px;font-size:.8rem">{s}</span>'
            f'<div style="background:{SEV_COLORS[ThreatSeverity(s)]};height:18px;'
            f'width:{max(20, int(c/max(1,len(threats))*220))}px;border-radius:4px"></div>'
            f'<span style="font-size:.875rem">{c}</span></div>'
            for s, c in sev_cnt.items()
        )

        threat_rate = f"{len(threats)/max(1,len(results)):.0%}"
        threat_cards_html = "\n".join(threat_card(r) for r in threats) or \
                            '<p style="color:#16a34a">✓ No threats detected above threshold.</p>'

        clean_rows = "".join(
            f'<tr style="border-bottom:1px solid #f1f5f9">'
            f'<td style="padding:5px 8px;font-size:.85rem">{r.email.subject[:55] or "(No Subject)"}</td>'
            f'<td style="padding:5px 8px;color:#6b7280;font-size:.8rem">{r.email.sender[:40]}</td>'
            f'<td style="padding:5px 8px;color:#16a34a;font-size:.8rem">{r.overall_score:.0%}</td>'
            f'</tr>'
            for r in clean[:50]
        ) or '<tr><td colspan="3" style="padding:8px;color:#9ca3af">None</td></tr>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Email Threat Intelligence Report</title>
<style>
  *{{box-sizing:border-box}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#f1f5f9;margin:0;padding:24px;color:#1e293b}}
  .wrap{{max-width:1100px;margin:0 auto}}
  .card{{background:white;border-radius:12px;padding:24px;
         box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px}}
  h2{{margin:0 0 16px;font-size:1.05rem;color:#374151}}
  .grid4{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}}
  .stat{{text-align:center;padding:8px}}
  .num{{font-size:2.2rem;font-weight:800;line-height:1}}
  .lbl{{font-size:.8rem;color:#6b7280;margin-top:4px}}
  @media(max-width:700px){{.grid4{{grid-template-columns:1fr 1fr}};.two{{display:block}}}}
</style>
</head>
<body>
<div class="wrap">

<div class="card" style="background:linear-gradient(135deg,#0f172a,#1e3a5f);color:white;padding:28px">
  <div style="display:flex;align-items:center;gap:12px">
    <span style="font-size:2rem">🛡️</span>
    <div>
      <h1 style="margin:0;font-size:1.4rem">Email Threat Intelligence Report</h1>
      <p style="margin:4px 0 0;color:#94a3b8;font-size:.875rem">Generated: {now}</p>
    </div>
  </div>
</div>

<div class="card">
  <h2>📊 Analysis Summary</h2>
  <div class="grid4">
    <div class="stat"><div class="num" style="color:#3b82f6">{len(results)}</div><div class="lbl">Scanned</div></div>
    <div class="stat"><div class="num" style="color:#dc2626">{len(threats)}</div><div class="lbl">Threats Found</div></div>
    <div class="stat"><div class="num" style="color:#16a34a">{len(clean)}</div><div class="lbl">Clean Emails</div></div>
    <div class="stat"><div class="num" style="color:#d97706">{threat_rate}</div><div class="lbl">Threat Rate</div></div>
  </div>
</div>

<div class="two" style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">
  <div class="card" style="margin:0">
    <h2>⚡ Severity Breakdown</h2>
    {sev_bars or '<p style="color:#6b7280;font-size:.875rem">No threats</p>'}
  </div>
  <div class="card" style="margin:0">
    <h2>🎯 Threat Type Distribution</h2>
    {type_rows or '<p style="color:#6b7280;font-size:.875rem">No threats</p>'}
  </div>
</div>

<div class="card">
  <h2>⚠️ Threat Details — {len(threats)} email(s) flagged
    <span style="font-size:.75rem;font-weight:400;color:#9ca3af">(click to expand indicators)</span>
  </h2>
  {threat_cards_html}
</div>

<div class="card">
  <h2>✅ Clean Emails ({len(clean)})</h2>
  <table style="width:100%;border-collapse:collapse">
    <tr style="background:#f8fafc">
      <th style="padding:6px 8px;text-align:left;font-size:.75rem;color:#6b7280">SUBJECT</th>
      <th style="padding:6px 8px;text-align:left;font-size:.75rem;color:#6b7280">SENDER</th>
      <th style="padding:6px 8px;text-align:left;font-size:.75rem;color:#6b7280">SCORE</th>
    </tr>
    {clean_rows}
  </table>
</div>

<div style="text-align:center;color:#94a3b8;font-size:.75rem;padding:16px">
  Email Threat Intelligence System &bull; Report generated {now}
</div>
</div>
</body>
</html>"""
        path.write_text(html, encoding="utf-8")
        self.logger.info(f"HTML report: {path}")

    # ── Console ───────────────────────────────────────────────────────────────
    def _print_console(self, results: List[EmailThreatResult]):
        threats = [r for r in results if r.is_threat]
        print(f"\n{'═'*72}")
        print(f"  THREAT REPORT — {datetime.utcnow():%Y-%m-%d %H:%M} UTC")
        print(f"  Scanned: {len(results)} | Threats: {len(threats)} | Clean: {len(results)-len(threats)}")
        print(f"{'═'*72}")
        for r in threats:
            print(f"\n  [{r.severity.value}] {r.overall_score:.0%}  {r.email.subject[:55]}")
            print(f"  From: {r.email.sender}")
            for i in r.indicators:
                print(f"    ↳ {i.threat_type.value} ({i.score:.0%}) [{i.source}] {i.description[:60]}")
        print()
