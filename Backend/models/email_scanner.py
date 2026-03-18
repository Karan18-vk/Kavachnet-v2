import re
from dataclasses import dataclass, field
from typing import List
from models.phishing_detector import analyze_url

URL_REGEX = re.compile(r"https?://[^\s<>"')+\]]+", re.IGNORECASE)
SUSPICIOUS_SUBJECTS = ["urgent","action required","verify your","confirm your","suspended",
    "locked","unusual activity","immediate","final notice","winner","congratulations",
    "limited time","claim your","free gift","click below","reset your password"]
DANGEROUS_EXTENSIONS = [".exe",".bat",".cmd",".scr",".vbs",".js",".wsf",".hta",".pif",".ps1"]

@dataclass
class EmailScanResult:
    verdict: str
    confidence: float
    risk_score: int
    flags: List[str] = field(default_factory=list)
    extracted_urls: List[dict] = field(default_factory=list)
    summary: str = ""
    def to_dict(self):
        return {"verdict": self.verdict, "confidence": round(self.confidence*100,1),
                "risk_score": self.risk_score, "flags": self.flags,
                "extracted_urls": self.extracted_urls, "summary": self.summary}

def scan_email(subject="", sender="", body="", headers="", attachments=None):
    attachments = attachments or []
    flags, score, urls = [], 0, []
    subject_l, sender_l, body_l = subject.lower(), sender.lower(), body.lower()
    triggered = [kw for kw in SUSPICIOUS_SUBJECTS if kw in subject_l]
    if triggered:
        score += min(len(triggered)*10, 30)
        flags.append(f"Suspicious subject: {', '.join(triggered[:3])}")
    spoofed = [b for b in ["paypal","amazon","apple","google","microsoft","netflix"]
               if b in subject_l or b in body_l]
    if spoofed and not any(b in sender_l for b in spoofed):
        score += 35; flags.append(f"Possible brand spoofing: {spoofed[0]}")
    raw_urls = URL_REGEX.findall(body)
    for raw_url in set(raw_urls):
        r = analyze_url(raw_url); urls.append(r.to_dict())
        if r.verdict == "malicious":   score += 30; flags.append(f"Malicious URL: {raw_url[:60]}")
        elif r.verdict == "suspicious": score += 10; flags.append(f"Suspicious URL: {raw_url[:60]}")
    for att in attachments:
        for ext in DANGEROUS_EXTENSIONS:
            if isinstance(att,str) and att.lower().endswith(ext):
                score += 40; flags.append(f"Dangerous attachment: {att}")
    if re.search(r"<form[^>]*action", body, re.IGNORECASE):
        score += 20; flags.append("HTML form in email — possible credential harvesting")
    urgency = sum(1 for kw in ["24 hours","immediately","now","expire","suspended"] if kw in body_l)
    if urgency >= 2: score += 15; flags.append("High urgency language detected")
    score = min(score, 100)
    if score >= 55:
        verdict, confidence = "malicious", 0.60+(score-55)/300
        summary = "Strong phishing/malware indicators. Do not click links or open attachments."
    elif score >= 25:
        verdict, confidence = "suspicious", 0.40+score/200
        summary = "Suspicious characteristics. Verify sender before acting."
    else:
        verdict, confidence = "safe", 1.0-score/120
        summary = "No significant threats detected."
    if not flags: flags.append("No significant threat indicators found")
    return EmailScanResult(verdict, round(min(confidence,0.99),3), score, flags, urls, summary)
