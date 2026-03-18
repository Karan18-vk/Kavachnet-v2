import os

os.makedirs('models', exist_ok=True)
os.makedirs('utils', exist_ok=True)
os.makedirs('routes', exist_ok=True)

files = {}

# ── database.py ──────────────────────────────────────────────────────────────
files['database.py'] = '''from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
'''

# ── models/__init__.py ────────────────────────────────────────────────────────
files['models/__init__.py'] = ''

# ── utils/__init__.py ─────────────────────────────────────────────────────────
files['utils/__init__.py'] = ''

# ── routes/__init__.py ────────────────────────────────────────────────────────
files['routes/__init__.py'] = ''

# ── models/user.py ────────────────────────────────────────────────────────────
files['models/user.py'] = '''from database import db
from datetime import datetime

class Institution(db.Model):
    __tablename__ = "institutions"
    id             = db.Column(db.Integer, primary_key=True)
    name           = db.Column(db.String(200), nullable=False)
    code           = db.Column(db.String(20),  unique=True, nullable=False)
    contact_person = db.Column(db.String(100))
    email          = db.Column(db.String(150), nullable=False)
    phone          = db.Column(db.String(20))
    status         = db.Column(db.String(20), default="pending")
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    users = db.relationship("User", backref="institution", lazy=True)
    def to_dict(self):
        return {"id": self.id, "name": self.name, "code": self.code,
                "contact_person": self.contact_person, "email": self.email,
                "status": self.status, "created_at": self.created_at.isoformat()}

class User(db.Model):
    __tablename__ = "users"
    id             = db.Column(db.Integer, primary_key=True)
    first_name     = db.Column(db.String(80),  nullable=False)
    last_name      = db.Column(db.String(80),  nullable=False)
    email          = db.Column(db.String(150), unique=True, nullable=False)
    staff_id       = db.Column(db.String(50),  unique=True, nullable=True)
    password_hash  = db.Column(db.String(256), nullable=False)
    role           = db.Column(db.String(20),  default="staff")
    department     = db.Column(db.String(100), default="SOC")
    institution_id = db.Column(db.Integer, db.ForeignKey("institutions.id"), nullable=False)
    status         = db.Column(db.String(20),  default="pending")
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    def to_dict(self):
        return {"id": self.id, "first_name": self.first_name, "last_name": self.last_name,
                "email": self.email, "staff_id": self.staff_id, "role": self.role,
                "department": self.department,
                "institution": self.institution.name if self.institution else None,
                "status": self.status, "created_at": self.created_at.isoformat()}

class OTPRecord(db.Model):
    __tablename__ = "otp_records"
    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(150), nullable=False)
    otp_code   = db.Column(db.String(6),   nullable=False)
    expires_at = db.Column(db.DateTime,    nullable=False)
    used       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id             = db.Column(db.Integer, primary_key=True)
    user_id        = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    institution_id = db.Column(db.Integer, nullable=True)
    action         = db.Column(db.String(100), nullable=False)
    resource       = db.Column(db.String(200))
    detail         = db.Column(db.Text)
    ip_address     = db.Column(db.String(50))
    severity       = db.Column(db.String(20), default="info")
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow)
    def to_dict(self):
        return {"id": self.id, "user_id": self.user_id, "action": self.action,
                "resource": self.resource, "detail": self.detail,
                "ip_address": self.ip_address, "severity": self.severity,
                "timestamp": self.timestamp.isoformat()}

class Incident(db.Model):
    __tablename__ = "incidents"
    id             = db.Column(db.Integer, primary_key=True)
    institution_id = db.Column(db.Integer, db.ForeignKey("institutions.id"), nullable=True)
    title          = db.Column(db.String(200), nullable=False)
    description    = db.Column(db.Text)
    threat_type    = db.Column(db.String(50))
    severity       = db.Column(db.String(20), default="medium")
    status         = db.Column(db.String(20), default="open")
    source_ip      = db.Column(db.String(50))
    target         = db.Column(db.String(200))
    confidence     = db.Column(db.Float, default=0.0)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at    = db.Column(db.DateTime, nullable=True)
    def to_dict(self):
        return {"id": self.id, "title": self.title, "description": self.description,
                "threat_type": self.threat_type, "severity": self.severity,
                "status": self.status, "source_ip": self.source_ip, "target": self.target,
                "confidence": round(self.confidence * 100, 1),
                "created_at": self.created_at.isoformat(),
                "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None}

class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"
    id             = db.Column(db.Integer, primary_key=True)
    ip_address     = db.Column(db.String(50),  nullable=False)
    reason         = db.Column(db.String(200))
    blocked_by     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    institution_id = db.Column(db.Integer, nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at     = db.Column(db.DateTime, nullable=True)
    is_active      = db.Column(db.Boolean, default=True)
    def to_dict(self):
        return {"id": self.id, "ip_address": self.ip_address, "reason": self.reason,
                "created_at": self.created_at.isoformat(),
                "expires_at": self.expires_at.isoformat() if self.expires_at else None,
                "is_active": self.is_active}

class ScanResult(db.Model):
    __tablename__ = "scan_results"
    id             = db.Column(db.Integer, primary_key=True)
    scan_type      = db.Column(db.String(30))
    input_data     = db.Column(db.Text)
    verdict        = db.Column(db.String(20))
    confidence     = db.Column(db.Float)
    details        = db.Column(db.Text)
    scanned_by     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    institution_id = db.Column(db.Integer, nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    def to_dict(self):
        import json
        return {"id": self.id, "scan_type": self.scan_type, "input_data": self.input_data,
                "verdict": self.verdict, "confidence": round(self.confidence * 100, 1),
                "details": json.loads(self.details) if self.details else {},
                "created_at": self.created_at.isoformat()}
'''

# ── models/phishing_detector.py ───────────────────────────────────────────────
files['models/phishing_detector.py'] = '''import re, math, urllib.parse
from dataclasses import dataclass, field
from typing import List

PHISHING_KEYWORDS = ["login","signin","verify","account","update","secure","banking",
    "paypal","apple","amazon","microsoft","google","netflix","confirm","suspended",
    "unusual","activity","password","credential","wallet","crypto","urgent","alert",
    "click","limited","free","prize","winner"]
SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club",".online",
    ".site",".live",".click",".download",".loan",".stream",".work",".trade",".win"]
TRUSTED_DOMAINS = ["google.com","github.com","microsoft.com","apple.com","amazon.com",
    "paypal.com","wikipedia.org","youtube.com","facebook.com","linkedin.com","twitter.com","x.com"]
IP_PATTERN  = re.compile(r"https?://(\\d{1,3}\\.){3}\\d{1,3}")
URL_SHORTEN = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly","short.io","rebrand.ly"]

@dataclass
class PhishingResult:
    url: str
    verdict: str
    confidence: float
    risk_score: int
    flags: List[str] = field(default_factory=list)
    indicators: dict = field(default_factory=dict)
    def to_dict(self):
        return {"url": self.url, "verdict": self.verdict,
                "confidence": round(self.confidence * 100, 1),
                "risk_score": self.risk_score, "flags": self.flags,
                "indicators": self.indicators}

def _entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())

def analyze_url(raw_url):
    url = raw_url.strip()
    if not url.startswith(("http://","https://")): url = "http://" + url
    flags, score, details = [], 0, {}
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.","")
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        full   = (domain + path + query).lower()
    except:
        return PhishingResult(raw_url, "suspicious", 0.6, 55, ["URL could not be parsed"], {})
    for td in TRUSTED_DOMAINS:
        if domain == td or domain.endswith("." + td):
            return PhishingResult(raw_url, "safe", 0.95, 5, ["Trusted domain"], {"domain": domain})
    if IP_PATTERN.match(url):
        flags.append("IP address used as hostname"); score += 40; details["ip_host"] = True
    for s in URL_SHORTEN:
        if domain == s:
            flags.append(f"URL shortener: {s}"); score += 20; details["shortened"] = True; break
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"High-risk TLD: {tld}"); score += 25; details["suspicious_tld"] = tld; break
    found_kw = [kw for kw in PHISHING_KEYWORDS if kw in full]
    if found_kw:
        score += min(len(found_kw)*8, 30)
        flags.append(f"Phishing keywords: {', '.join(found_kw[:5])}"); details["keywords"] = found_kw
    sub_count = len(domain.split(".")) - 2
    if sub_count > 2: score += 15; flags.append(f"Excessive subdomains ({sub_count})")
    if len(domain) > 40: score += 15; flags.append("Very long domain name")
    ent = _entropy(domain.split(".")[0]); details["domain_entropy"] = round(ent, 2)
    if ent > 3.8: score += 20; flags.append(f"High domain entropy ({ent:.2f})")
    if domain.count("-") >= 3: score += 10; flags.append("Many hyphens in domain")
    if parsed.scheme == "http": score += 10; flags.append("No HTTPS")
    if "@" in url: score += 30; flags.append("@ symbol in URL")
    score = min(score, 100)
    if score >= 60:   verdict, confidence = "malicious",  0.60 + (score-60)/250
    elif score >= 30: verdict, confidence = "suspicious", 0.40 + score/200
    else:             verdict, confidence = "safe",       1.0 - score/100
    confidence = round(min(confidence, 0.99), 3)
    if not flags: flags.append("No significant phishing indicators detected")
    return PhishingResult(raw_url, verdict, confidence, score, flags, details)
'''

# ── models/email_scanner.py ───────────────────────────────────────────────────
files['models/email_scanner.py'] = '''import re
from dataclasses import dataclass, field
from typing import List
from models.phishing_detector import analyze_url

URL_REGEX = re.compile(r"https?://[^\\s<>\"\')+\\]]+", re.IGNORECASE)
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
'''

# ── models/threat_analyzer.py ─────────────────────────────────────────────────
files['models/threat_analyzer.py'] = '''import random, datetime
from dataclasses import dataclass, field
from typing import List, Dict

KNOWN_MALICIOUS = ["45.95.","185.220.","194.165.","91.108.","23.129.","104.244."]
PRIVATE_RANGES  = ["10.","192.168.","172.16.","127.","::1"]

@dataclass
class ThreatResult:
    ip_address: str
    threat_type: str
    severity: str
    confidence: float
    risk_score: int
    flags: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    def to_dict(self):
        return {"ip_address": self.ip_address, "threat_type": self.threat_type,
                "severity": self.severity, "confidence": round(self.confidence*100,1),
                "risk_score": self.risk_score, "flags": self.flags,
                "recommendations": self.recommendations}

def analyze_ip(ip):
    for priv in PRIVATE_RANGES:
        if ip.startswith(priv):
            return ThreatResult(ip,"clean","low",0.98,2,["Private IP"],["No action required"])
    score, flags = 0, []
    for bad in KNOWN_MALICIOUS:
        if ip.startswith(bad):
            flags.append(f"Known malicious range ({bad}*)"); score += 60; break
    score = min(score + random.randint(0,15), 100)
    if score >= 60:
        threat, sev, conf = "c2", "critical", 0.80
        flags.append("Potential C2 traffic source")
        recs = ["Block IP immediately","Investigate all connections","Check lateral movement"]
    elif score >= 40:
        threat, sev, conf = "suspicious", "high", 0.65
        recs = ["Rate-limit this IP","Monitor closely","Consider temporary block"]
    elif score >= 20:
        threat, sev, conf = "suspicious", "medium", 0.50
        recs = ["Monitor this IP","Log all requests"]
    else:
        threat, sev, conf = "clean", "low", 0.90
        recs = ["No immediate action required"]
    return ThreatResult(ip, threat, sev, conf, score, flags, recs)

def analyze_log_events(events):
    results = {"total_events": len(events), "threats_detected": [], "summary": {}, "risk_level": "low"}
    if not events: return results
    ip_events = {}
    for ev in events:
        ip = ev.get("ip","unknown"); ip_events.setdefault(ip,[]).append(ev)
    threats = []
    for ip, evs in ip_events.items():
        failed = sum(1 for e in evs if "fail" in str(e.get("action","")).lower())
        ports  = set(e.get("port") for e in evs if e.get("port"))
        if failed >= 5:
            threats.append({"type":"brute_force","ip":ip,
                "severity":"high" if failed>=10 else "medium",
                "detail":f"{failed} failed logins from {ip}",
                "recommendation":f"Block {ip} and reset affected accounts"})
        if len(ports) >= 8:
            threats.append({"type":"port_scan","ip":ip,"severity":"high",
                "detail":f"Port scan from {ip} — {len(ports)} ports probed",
                "recommendation":f"Block {ip} at firewall immediately"})
    results["threats_detected"] = threats
    results["summary"] = {"unique_ips":len(ip_events),
        "brute_force_count": sum(1 for t in threats if t["type"]=="brute_force"),
        "port_scan_count":   sum(1 for t in threats if t["type"]=="port_scan")}
    results["risk_level"] = ("critical" if any(t["severity"]=="critical" for t in threats)
        else "high" if any(t["severity"]=="high" for t in threats)
        else "medium" if threats else "low")
    return results

def generate_threat_feed(institution_id=None):
    types = [
        ("Phishing Campaign","phishing","high","Mass phishing campaign targeting institutions."),
        ("Brute Force SSH","brute_force","medium","Automated SSH brute-force from botnet range."),
        ("Ransomware IOC","malware","critical","Ransomware C2 beacon in DNS traffic."),
        ("Port Scan","port_scan","medium","Systematic port reconnaissance from external host."),
        ("Zero-Day Probe","zero_day","critical","Exploit attempt matching new CVE signature."),
        ("Credential Stuffing","brute_force","high","Large-scale credential stuffing detected."),
        ("Data Exfiltration","anomaly","critical","Unusual outbound data to unknown host."),
    ]
    now  = datetime.datetime.utcnow()
    feed = []
    for i in range(10):
        tt = random.choice(types)
        feed.append({"id":1000+i,"title":tt[0],"threat_type":tt[1],"severity":tt[2],
            "description":tt[3],
            "source_ip":f"{random.randint(45,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "confidence":round(random.uniform(0.65,0.99)*100,1),
            "timestamp":(now-datetime.timedelta(minutes=random.randint(1,480))).isoformat()})
    return sorted(feed, key=lambda x: x["timestamp"], reverse=True)
'''

# ── utils/jwt_helper.py ───────────────────────────────────────────────────────
files['utils/jwt_helper.py'] = '''import jwt, hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from models.user import User

def create_token(user_id, role, institution_id):
    expiry = datetime.utcnow() + timedelta(hours=current_app.config["JWT_EXPIRY_HOURS"])
    return jwt.encode({"user_id":user_id,"role":role,"institution_id":institution_id,"exp":expiry},
                      current_app.config["SECRET_KEY"], algorithm="HS256")

def decode_token(token):
    return jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization","")
        if not auth.startswith("Bearer "):
            return jsonify({"error":"Authorization token missing"}), 401
        try:
            payload = decode_token(auth.split(" ")[1])
        except jwt.ExpiredSignatureError:
            return jsonify({"error":"Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error":"Invalid token"}), 401
        user = User.query.get(payload["user_id"])
        if not user or user.status != "active":
            return jsonify({"error":"User not found or inactive"}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if request.current_user.role != "admin":
            return jsonify({"error":"Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated
'''

# ── utils/email_service.py ────────────────────────────────────────────────────
files['utils/email_service.py'] = '''import smtplib, random, string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from flask import current_app

def generate_otp(length=6):
    return "".join(random.choices(string.digits, k=length))

def send_otp_email(to_email, otp_code, user_name=""):
    username = current_app.config.get("MAIL_USERNAME","")
    password = current_app.config.get("MAIL_PASSWORD","")
    if not username or not password:
        print(f"\\n[DEV MODE] OTP for {to_email}: {otp_code}\\n")
        return True
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "KavachNet — Your Login OTP"
    msg["From"]    = current_app.config.get("MAIL_FROM", username)
    msg["To"]      = to_email
    body = f"""<html><body style="font-family:sans-serif;background:#0a0f1e;color:#e2e8f0;padding:40px;">
    <div style="max-width:480px;margin:auto;background:#0d1628;border:1px solid #1e3a5f;border-radius:12px;padding:32px;">
    <h2 style="color:#38bdf8;">KavachNet Security</h2>
    <p>Hello {user_name}, your OTP:</p>
    <div style="background:#1e293b;border:2px solid #3b82f6;border-radius:8px;text-align:center;
                padding:20px;letter-spacing:12px;font-size:32px;font-weight:bold;color:#38bdf8;margin:24px 0;">
    {otp_code}</div>
    <p style="color:#64748b;font-size:13px;">Expires in {current_app.config.get("OTP_EXPIRY_MINUTES",10)} minutes.</p>
    </div></body></html>"""
    msg.attach(MIMEText(body,"html"))
    try:
        with smtplib.SMTP(current_app.config["MAIL_SERVER"], current_app.config["MAIL_PORT"]) as s:
            s.ehlo(); s.starttls(); s.login(username, password)
            s.sendmail(username, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[Email Error] {e}"); return False

def store_otp(email, otp):
    from database import db
    from models.user import OTPRecord
    OTPRecord.query.filter_by(email=email, used=False).delete()
    expiry = datetime.utcnow() + timedelta(minutes=current_app.config.get("OTP_EXPIRY_MINUTES",10))
    db.session.add(OTPRecord(email=email, otp_code=otp, expires_at=expiry))
    db.session.commit()

def verify_otp(email, otp):
    from database import db
    from models.user import OTPRecord
    record = OTPRecord.query.filter_by(email=email, otp_code=otp, used=False)\
                            .order_by(OTPRecord.created_at.desc()).first()
    if not record or datetime.utcnow() > record.expires_at: return False
    record.used = True; db.session.commit(); return True
'''

# ── routes/auth.py ────────────────────────────────────────────────────────────
files['routes/auth.py'] = '''from flask import Blueprint, request, jsonify
from models.user import User, AuditLog
from utils.jwt_helper import create_token, token_required, hash_password
from utils.email_service import generate_otp, send_otp_email, store_otp, verify_otp
from database import db

auth_bp = Blueprint("auth", __name__)

def _log(action, user=None, detail="", severity="info"):
    db.session.add(AuditLog(user_id=user.id if user else None,
        institution_id=user.institution_id if user else None,
        action=action, detail=detail, ip_address=request.remote_addr, severity=severity))
    db.session.commit()

@auth_bp.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json() or {}
    email, password = data.get("email","").strip().lower(), data.get("password","")
    if not email or not password: return jsonify({"error":"Email and password required"}), 400
    user = User.query.filter_by(email=email, role="admin").first()
    if not user or user.password_hash != hash_password(password):
        _log("ADMIN_LOGIN_FAILED", detail=f"Failed for {email}", severity="warning")
        return jsonify({"error":"Invalid credentials"}), 401
    if user.status != "active": return jsonify({"error":"Account not active"}), 403
    otp = generate_otp(); store_otp(email, otp); email_sent = send_otp_email(email, otp, user.first_name)
    _log("ADMIN_OTP_SENT", user, f"OTP sent to {email}")
    return jsonify({"message":"OTP sent to your email","email":email,"email_sent":email_sent,
                    "dev_hint":"Check Render logs for OTP if email not configured"}), 200

@auth_bp.route("/admin/verify-otp", methods=["POST"])
def admin_verify_otp():
    data = request.get_json() or {}
    email, otp = data.get("email","").strip().lower(), data.get("otp","").strip()
    if not email or not otp: return jsonify({"error":"Email and OTP required"}), 400
    if not verify_otp(email, otp):
        _log("OTP_FAILED", detail=f"Wrong OTP for {email}", severity="warning")
        return jsonify({"error":"Invalid or expired OTP"}), 401
    user = User.query.filter_by(email=email, role="admin").first()
    if not user: return jsonify({"error":"User not found"}), 404
    token = create_token(user.id, user.role, user.institution_id)
    _log("ADMIN_LOGIN_SUCCESS", user)
    return jsonify({"token":token,"user":user.to_dict(),"message":"Login successful"}), 200

@auth_bp.route("/staff/login", methods=["POST"])
def staff_login():
    data = request.get_json() or {}
    staff_id, password = data.get("staff_id","").strip(), data.get("password","")
    if not staff_id or not password: return jsonify({"error":"Staff ID and password required"}), 400
    user = (User.query.filter_by(staff_id=staff_id).first() or
            User.query.filter_by(email=staff_id, role="staff").first())
    if not user or user.password_hash != hash_password(password):
        _log("STAFF_LOGIN_FAILED", detail=f"Failed for {staff_id}", severity="warning")
        return jsonify({"error":"Invalid Staff ID or password"}), 401
    if user.status != "active": return jsonify({"error":"Account pending approval"}), 403
    token = create_token(user.id, user.role, user.institution_id)
    _log("STAFF_LOGIN_SUCCESS", user)
    return jsonify({"token":token,"user":user.to_dict(),"message":"Login successful"}), 200

@auth_bp.route("/me", methods=["GET"])
@token_required
def me():
    return jsonify({"user":request.current_user.to_dict()}), 200

@auth_bp.route("/logout", methods=["POST"])
@token_required
def logout():
    _log("LOGOUT", request.current_user)
    return jsonify({"message":"Logged out"}), 200
'''

# ── routes/institution.py ─────────────────────────────────────────────────────
files['routes/institution.py'] = '''import secrets, string
from flask import Blueprint, request, jsonify
from models.user import Institution, User
from utils.jwt_helper import token_required, hash_password
from database import db

institution_bp = Blueprint("institution", __name__)

def _gen_code(n=8):
    return "".join(secrets.choice(string.ascii_uppercase+string.digits) for _ in range(n))

@institution_bp.route("/register", methods=["POST"])
def register_institution():
    data = request.get_json() or {}
    name, contact = data.get("institution_name","").strip(), data.get("contact_person","").strip()
    email, phone  = data.get("email","").strip().lower(), data.get("phone","").strip()
    if not name or not contact or not email:
        return jsonify({"error":"Name, contact, and email required"}), 400
    if Institution.query.filter_by(email=email).first():
        return jsonify({"error":"Institution with this email exists"}), 409
    code = _gen_code()
    inst = Institution(name=name,code=code,contact_person=contact,email=email,phone=phone,status="approved")
    db.session.add(inst); db.session.commit()
    return jsonify({"message":"Institution registered","institution_code":code,"institution_name":name}), 201

@institution_bp.route("/validate-code", methods=["POST"])
def validate_code():
    data = request.get_json() or {}
    code = data.get("code","").strip().upper()
    if not code: return jsonify({"error":"Code required"}), 400
    inst = Institution.query.filter_by(code=code, status="approved").first()
    if not inst: return jsonify({"error":"Invalid or unapproved code"}), 404
    admin_count = User.query.filter_by(institution_id=inst.id, role="admin").count()
    staff_count = User.query.filter_by(institution_id=inst.id, role="staff").count()
    return jsonify({"valid":True,"institution":inst.to_dict(),
        "slots":{"admin_available":admin_count==0,"staff_available":staff_count<2,
                 "admin_count":admin_count,"staff_count":staff_count}}), 200

@institution_bp.route("/create-account", methods=["POST"])
def create_account():
    data = request.get_json() or {}
    code  = data.get("institution_code","").strip().upper()
    email = data.get("email","").strip().lower()
    role  = data.get("role","staff")
    password = data.get("password","")
    if not all([code, data.get("first_name"), data.get("last_name"), email, password]):
        return jsonify({"error":"All fields required"}), 400
    if len(password) < 8: return jsonify({"error":"Password min 8 chars"}), 400
    inst = Institution.query.filter_by(code=code, status="approved").first()
    if not inst: return jsonify({"error":"Invalid institution code"}), 404
    if User.query.filter_by(email=email).first(): return jsonify({"error":"Email already registered"}), 409
    if role=="admin" and User.query.filter_by(institution_id=inst.id,role="admin").count()>=1:
        return jsonify({"error":"Institution already has an admin"}), 409
    if role=="staff" and User.query.filter_by(institution_id=inst.id,role="staff").count()>=2:
        return jsonify({"error":"Max 2 staff per institution"}), 409
    staff_id = f"KV-{inst.id:03d}-{User.query.count()+1:04d}"
    user = User(first_name=data.get("first_name",""), last_name=data.get("last_name",""),
        email=email, staff_id=staff_id, password_hash=hash_password(password), role=role,
        department=data.get("department","SOC"), institution_id=inst.id,
        status="active" if role=="admin" else "pending")
    db.session.add(user); db.session.commit()
    return jsonify({"message":"Account created","staff_id":staff_id,"user":user.to_dict()}), 201

@institution_bp.route("/users", methods=["GET"])
@token_required
def list_users():
    users = User.query.filter_by(institution_id=request.current_user.institution_id).all()
    return jsonify({"users":[u.to_dict() for u in users]}), 200

@institution_bp.route("/users/<int:user_id>/status", methods=["PUT"])
@token_required
def update_user_status(user_id):
    if request.current_user.role != "admin": return jsonify({"error":"Admin only"}), 403
    data   = request.get_json() or {}
    status = data.get("status")
    if status not in ("active","suspended","pending"): return jsonify({"error":"Invalid status"}), 400
    user = User.query.filter_by(id=user_id,institution_id=request.current_user.institution_id).first()
    if not user: return jsonify({"error":"User not found"}), 404
    user.status = status; db.session.commit()
    return jsonify({"message":f"Status set to {status}","user":user.to_dict()}), 200
'''

# ── routes/scanner.py ─────────────────────────────────────────────────────────
files['routes/scanner.py'] = '''import json
from flask import Blueprint, request, jsonify
from models.phishing_detector import analyze_url
from models.email_scanner import scan_email
from models.threat_analyzer import analyze_ip, generate_threat_feed
from models.user import ScanResult, Incident
from utils.jwt_helper import token_required
from database import db

scanner_bp = Blueprint("scanner", __name__)

def _save(scan_type, input_data, result, user):
    db.session.add(ScanResult(scan_type=scan_type, input_data=input_data[:500],
        verdict=result.verdict, confidence=result.confidence,
        details=json.dumps(result.to_dict()), scanned_by=user.id,
        institution_id=user.institution_id))
    if result.verdict == "malicious":
        db.session.add(Incident(institution_id=user.institution_id,
            title=f"Malicious {scan_type.upper()} detected",
            description=f"Scanner flagged: {input_data[:200]}",
            threat_type="phishing" if scan_type=="url" else "malware",
            severity="high", confidence=result.confidence, target=input_data[:200]))
    db.session.commit()

@scanner_bp.route("/url", methods=["POST"])
@token_required
def scan_url():
    data = request.get_json() or {}
    url  = data.get("url","").strip()
    if not url: return jsonify({"error":"URL required"}), 400
    result = analyze_url(url); _save("url", url, result, request.current_user)
    return jsonify({"result":result.to_dict()}), 200

@scanner_bp.route("/email", methods=["POST"])
@token_required
def scan_email_route():
    data = request.get_json() or {}
    subject, sender, body = data.get("subject",""), data.get("sender",""), data.get("body","")
    if not body and not subject: return jsonify({"error":"Subject or body required"}), 400
    result = scan_email(subject, sender, body, data.get("headers",""), data.get("attachments",[]))
    _save("email", f"Subject: {subject[:100]}", result, request.current_user)
    return jsonify({"result":result.to_dict()}), 200

@scanner_bp.route("/ip", methods=["POST"])
@token_required
def scan_ip():
    data = request.get_json() or {}
    ip   = data.get("ip","").strip()
    if not ip: return jsonify({"error":"IP required"}), 400
    return jsonify({"result":analyze_ip(ip).to_dict()}), 200

@scanner_bp.route("/threat-feed", methods=["GET"])
@token_required
def threat_feed():
    feed = generate_threat_feed(request.current_user.institution_id)
    return jsonify({"feed":feed,"count":len(feed)}), 200

@scanner_bp.route("/history", methods=["GET"])
@token_required
def scan_history():
    page  = request.args.get("page",1,type=int)
    scans = (ScanResult.query.filter_by(institution_id=request.current_user.institution_id)
             .order_by(ScanResult.created_at.desc()).paginate(page=page,per_page=20,error_out=False))
    return jsonify({"scans":[s.to_dict() for s in scans.items],"total":scans.total,"page":page}), 200

@scanner_bp.route("/url/batch", methods=["POST"])
@token_required
def scan_url_batch():
    data = request.get_json() or {}
    urls = data.get("urls",[])
    if not urls: return jsonify({"error":"Provide a list of URLs"}), 400
    if len(urls) > 50: return jsonify({"error":"Max 50 URLs per batch"}), 400
    results = [analyze_url(str(u).strip()).to_dict() for u in urls]
    mal = sum(1 for r in results if r["verdict"]=="malicious")
    sus = sum(1 for r in results if r["verdict"]=="suspicious")
    return jsonify({"results":results,"summary":{"total":len(results),"malicious":mal,
                    "suspicious":sus,"safe":len(results)-mal-sus}}), 200
'''

# ── routes/dashboard.py ───────────────────────────────────────────────────────
files['routes/dashboard.py'] = '''import datetime
from flask import Blueprint, request, jsonify
from models.user import AuditLog, Incident, BlockedIP, ScanResult
from utils.jwt_helper import token_required
from database import db

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/stats", methods=["GET"])
@token_required
def stats():
    inst_id = request.current_user.institution_id
    today   = datetime.datetime.utcnow().replace(hour=0,minute=0,second=0)
    trend   = []
    for i in range(6,-1,-1):
        d = today - datetime.timedelta(days=i)
        count = Incident.query.filter(Incident.institution_id==inst_id,
            Incident.created_at>=d, Incident.created_at<d+datetime.timedelta(days=1)).count()
        trend.append({"date":d.strftime("%b %d"),"incidents":count})
    sev = {s:Incident.query.filter_by(institution_id=inst_id,severity=s).count()
           for s in ["low","medium","high","critical"]}
    return jsonify({"incidents":{
        "total":Incident.query.filter_by(institution_id=inst_id).count(),
        "open":Incident.query.filter_by(institution_id=inst_id,status="open").count(),
        "critical":Incident.query.filter_by(institution_id=inst_id,severity="critical").count(),
        "severity_breakdown":sev},
        "scanning":{"total_scans":ScanResult.query.filter_by(institution_id=inst_id).count(),
            "threats_found":ScanResult.query.filter_by(institution_id=inst_id,verdict="malicious").count()},
        "firewall":{"blocked_ips":BlockedIP.query.filter_by(institution_id=inst_id,is_active=True).count()},
        "trend_7d":trend}), 200

@dashboard_bp.route("/incidents", methods=["GET"])
@token_required
def list_incidents():
    inst_id = request.current_user.institution_id
    page    = request.args.get("page",1,type=int)
    q = Incident.query.filter_by(institution_id=inst_id)
    if request.args.get("status"):   q = q.filter_by(status=request.args.get("status"))
    if request.args.get("severity"): q = q.filter_by(severity=request.args.get("severity"))
    incidents = q.order_by(Incident.created_at.desc()).paginate(page=page,per_page=25,error_out=False)
    return jsonify({"incidents":[i.to_dict() for i in incidents.items],"total":incidents.total}), 200

@dashboard_bp.route("/incidents", methods=["POST"])
@token_required
def create_incident():
    data = request.get_json() or {}
    inc  = Incident(institution_id=request.current_user.institution_id,
        title=data.get("title","Manual incident"), description=data.get("description",""),
        threat_type=data.get("threat_type","anomaly"), severity=data.get("severity","medium"),
        source_ip=data.get("source_ip",""), target=data.get("target",""),
        confidence=data.get("confidence",0.5))
    db.session.add(inc); db.session.commit()
    return jsonify({"incident":inc.to_dict()}), 201

@dashboard_bp.route("/incidents/<int:incident_id>/status", methods=["PUT"])
@token_required
def update_incident(incident_id):
    data   = request.get_json() or {}
    status = data.get("status")
    if status not in ("open","investigating","resolved"): return jsonify({"error":"Invalid status"}), 400
    inc = Incident.query.filter_by(id=incident_id,institution_id=request.current_user.institution_id).first()
    if not inc: return jsonify({"error":"Not found"}), 404
    inc.status = status
    if status == "resolved": inc.resolved_at = datetime.datetime.utcnow()
    db.session.commit()
    return jsonify({"incident":inc.to_dict()}), 200

@dashboard_bp.route("/firewall", methods=["GET"])
@token_required
def list_blocked():
    blocked = BlockedIP.query.filter_by(institution_id=request.current_user.institution_id,is_active=True)\
                             .order_by(BlockedIP.created_at.desc()).all()
    return jsonify({"blocked_ips":[b.to_dict() for b in blocked]}), 200

@dashboard_bp.route("/firewall/block", methods=["POST"])
@token_required
def block_ip():
    data = request.get_json() or {}
    ip   = data.get("ip","").strip()
    if not ip: return jsonify({"error":"IP required"}), 400
    if BlockedIP.query.filter_by(ip_address=ip,institution_id=request.current_user.institution_id,is_active=True).first():
        return jsonify({"error":"IP already blocked"}), 409
    expires = None
    if data.get("expires_hours"):
        expires = datetime.datetime.utcnow() + datetime.timedelta(hours=int(data["expires_hours"]))
    b = BlockedIP(ip_address=ip, reason=data.get("reason","Manual block"),
        blocked_by=request.current_user.id, institution_id=request.current_user.institution_id,
        expires_at=expires)
    db.session.add(b); db.session.commit()
    return jsonify({"message":f"IP {ip} blocked","block":b.to_dict()}), 201

@dashboard_bp.route("/firewall/<int:block_id>", methods=["DELETE"])
@token_required
def unblock_ip(block_id):
    b = BlockedIP.query.filter_by(id=block_id,institution_id=request.current_user.institution_id).first()
    if not b: return jsonify({"error":"Not found"}), 404
    b.is_active = False; db.session.commit()
    return jsonify({"message":f"IP {b.ip_address} unblocked"}), 200
'''

# ── routes/logs.py ────────────────────────────────────────────────────────────
files['routes/logs.py'] = '''import json, datetime
from flask import Blueprint, request, jsonify, Response
from models.user import AuditLog
from utils.jwt_helper import token_required
from database import db

logs_bp = Blueprint("logs", __name__)

@logs_bp.route("/audit", methods=["GET"])
@token_required
def get_logs():
    inst_id  = request.current_user.institution_id
    page     = request.args.get("page",1,type=int)
    severity = request.args.get("severity")
    action   = request.args.get("action")
    q = AuditLog.query.filter_by(institution_id=inst_id)
    if severity: q = q.filter_by(severity=severity)
    if action:   q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    logs = q.order_by(AuditLog.timestamp.desc()).paginate(page=page,per_page=50,error_out=False)
    return jsonify({"logs":[l.to_dict() for l in logs.items],"total":logs.total,"page":page}), 200

@logs_bp.route("/audit/export", methods=["GET"])
@token_required
def export_logs():
    inst_id = request.current_user.institution_id
    logs    = AuditLog.query.filter_by(institution_id=inst_id).order_by(AuditLog.timestamp.desc()).all()
    data    = {"exported_at":datetime.datetime.utcnow().isoformat(),
               "total":len(logs),"logs":[l.to_dict() for l in logs]}
    return Response(json.dumps(data,indent=2), mimetype="application/json",
        headers={"Content-Disposition":f"attachment; filename=kavachnet-audit-{datetime.date.today()}.json"})

@logs_bp.route("/audit", methods=["POST"])
@token_required
def add_log():
    data = request.get_json() or {}
    log  = AuditLog(user_id=request.current_user.id, institution_id=request.current_user.institution_id,
        action=data.get("action","MANUAL"), resource=data.get("resource",""),
        detail=data.get("detail",""), ip_address=request.remote_addr,
        severity=data.get("severity","info"))
    db.session.add(log); db.session.commit()
    return jsonify({"log":log.to_dict()}), 201

@logs_bp.route("/audit/stats", methods=["GET"])
@token_required
def log_stats():
    inst_id  = request.current_user.institution_id
    today    = datetime.datetime.utcnow().replace(hour=0,minute=0,second=0)
    return jsonify({"total":AuditLog.query.filter_by(institution_id=inst_id).count(),
        "warnings":AuditLog.query.filter_by(institution_id=inst_id,severity="warning").count(),
        "critical":AuditLog.query.filter_by(institution_id=inst_id,severity="critical").count(),
        "today":AuditLog.query.filter(AuditLog.institution_id==inst_id,
                                      AuditLog.timestamp>=today).count()}), 200
'''

# ── Write all files ────────────────────────────────────────────────────────────
for path, content in files.items():
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"  wrote  {path}")

print("\nAll files created successfully!")
print("Now run: git add . && git commit -m 'feat: complete backend' && git push origin main")