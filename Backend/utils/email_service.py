import smtplib, random, string
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
        print(f"\n[DEV MODE] OTP for {to_email}: {otp_code}\n")
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
    record = OTPRecord.query.filter_by(email=email, otp_code=otp, used=False)                            .order_by(OTPRecord.created_at.desc()).first()
    if not record or datetime.utcnow() > record.expires_at: return False
    record.used = True; db.session.commit(); return True
