

import smtplib     #use to send email using SMTP
from email.mime.text import MIMEText   # use to create email message content
from email.mime.multipart import MIMEMultipart # use to create email with multiple part
from config import Config #use to store usually email,pass,SMTP server,port number
import datetime

def send_otp(to_email: str, otp: str):
    try:
        msg = MIMEMultipart()
        msg['From'] = Config.EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = "KavachNet — Your OTP Code"

        body = f"""
        Hello,

        Your One-Time Password (OTP) for KavachNet login is:

        🔐  {otp}

        This OTP is valid for 5 minutes.
        Do NOT share this with anyone.

        — KavachNet Security System
        """
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
        server.sendmail(Config.EMAIL_ADDRESS, to_email, msg.as_string())
        server.quit()

        print(f"[EMAIL] OTP sent to {to_email}")
        return True

    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False

def send_institution_approval(to_email: str, name: str, code: str, expiry: str):
    try:
        msg = MIMEMultipart()
        msg['From'] = Config.EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = "KavachNet — Institution Approved!"

        expiry_date = datetime.datetime.fromisoformat(expiry).strftime('%d %b %Y, %I:%M %p')

        body = f"""
        Hello {name},

        Great news! Your institution has been approved by the KavachNet makers.

        Your unique Invitation Code is:
        🔐  {code}

        Use this code to register your first Admin account on the portal.

        ⚠️ SECURITY NOTICE:
        This code is valid for 1 week and will expire on {expiry_date}.
        A new code will be generated automatically after expiry and will be visible on your dashboard.

        Welcome to the shield.
        — KavachNet Security System
        """
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
        server.sendmail(Config.EMAIL_ADDRESS, to_email, msg.as_string())
        server.quit()

        print(f"[EMAIL] Approval sent to {to_email}")
        return True

    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False
