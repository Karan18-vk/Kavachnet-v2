

import smtplib     #use to send email using SMTP
from email.mime.text import MIMEText   # use to create email message content
from email.mime.multipart import MIMEMultipart # use to create email with multiple part
from config import Config #use to store usually email,pass,SMTP server,port number

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
