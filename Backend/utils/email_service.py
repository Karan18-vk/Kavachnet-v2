# Backend/utils/email_service.py

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time
import os
from config import Config
from utils.logger import app_logger

# Determine if we should actually dispatch emails
EMAIL_DRY_RUN = os.getenv("EMAIL_DRY_RUN", "False").lower() == "true"

def send_email_with_retry(to_email: str, subject: str, html_content: str, text_content: str = None, max_attempts: int = 3, backoff_base: int = 2):
    """
    Core resilient email dispatcher.
    Handles SMTP connections, exponential backoff retries, and dry-run safety.
    """
    
    if EMAIL_DRY_RUN:
        app_logger.info(f"[[DRY RUN]] Email to {to_email} | Subject: {subject}")
        app_logger.debug(f"[[DRY RUN]] Body snippet: {html_content[:100]}...")
        # Simulate success for dry runs
        return True, 1, None
        
    msg = MIMEMultipart('alternative')
    msg['From'] = Config.EMAIL_ADDRESS
    msg['To'] = to_email
    msg['Subject'] = subject
    
    if text_content:
        msg.attach(MIMEText(text_content, 'plain'))
    if html_content:
        msg.attach(MIMEText(html_content, 'html'))
        
    attempts = 0
    last_error = None
    
    while attempts < max_attempts:
        attempts += 1
        try:
            server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=10)
            server.starttls()
            server.login(Config.EMAIL_ADDRESS, Config.EMAIL_PASSWORD)
            server.sendmail(Config.EMAIL_ADDRESS, to_email, msg.as_string())
            server.quit()
            
            app_logger.info(f"Successfully dispatched email to {to_email} (Attempt {attempts})")
            return True, attempts, None
            
        except smtplib.SMTPAuthenticationError as e:
            # Permanent failure: Do not retry
            last_error = f"AuthError: {str(e)}"
            app_logger.error(f"Permanent SMTP Auth Failure for {to_email}: {last_error}")
            break
            
        except smtplib.SMTPRecipientsRefused as e:
            # Permanent failure: Invalid recipient
            last_error = f"RecipientRefused: {str(e)}"
            app_logger.error(f"Recipient Refused for {to_email}: {last_error}")
            break
            
        except Exception as e:
            # Transient failure: Timeout, connection drop, etc.
            last_error = str(e)
            app_logger.warning(f"Transient SMTP failure for {to_email} (Attempt {attempts}/{max_attempts}): {last_error}")
            
            if attempts < max_attempts:
                sleep_time = backoff_base ** attempts
                time.sleep(sleep_time)
                
    app_logger.error(f"Final email dispatch failure to {to_email} after {attempts} attempts. Last Error: {last_error}")
    return False, attempts, last_error
