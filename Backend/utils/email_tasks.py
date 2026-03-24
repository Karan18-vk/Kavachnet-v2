from utils.email_templates import (
    build_otp_email,
    build_institution_approval_email,
    build_code_update_email,
    build_threat_alert_email,
    build_incident_email
)
from models.user import EmailQueue, Institution
from database import db
from utils.json_logger import json_metrics_logger
from datetime import datetime, timedelta

def check_anomaly_thresholds(recipient: str, institution_id: str, log_type: str) -> bool:
    """Evaluates email volume against strict anomaly rules using SQLAlchemy."""
    now = datetime.utcnow()
    
    # Rule 1: OTPs (15 per hour per recipient)
    if 'OTP' in log_type:
        one_hour_ago = now - timedelta(hours=1)
        count = EmailQueue.query.filter(
            EmailQueue.recipient == recipient,
            EmailQueue.type.contains('OTP'),
            EmailQueue.created_at >= one_hour_ago
        ).count()
        return count < 15
        
    # Rule 2: Code Rotations (5 per day per institution)
    if institution_id and ('ROTATION' in log_type or 'EXPIRY' in log_type):
        one_day_ago = now - timedelta(days=1)
        count = EmailQueue.query.filter(
            EmailQueue.institution_id == institution_id,
            (EmailQueue.type.contains('ROTATION') | EmailQueue.type.contains('EXPIRY')),
            EmailQueue.created_at >= one_day_ago
        ).count()
        return count < 5
        
    # Rule 3: Alerts/Incidents (30 per hour per institution)
    if institution_id and ('THREAT' in log_type or 'INCIDENT' in log_type):
        one_hour_ago = now - timedelta(hours=1)
        count = EmailQueue.query.filter(
            EmailQueue.institution_id == institution_id,
            (EmailQueue.type.contains('THREAT') | EmailQueue.type.contains('INCIDENT')),
            EmailQueue.created_at >= one_hour_ago
        ).count()
        return count < 30
        
    # Default rate limit (50 per hour per institution)
    if institution_id:
        one_hour_ago = now - timedelta(hours=1)
        count = EmailQueue.query.filter(
            EmailQueue.institution_id == institution_id,
            EmailQueue.created_at >= one_hour_ago
        ).count()
        return count < 50
        
    return True

def enqueue_email(recipient, subject, html, text, log_type, institution_id=None):
    """Pushes an email to the SQLAlchemy-backed queue."""
    try:
        new_email = EmailQueue(
            recipient=recipient,
            subject=subject,
            html_body=html,
            text_body=text,
            type=log_type,
            institution_id=institution_id,
            status="PENDING"
        )
        db.session.add(new_email)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        json_metrics_logger.error(f"Email enqueue failed: {e}")
        return False

def send_otp_task(username: str, email: str, otp: str):
    if not check_anomaly_thresholds(email, None, "AUTH_OTP"):
        json_metrics_logger.warning("OTP email thwarted by anomaly limits", extra={"metrics": {"recipient": email, "event": "anomaly_blocked"}})
        return False
        
    subject, html_body, txt_body = build_otp_email(otp)
    return enqueue_email(email, subject, html_body, txt_body, "AUTH_OTP", institution_id=None)

def send_institution_approval_task(institution_id: str, code: str, expiry: str):
    inst = Institution.query.get(institution_id)
    if not inst: return False
    
    email = inst.admin_email
    if not check_anomaly_thresholds(email, institution_id, "INST_APPROVAL"):
        json_metrics_logger.warning("Approval email thwarted by anomaly limits", extra={"metrics": {"institution_id": institution_id, "event": "anomaly_blocked"}})
        return False
    
    subject, html_body, txt_body = build_institution_approval_email(inst.name, code, expiry)
    return enqueue_email(email, subject, html_body, txt_body, "INST_APPROVAL", institution_id)

def send_institution_code_update_task(institution_id: str, old_code: str, new_code: str, expiry: str):
    inst = Institution.query.get(institution_id)
    if not inst: return False
    
    email = inst.admin_email
    if not check_anomaly_thresholds(email, institution_id, "CODE_ROTATION"):
        json_metrics_logger.warning("Rotation email thwarted by anomaly limits", extra={"metrics": {"institution_id": institution_id, "event": "anomaly_blocked"}})
        return False
    
    subject, html_body, txt_body = build_code_update_email(inst.name, inst.name, old_code, new_code, expiry)
    return enqueue_email(email, subject, html_body, txt_body, "CODE_ROTATION", institution_id)

def send_threat_alert_task(institution_code: str, threat_details: str, severity: str):
    inst = Institution.query.filter_by(institution_code=institution_code).first()
    if not inst: return False
    
    if not check_anomaly_thresholds(inst.admin_email, inst.id, "THREAT_ALERT"):
        json_metrics_logger.warning("Threat alert thwarted by anomaly limits", extra={"metrics": {"institution_id": inst.id, "event": "anomaly_blocked"}})
        return False
    
    subject, html_body, txt_body = build_threat_alert_email(inst.name, threat_details, severity)
    return enqueue_email(inst.admin_email, subject, html_body, txt_body, "THREAT_ALERT", inst.id)

def send_incident_report_task(institution_code: str, incident_type: str, message: str, severity: str):
    inst = Institution.query.filter_by(institution_code=institution_code).first()
    if not inst: return False
    
    if not check_anomaly_thresholds(inst.admin_email, inst.id, "INCIDENT_REPORT"):
        json_metrics_logger.warning("Incident report thwarted by anomaly limits", extra={"metrics": {"institution_id": inst.id, "event": "anomaly_blocked"}})
        return False
    
    subject, html_body, txt_body = build_incident_email(inst.name, incident_type, message, severity)
    return enqueue_email(inst.admin_email, subject, html_body, txt_body, "INCIDENT_REPORT", inst.id)
