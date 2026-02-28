# Backend/utils/email_tasks.py

from utils.email_templates import (
    build_otp_email,
    build_institution_approval_email,
    build_code_update_email,
    build_threat_alert_email,
    build_incident_email
)
from models.db import Database
from utils.json_logger import json_metrics_logger

# We maintain a transient local db connection for tasks, 
# although in production a connection pool or SQLAlchemy session is preferred.

def _get_db():
    return Database()

def send_otp_task(username: str, email: str, otp: str):
    """Enqueues an OTP to the async email queue."""
    db = _get_db()
    
    if not db.check_anomaly_thresholds(email, None, "AUTH_OTP"):
        json_metrics_logger.warning("OTP email thwarted by anomaly limits", extra={"metrics": {"recipient": email, "event": "anomaly_blocked"}})
        return False
        
    subject, html_body, txt_body = build_otp_email(otp)
    
    db.enqueue_email(email, subject, html_body, txt_body, "AUTH_OTP", institution_id=None)
    json_metrics_logger.info("OTP task enqueued", extra={"metrics": {"event": "enqueue", "type": "AUTH_OTP", "recipient": email}})
    return True

def send_institution_approval_task(institution_id: str, code: str, expiry: str):
    db = _get_db()
    
    inst = db.get_institution_by_id(institution_id)
    if not inst:
        return False
        
    admin_name = inst['contact_person']
    email = inst['email']
    
    if not db.check_anomaly_thresholds(email, institution_id, "INST_APPROVAL"):
        json_metrics_logger.warning("Approval email thwarted by anomaly limits", extra={"metrics": {"institution_id": institution_id, "event": "anomaly_blocked"}})
        return False
    
    subject, html_body, txt_body = build_institution_approval_email(admin_name, code, expiry)
    
    db.enqueue_email(email, subject, html_body, txt_body, "INST_APPROVAL", institution_id)
    json_metrics_logger.info("Approval task enqueued", extra={"metrics": {"event": "enqueue", "type": "INST_APPROVAL", "institution_id": institution_id}})
    return True

def send_institution_code_update_task(institution_id: str, old_code: str, new_code: str, expiry: str):
    db = _get_db()
    
    inst = db.get_institution_by_id(institution_id)
    if not inst:
        return False
        
    admin_name = inst['contact_person']
    email = inst['email']
    inst_name = inst['name']
    
    if not db.check_anomaly_thresholds(email, institution_id, "CODE_ROTATION"):
        json_metrics_logger.warning("Rotation email thwarted by anomaly limits", extra={"metrics": {"institution_id": institution_id, "event": "anomaly_blocked"}})
        return False
    
    subject, html_body, txt_body = build_code_update_email(admin_name, inst_name, old_code, new_code, expiry)
    
    db.enqueue_email(email, subject, html_body, txt_body, "CODE_ROTATION", institution_id)
    json_metrics_logger.info("Rotation task enqueued", extra={"metrics": {"event": "enqueue", "type": "CODE_ROTATION", "institution_id": institution_id}})
    return True

def send_threat_alert_task(institution_code: str, threat_details: str, severity: str):
    db = _get_db()
    inst = db.get_institution_by_code(institution_code)
    if not inst:
        return False
        
    inst_id = inst['id']
    email = inst['email']
    inst_name = inst['name']
    
    if not db.check_anomaly_thresholds(email, inst_id, "THREAT_ALERT"):
        json_metrics_logger.warning("Threat alert thwarted by anomaly limits", extra={"metrics": {"institution_id": inst_id, "event": "anomaly_blocked"}})
        return False
    
    subject, html_body, txt_body = build_threat_alert_email(inst_name, threat_details, severity)
    
    db.enqueue_email(email, subject, html_body, txt_body, "THREAT_ALERT", inst_id)
    json_metrics_logger.info("Threat alert enqueued", extra={"metrics": {"event": "enqueue", "type": "THREAT_ALERT", "institution_id": inst_id}})
    return True

def send_incident_report_task(institution_code: str, incident_type: str, message: str, severity: str):
    db = _get_db()
    inst = db.get_institution_by_code(institution_code)
    
    if not inst:
        return False
        
    inst_id = inst['id']
    email = inst['email']
    inst_name = inst['name']
    
    if not db.check_anomaly_thresholds(email, inst_id, "INCIDENT_REPORT"):
        json_metrics_logger.warning("Incident report thwarted by anomaly limits", extra={"metrics": {"institution_id": inst_id, "event": "anomaly_blocked"}})
        return False
    
    subject, html_body, txt_body = build_incident_email(inst_name, incident_type, message, severity)
    
    db.enqueue_email(email, subject, html_body, txt_body, "INCIDENT_REPORT", inst_id)
    json_metrics_logger.info("Incident report enqueued", extra={"metrics": {"event": "enqueue", "type": "INCIDENT_REPORT", "institution_id": inst_id}})
    return True
