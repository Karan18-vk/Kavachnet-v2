from database import db
from datetime import datetime
import uuid

class Institution(db.Model):
    __tablename__ = "institutions"
    id               = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name             = db.Column(db.String(255), nullable=False)
    institution_code = db.Column(db.String(50), unique=True, nullable=False)
    admin_email      = db.Column(db.String(255), unique=True, nullable=False)
    status           = db.Column(db.String(20), default="pending") # pending, approved, rejected
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    users = db.relationship('User', backref='institution', lazy=True)
    threat_logs = db.relationship('ThreatLog', backref='institution', lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "code": self.institution_code,
            "admin_email": self.admin_email,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class User(db.Model):
    __tablename__ = "users"
    id               = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name             = db.Column(db.String(255), nullable=False)
    email            = db.Column(db.String(255), unique=True, nullable=False)
    password_hash    = db.Column(db.String(255), nullable=False)
    role             = db.Column(db.String(20),  default="staff") # superadmin, admin, staff
    institution_id   = db.Column(db.String(36), db.ForeignKey('institutions.id'), nullable=True)
    status           = db.Column(db.String(20),  default="approved")
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    threat_logs = db.relationship('ThreatLog', backref='user', lazy=True)
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "institution_id": self.institution_id,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class ThreatLog(db.Model):
    __tablename__ = "threat_logs"
    id               = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    type             = db.Column(db.String(50), nullable=False) # phishing, malware, sql_injection, etc.
    status           = db.Column(db.String(20), default="blocked") # blocked, flagged, overridden
    risk_level       = db.Column(db.String(20), default="low") # low, medium, high, critical
    user_id          = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    institution_id   = db.Column(db.String(36), db.ForeignKey('institutions.id'), nullable=True)
    details          = db.Column(db.Text)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "status": self.status,
            "risk_level": self.risk_level,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class ActivityLog(db.Model):
    __tablename__ = "activity_logs"
    id               = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    action           = db.Column(db.String(255), nullable=False)
    user_id          = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    timestamp        = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "action": self.action,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }

# Keeping legacy support models if needed, but refactoring to use consistent naming where possible
class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id             = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    institution_id = db.Column(db.String(36), db.ForeignKey('institutions.id'))
    user_id        = db.Column(db.String(36), db.ForeignKey('users.id'))
    action         = db.Column(db.String(100), nullable=False)
    resource       = db.Column(db.String(100))
    detail         = db.Column(db.Text)
    severity       = db.Column(db.String(20), default="info") # info, warning, critical
    ip_address     = db.Column(db.String(45))
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "institution_id": self.institution_id,
            "user_id": self.user_id,
            "action": self.action,
            "resource": self.resource,
            "detail": self.detail,
            "severity": self.severity,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }

class Incident(db.Model):
    __tablename__ = "incidents"
    id             = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    institution_id = db.Column(db.String(36), db.ForeignKey('institutions.id'))
    title          = db.Column(db.String(255))
    description    = db.Column(db.Text)
    threat_type    = db.Column(db.String(50))
    severity       = db.Column(db.String(20), default="medium")
    status         = db.Column(db.String(20), default="OPEN")
    confidence     = db.Column(db.Float)
    target         = db.Column(db.Text)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "institution_id": self.institution_id,
            "title": self.title,
            "description": self.description,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "status": self.status,
            "confidence": self.confidence,
            "target": self.target,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class OTPRecord(db.Model):
    __tablename__ = "otp_records"
    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(150), nullable=False)
    otp_code   = db.Column(db.String(6),   nullable=False)
    expires_at = db.Column(db.DateTime,    nullable=False)
    used       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "otp_code": self.otp_code,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "used": self.used,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"
    id             = db.Column(db.Integer, primary_key=True)
    ip_address     = db.Column(db.String(50),  nullable=False)
    reason         = db.Column(db.String(200))
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    is_active      = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "is_active": self.is_active
        }

class ScanResult(db.Model):
    __tablename__ = "scan_results"
    id             = db.Column(db.Integer, primary_key=True)
    scan_type      = db.Column(db.String(30))
    input_data     = db.Column(db.Text)
    verdict        = db.Column(db.String(20))
    confidence     = db.Column(db.Float)
    details        = db.Column(db.Text)
    scanned_by     = db.Column(db.String(255))
    institution_id = db.Column(db.String(36), db.ForeignKey('institutions.id'))
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_type": self.scan_type,
            "input_data": self.input_data,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "details": self.details,
            "scanned_by": self.scanned_by,
            "institution_id": self.institution_id,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class UserOverride(db.Model):
    __tablename__ = "user_overrides"
    id             = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id        = db.Column(db.String(36), db.ForeignKey('users.id'))
    target_url     = db.Column(db.Text, nullable=False)
    risk_level     = db.Column(db.String(20), nullable=False)
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow)
    forensics      = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "target_url": self.target_url,
            "risk_level": self.risk_level,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "forensics": self.forensics
        }

class EmailQueue(db.Model):
    __tablename__ = "email_queue"
    id             = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    recipient      = db.Column(db.String(255), nullable=False)
    subject        = db.Column(db.String(255))
    html_body      = db.Column(db.Text)
    text_body      = db.Column(db.Text)
    type           = db.Column(db.String(50))
    status         = db.Column(db.String(20), default="PENDING") # PENDING, PROCESSING, SENT, FAILED
    attempts       = db.Column(db.Integer, default=0)
    last_error     = db.Column(db.Text)
    institution_id = db.Column(db.String(36), db.ForeignKey('institutions.id'))
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at     = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    next_retry_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "recipient": self.recipient,
            "subject": self.subject,
            "type": self.type,
            "status": self.status,
            "attempts": self.attempts,
            "last_error": self.last_error,
            "institution_id": self.institution_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }

class ChatMessage(db.Model):
    __tablename__ = "chat_messages"
    id        = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id   = db.Column(db.String(36), db.ForeignKey('users.id'))
    message   = db.Column(db.Text, nullable=False)
    reply     = db.Column(db.Text, nullable=False)
    intent    = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "message": self.message,
            "reply": self.reply,
            "intent": self.intent,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }
