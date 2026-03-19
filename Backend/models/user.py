from database import db
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
