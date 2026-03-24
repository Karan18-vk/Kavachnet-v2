from database import db
from datetime import datetime

class Institution(db.Model):
    __tablename__ = "institutions"
    id             = db.Column(db.String(255), primary_key=True)
    name           = db.Column(db.String(255), nullable=False)
    email          = db.Column(db.String(255), unique=True, nullable=False)
    contact_person = db.Column(db.String(255), nullable=False)
    phone          = db.Column(db.String(50))
    institution_code = db.Column(db.String(50), unique=True)
    status         = db.Column(db.String(20), default="pending")
    rejection_reason = db.Column(db.Text)
    created_at     = db.Column(db.String(50), nullable=False)
    approved_at    = db.Column(db.String(50))
    code_expires_at = db.Column(db.String(50))
    
    def to_dict(self):
        return {"id": self.id, "name": self.name, "email": self.email,
                "institution_code": self.institution_code, "status": self.status, 
                "created_at": self.created_at}

class User(db.Model):
    __tablename__ = "users"
    id             = db.Column(db.String(255), primary_key=True)
    username       = db.Column(db.String(255), unique=True, nullable=False)
    password       = db.Column(db.String(255), nullable=False) # Changed from password_hash
    email          = db.Column(db.String(255), nullable=False)
    role           = db.Column(db.String(20),  default="staff")
    institution_code = db.Column(db.String(50))
    status         = db.Column(db.String(20),  default="pending")
    created_at     = db.Column(db.String(50), nullable=False)
    lockout_until  = db.Column(db.String(50))

    def to_dict(self):
        return {"id": self.id, "username": self.username,
                "email": self.email, "role": self.role,
                "institution_code": self.institution_code,
                "status": self.status, "created_at": self.created_at}

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id             = db.Column(db.String(255), primary_key=True)
    username       = db.Column(db.String(255), nullable=False)
    action         = db.Column(db.String(100), nullable=False)
    object_type    = db.Column(db.String(50), nullable=False)
    object_id      = db.Column(db.String(255))
    timestamp      = db.Column(db.String(50), nullable=False)
    forensics      = db.Column(db.Text)
    def to_dict(self):
        return {"id": self.id, "username": self.username, "action": self.action,
                "object_type": self.object_type, "timestamp": self.timestamp}

class Incident(db.Model):
    __tablename__ = "incidents"
    id             = db.Column(db.String(255), primary_key=True)
    institution_id = db.Column(db.String(255))
    title          = db.Column(db.String(255))
    description    = db.Column(db.Text)
    threat_type    = db.Column(db.String(50))
    severity       = db.Column(db.String(20), default="medium")
    status         = db.Column(db.String(20), default="OPEN")
    confidence     = db.Column(db.Float)
    target         = db.Column(db.Text)

    def to_dict(self):
        return {"id": self.id, "title": self.title, "threat_type": self.threat_type,
                "severity": self.severity, "status": self.status, "timestamp": self.timestamp}

class OTPRecord(db.Model):
    __tablename__ = "otp_records"
    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(150), nullable=False)
    otp_code   = db.Column(db.String(6),   nullable=False)
    expires_at = db.Column(db.DateTime,    nullable=False)
    used       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"
    id             = db.Column(db.Integer, primary_key=True)
    ip_address     = db.Column(db.String(50),  nullable=False)
    reason         = db.Column(db.String(200))
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    is_active      = db.Column(db.Boolean, default=True)

class ScanResult(db.Model):
    __tablename__ = "scan_results"
    id             = db.Column(db.Integer, primary_key=True)
    scan_type      = db.Column(db.String(30))
    input_data     = db.Column(db.Text)
    verdict        = db.Column(db.String(20))
    confidence     = db.Column(db.Float)
    details        = db.Column(db.Text)
    scanned_by     = db.Column(db.String(255))
    institution_id = db.Column(db.String(255))
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "scan_type": self.scan_type, "input_data": self.input_data,
            "verdict": self.verdict, "confidence": self.confidence,
            "details": self.details, "created_at": self.created_at.isoformat() if self.created_at else None
        }

class UserOverride(db.Model):
    __tablename__ = "user_overrides"
    id             = db.Column(db.String(255), primary_key=True)
    username       = db.Column(db.String(255), nullable=False)
    target_url     = db.Column(db.Text, nullable=False)
    risk_level     = db.Column(db.String(20), nullable=False)
    timestamp      = db.Column(db.String(50), nullable=False)
    forensics      = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "target_url": self.target_url,
            "risk_level": self.risk_level,
            "timestamp": self.timestamp,
            "forensics": self.forensics
        }
