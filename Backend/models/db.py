# models/db.py

import sqlite3
import datetime
import uuid
import random
import string
from collections import defaultdict
from config import Config

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
    DBIntegrityError = (sqlite3.IntegrityError, psycopg2.IntegrityError)
except ImportError:
    PSYCOPG2_AVAILABLE = False
    DBIntegrityError = sqlite3.IntegrityError

class PostgresCursorWrapper:
    def __init__(self, cursor):
        self.cursor = cursor
        
    def execute(self, sql, params=None):
        sql = sql.replace('?', '%s')
        if params is not None:
            self.cursor.execute(sql, params)
        else:
            self.cursor.execute(sql)
        return self

    def executescript(self, sql):
        self.cursor.execute(sql)
        return self

    def fetchone(self):
        res = self.cursor.fetchone()
        return dict(res) if res else None

    def fetchall(self):
        res = self.cursor.fetchall()
        return [dict(r) for r in res] if res else []

class PostgresWrapper:
    def __init__(self, conn):
        self.conn = conn
        self.row_factory = None
        self.is_postgres = True

    def cursor(self):
        c = self.conn.cursor(cursor_factory=RealDictCursor)
        return PostgresCursorWrapper(c)

    def execute(self, sql, params=None):
        c = self.cursor()
        return c.execute(sql, params)
        
    def executescript(self, sql):
        c = self.cursor()
        c.execute(sql)
        return c

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()

def _generate_institution_code():
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=8))


class Database:
    def __init__(self):
        self.db_name = Config.DB_NAME
        self._create_tables()

    def _connect(self):
        if getattr(Config, 'DATABASE_URL', None) and PSYCOPG2_AVAILABLE:
            conn = psycopg2.connect(Config.DATABASE_URL)
            return PostgresWrapper(conn)
            
        # Increased timeout for enterprise concurrency
        conn = sqlite3.connect(self.db_name, timeout=20.0) 
        conn.row_factory = sqlite3.Row
        return conn

    def _create_tables(self):
        conn = self._connect()
        cursor = conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS institutions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                contact_person TEXT NOT NULL,
                phone TEXT,
                institution_code TEXT UNIQUE,
                status TEXT DEFAULT 'pending',
                rejection_reason TEXT,
                created_at TEXT NOT NULL,
                approved_at TEXT,
                code_expires_at TEXT
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'staff',
                institution_code TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL,
                lockout_until TEXT
            );

            CREATE TABLE IF NOT EXISTS failed_attempts (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS login_logs (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                hour INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT DEFAULT 'OPEN',
                timestamp TEXT NOT NULL,
                institution_code TEXT,
                forensics TEXT -- Column for IP/UA
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                object_type TEXT NOT NULL,
                object_id TEXT,
                timestamp TEXT NOT NULL,
                forensics TEXT
            );

            CREATE TABLE IF NOT EXISTS institution_codes (
                id TEXT PRIMARY KEY,
                institution_id TEXT NOT NULL,
                code_value TEXT NOT NULL UNIQUE,
                generated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT DEFAULT 'ACTIVE',
                generated_by TEXT,
                FOREIGN KEY(institution_id) REFERENCES institutions(id)
            );

            CREATE TABLE IF NOT EXISTS email_logs (
                id TEXT PRIMARY KEY,
                recipient TEXT NOT NULL,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER DEFAULT 1,
                last_error TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_queue (
                id TEXT PRIMARY KEY,
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                html_body TEXT NOT NULL,
                text_body TEXT,
                type TEXT NOT NULL,
                institution_id TEXT,
                status TEXT DEFAULT 'PENDING',
                attempts INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 3,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                next_retry_at TEXT NOT NULL
            );
            
            -- Production Performance: Indexes
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_inst ON users(institution_code);
            CREATE INDEX IF NOT EXISTS idx_incidents_inst ON incidents(institution_code);
            CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_logs_username ON login_logs(username);
            CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs(username);
            CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(timestamp DESC);
        """)
        
        # Gracefully upgrade existing DBs without recreating
        try:
            cursor.execute("ALTER TABLE email_queue ADD COLUMN next_retry_at TEXT DEFAULT '2000-01-01T00:00:00'")
        except Exception:
            pass # Column already exists
            
        conn.commit()
        conn.close()
        print("[DB] Tables ready.")

    # ── INSTITUTIONS ──────────────────────────
    def register_institution(self, name, email, contact_person, phone=""):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO institutions (id, name, email, contact_person, phone, status, created_at) VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), name, email, contact_person, phone, 'pending', datetime.datetime.now().isoformat())
            )
            conn.commit()
            return True, None
        except DBIntegrityError:
            return False, "This institution email is already registered."
        finally:
            conn.close()

    def get_all_institutions(self):
        conn = self._connect()
        rows = conn.execute("SELECT * FROM institutions ORDER BY created_at DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_institution_by_code(self, code):
        conn = self._connect()
        row = conn.execute("SELECT * FROM institutions WHERE institution_code=?", (code,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_institution_by_id(self, inst_id):
        conn = self._connect()
        row = conn.execute("SELECT * FROM institutions WHERE id=?", (inst_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def approve_institution(self, inst_id, superadmin_username="superadmin"):
        conn = self._connect()
        while True:
            code = _generate_institution_code()
            existing = conn.execute("SELECT id FROM institutions WHERE institution_code=?", (code,)).fetchone()
            if not existing:
                break
        
        now = datetime.datetime.now()
        expiry = (now + datetime.timedelta(days=7)).isoformat()
        
        conn.execute(
            "UPDATE institutions SET status='approved', institution_code=?, approved_at=?, code_expires_at=? WHERE id=?",
            (code, now.isoformat(), expiry, inst_id)
        )
        conn.execute(
            "INSERT INTO institution_codes (id, institution_id, code_value, generated_at, expires_at, status, generated_by) VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), inst_id, code, now.isoformat(), expiry, 'ACTIVE', superadmin_username)
        )
        conn.commit()
        conn.close()
        return code, expiry

    def rotate_institution_code(self, inst_id, superadmin_username="superadmin"):
        conn = self._connect()
        
        # Get old code
        old_inst = conn.execute("SELECT institution_code FROM institutions WHERE id=?", (inst_id,)).fetchone()
        old_code = old_inst['institution_code'] if old_inst else None

        # Expire old codes in history
        conn.execute(
            "UPDATE institution_codes SET status='EXPIRED' WHERE institution_id=? AND status='ACTIVE'",
            (inst_id,)
        )

        while True:
            code = _generate_institution_code()
            existing = conn.execute("SELECT id FROM institutions WHERE institution_code=?", (code,)).fetchone()
            if not existing:
                break
        
        now = datetime.datetime.now()
        expiry = (now + datetime.timedelta(days=7)).isoformat()
        
        conn.execute(
            "UPDATE institutions SET institution_code=?, code_expires_at=? WHERE id=?",
            (code, expiry, inst_id)
        )
        conn.execute(
            "INSERT INTO institution_codes (id, institution_id, code_value, generated_at, expires_at, status, generated_by) VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), inst_id, code, now.isoformat(), expiry, 'ACTIVE', superadmin_username)
        )
        conn.commit()
        conn.close()
        return old_code, code, expiry

    def reject_institution(self, inst_id, reason=""):
        conn = self._connect()
        conn.execute("UPDATE institutions SET status='rejected', rejection_reason=? WHERE id=?", (reason, inst_id))
        conn.commit()
        conn.close()

    def get_member_count(self, institution_code):
        conn = self._connect()
        rows = conn.execute(
            "SELECT role, COUNT(*) as cnt FROM users WHERE institution_code=? AND status='approved' GROUP BY role",
            (institution_code,)
        ).fetchall()
        conn.close()
        counts = {r['role']: r['cnt'] for r in rows}
        return counts.get('admin', 0), counts.get('staff', 0)

    # ── USERS ─────────────────────────────────
    def save_user(self, username, hashed_password, email, role="staff", institution_code=None, status="pending"):
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO users (id, username, password, email, role, institution_code, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), username, hashed_password, email, role, institution_code, status, datetime.datetime.now().isoformat())
            )
            conn.commit()
            return True
        except DBIntegrityError:
            return False, "Username already exists."
        finally:
            conn.close()

    def get_user(self, username):
        conn = self._connect()
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_users_by_institution(self, institution_code):
        conn = self._connect()
        rows = conn.execute(
            "SELECT id, username, email, role, status, created_at FROM users WHERE institution_code=? ORDER BY created_at DESC",
            (institution_code,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_pending_staff(self, institution_code):
        conn = self._connect()
        rows = conn.execute(
            "SELECT id, username, email, role, status, created_at FROM users WHERE institution_code=? AND status='pending' ORDER BY created_at DESC",
            (institution_code,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def update_user_status(self, user_id, status):
        conn = self._connect()
        conn.execute("UPDATE users SET status=? WHERE id=?", (status, user_id))
        conn.commit()
        conn.close()

    def lock_user(self, username, until_iso):
        conn = self._connect()
        conn.execute("UPDATE users SET lockout_until=? WHERE username=?", (until_iso, username))
        conn.commit()
        conn.close()

    def clear_lockout(self, username):
        conn = self._connect()
        conn.execute("UPDATE users SET lockout_until=NULL WHERE username=?", (username,))
        conn.commit()
        conn.close()

    # ── FAILED ATTEMPTS ───────────────────────
    def log_failed_attempt(self, username):
        conn = self._connect()
        conn.execute(
            "INSERT INTO failed_attempts (id, username, timestamp) VALUES (?,?,?)",
            (str(uuid.uuid4()), username, datetime.datetime.now().isoformat())
        )
        conn.commit()
        conn.close()

    def get_recent_failed_attempts(self, username, window_seconds=300):
        conn = self._connect()
        cutoff = (datetime.datetime.now() - datetime.timedelta(seconds=window_seconds)).isoformat()
        rows = conn.execute(
            "SELECT * FROM failed_attempts WHERE username=? AND timestamp >= ?", (username, cutoff)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ── LOGIN LOGS ────────────────────────────
    def log_login(self, username, status):
        now = datetime.datetime.now()
        conn = self._connect()
        conn.execute(
            "INSERT INTO login_logs (id, username, status, timestamp, hour) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), username, status, now.isoformat(), now.hour)
        )
        conn.commit()
        conn.close()

    def get_all_login_logs(self):
        conn = self._connect()
        rows = conn.execute("SELECT hour, status FROM login_logs").fetchall()
        conn.close()
        grouped = defaultdict(lambda: {"hour": 0, "failed_count": 0, "success_count": 0})
        for row in rows:
            h = row["hour"]
            grouped[h]["hour"] = h
            if row["status"] == "FAILED":
                grouped[h]["failed_count"] += 1
            else:
                grouped[h]["success_count"] += 1
        return list(grouped.values())

    # ── INCIDENTS ─────────────────────────────
    def save_incident(self, incident: dict, institution_code=None):
        import datetime
        from flask import request
        
        # Ultra Security: Capture IP and UA if in request context
        ip = "system"
        ua = "system"
        try:
            ip = request.remote_addr or "unknown"
            ua = request.headers.get("User-Agent", "unknown")
        except:
            pass
            
        forensics = f"IP: {ip} | UA: {ua}"
        
        conn = self._connect()
        conn.execute(
            "INSERT INTO incidents (id, type, severity, message, status, timestamp, institution_code, forensics) VALUES (?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), incident.get("type","UNKNOWN"), incident.get("severity","LOW"),
             incident.get("message",""), "OPEN", datetime.datetime.now().isoformat(), institution_code, forensics)
        )
        conn.commit()
        conn.close()

    def get_all_incidents(self, institution_code=None):
        conn = self._connect()
        if institution_code:
            rows = conn.execute("SELECT * FROM incidents WHERE institution_code=? ORDER BY timestamp DESC", (institution_code,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM incidents ORDER BY timestamp DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_incident_by_id(self, incident_id):
        conn = self._connect()
        row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def update_incident_status(self, incident_id, new_status):
        conn = self._connect()
        conn.execute("UPDATE incidents SET status=? WHERE id=?", (new_status, incident_id))
        conn.commit()
        conn.close()

    # ── AUDIT LOGS ────────────────────────────
    def save_audit_log(self, username, action, object_type, object_id=None):
        # Capture IP/UA if in request context
        forensics = "system"
        try:
            from flask import request
            ip = request.remote_addr or "unknown"
            ua = request.headers.get("User-Agent", "unknown")
            forensics = f"IP: {ip} | UA: {ua}"
        except:
            pass

        conn = self._connect()
        conn.execute(
            "INSERT INTO audit_logs (id, username, action, object_type, object_id, timestamp, forensics) VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), username, action, object_type, object_id, datetime.datetime.now().isoformat(), forensics)
        )
        conn.commit()
        conn.close()

    def get_audit_logs(self, limit=100):
        conn = self._connect()
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # ── EMAIL LOGS ────────────────────────────
    def log_email_dispatch(self, recipient: str, log_type: str, status: str, attempts: int = 1, last_error: str = None):
        conn = self._connect()
        conn.execute(
            "INSERT INTO email_logs (id, recipient, type, status, attempts, last_error, created_at) VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), recipient, log_type, status, attempts, last_error, datetime.datetime.now().isoformat())
        )
        conn.commit()
        conn.close()

    def get_email_logs(self, limit: int = 100, log_type: str = None, status: str = None):
        """Fetches email logs for SuperAdmin observation with strict PII masking."""
        conn = self._connect()
        conn.row_factory = sqlite3.Row
        
        query = "SELECT * FROM email_logs"
        params = []
        conditions = []
        
        if log_type:
            conditions.append("type = ?")
            params.append(log_type)
        if status:
            conditions.append("status = ?")
            params.append(status)
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        try:
            rows = conn.execute(query, params).fetchall()
            logs = []
            for r in rows:
                d = dict(r)
                # Apply Zero-Trust PII Masking
                email = d.get('recipient', '')
                if '@' in email:
                    _, domain = email.split('@', 1)
                    d['recipient'] = f"***@{domain}"
                else:
                    d['recipient'] = "***"
                logs.append(d)
            return logs
        finally:
            conn.close()

    # ── EMAIL QUEUE & RATE LIMITING ───────────
    def enqueue_email(self, recipient: str, subject: str, html_body: str, text_body: str, log_type: str, institution_id: str = None):
        """Pushes an email to the DB-backed queue to be sent asynchronously."""
        from utils.validators import validate_email_strict
        from utils.json_logger import json_metrics_logger
        
        if not validate_email_strict(recipient):
             json_metrics_logger.error("Zero-Trust Regex Rejected Email", extra={"metrics": {"recipient": recipient, "type": log_type}})
             return
        
        conn = self._connect()
        try:
            now = datetime.datetime.now().isoformat()
            email_id = str(uuid.uuid4())
            conn.execute(
                '''INSERT INTO email_queue 
                   (id, recipient, subject, html_body, text_body, type, institution_id, created_at, updated_at, next_retry_at) 
                   VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (email_id, recipient, subject, html_body, text_body, log_type, institution_id, now, now, now)
            )
            conn.commit()
        finally:
            conn.close()

    def claim_pending_emails(self, batch_size=10):
        """Pulls pending (or retrying) emails safely."""
        conn = self._connect()
        conn.row_factory = sqlite3.Row
        try:
            # Find eligible emails: PENDING (and time allows it), or PROCESSING that have been stuck for > 5 mins (crash recovery)
            five_mins_ago = (datetime.datetime.now() - datetime.timedelta(minutes=5)).isoformat()
            now = datetime.datetime.now().isoformat()
            
            if hasattr(conn, 'is_postgres') and conn.is_postgres:
                rows = conn.execute(
                    '''SELECT id FROM email_queue 
                       WHERE (status = 'PENDING' AND next_retry_at <= ?) OR (status = 'PROCESSING' AND updated_at < ?) 
                       ORDER BY created_at ASC LIMIT ?
                       FOR UPDATE SKIP LOCKED''',
                    (now, five_mins_ago, batch_size)
                ).fetchall()
            else:
                conn.execute("BEGIN EXCLUSIVE")
                # Select IDs to claim
                rows = conn.execute(
                    '''SELECT id FROM email_queue 
                       WHERE (status = 'PENDING' AND next_retry_at <= ?) OR (status = 'PROCESSING' AND updated_at < ?) 
                       ORDER BY created_at ASC LIMIT ?''',
                    (now, five_mins_ago, batch_size)
                ).fetchall()
            
            claimed_ids = [r['id'] for r in rows]
            
            if claimed_ids:
                placeholders = ','.join('?' * len(claimed_ids))
                now = datetime.datetime.now().isoformat()
                conn.execute(
                    f"UPDATE email_queue SET status='PROCESSING', updated_at=? WHERE id IN ({placeholders})",
                    [now] + claimed_ids
                )
                
                emails = conn.execute(
                    f"SELECT * FROM email_queue WHERE id IN ({placeholders})",
                    claimed_ids
                ).fetchall()
                
                conn.commit()
                return [dict(e) for e in emails]
            
            conn.commit()
            return []
        except Exception:
            conn.rollback()
            return []
        finally:
            conn.close()

    def update_email_queue_status(self, email_id: str, status: str, error: str = None, next_retry_at: str = None):
        """Updates attempt count and final state of queued email."""
        conn = self._connect()
        now = datetime.datetime.now().isoformat()
        if not next_retry_at:
            next_retry_at = now
            
        try:
            conn.execute(
                "UPDATE email_queue SET status=?, attempts=attempts+1, last_error=?, updated_at=?, next_retry_at=? WHERE id=?",
                (status, error, now, next_retry_at, email_id)
            )
            conn.commit()
        finally:
            conn.close()

    def check_anomaly_thresholds(self, recipient: str, institution_id: str, log_type: str) -> bool:
        """Evaluates email volume against strict anomaly rules. Returns True if SAFE."""
        conn = self._connect()
        now = datetime.datetime.now()
        try:
            # Rule 1: OTPs (15 per hour per recipient)
            if 'OTP' in log_type:
                one_hour_ago = (now - datetime.timedelta(hours=1)).isoformat()
                count = conn.execute(
                    "SELECT COUNT(*) as count FROM email_queue WHERE recipient=? AND type LIKE '%OTP%' AND created_at > ?",
                    (recipient, one_hour_ago)
                ).fetchone()['count']
                return count < 15
                
            # Enforce institution boundaries
            if not institution_id:
                return True
                
            # Rule 2: Code Rotations (5 per day per institution)
            if 'ROTATION' in log_type or 'EXPIRY' in log_type:
                one_day_ago = (now - datetime.timedelta(days=1)).isoformat()
                count = conn.execute(
                    "SELECT COUNT(*) as count FROM email_queue WHERE institution_id=? AND (type LIKE '%ROTATION%' OR type LIKE '%EXPIRY%') AND created_at > ?",
                    (institution_id, one_day_ago)
                ).fetchone()['count']
                return count < 5
                
            # Rule 3: Alerts/Incidents (30 per hour per institution to prevent alert fatigue)
            if 'THREAT' in log_type or 'INCIDENT' in log_type:
                one_hour_ago = (now - datetime.timedelta(hours=1)).isoformat()
                count = conn.execute(
                    "SELECT COUNT(*) as count FROM email_queue WHERE institution_id=? AND (type LIKE '%THREAT%' OR type LIKE '%INCIDENT%') AND created_at > ?",
                    (institution_id, one_hour_ago)
                ).fetchone()['count']
                return count < 30
                
            # Default rate limit (50 per hour)
            one_hour_ago = (now - datetime.timedelta(hours=1)).isoformat()
            count = conn.execute(
                "SELECT COUNT(*) as count FROM email_queue WHERE institution_id=? AND created_at > ?",
                (institution_id, one_hour_ago)
            ).fetchone()['count']
            return count < 50
        finally:
            conn.close()
