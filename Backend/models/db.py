# models/db.py

import sqlite3
import datetime
import uuid
import random
import string
from collections import defaultdict
from config import Config


def _generate_institution_code():
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=8))


class Database:
    def __init__(self):
        self.db_name = Config.DB_NAME
        self._create_tables()

    def _connect(self):
        conn = sqlite3.connect(self.db_name)
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
                created_at TEXT NOT NULL
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
                institution_code TEXT
            );
        """)
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
        except sqlite3.IntegrityError:
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

    def approve_institution(self, inst_id):
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
        conn.commit()
        conn.close()
        return code, expiry

    def rotate_institution_code(self, inst_id):
        conn = self._connect()
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
        conn.commit()
        conn.close()
        return code, expiry

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
        except sqlite3.IntegrityError:
            return False
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
        conn = self._connect()
        conn.execute(
            "INSERT INTO incidents (id, type, severity, message, status, timestamp, institution_code) VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), incident.get("type","UNKNOWN"), incident.get("severity","LOW"),
             incident.get("message",""), "OPEN", datetime.datetime.now().isoformat(), institution_code)
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

    def update_incident_status(self, incident_id, new_status):
        conn = self._connect()
        conn.execute("UPDATE incidents SET status=? WHERE id=?", (new_status, incident_id))
        conn.commit()
        conn.close()
