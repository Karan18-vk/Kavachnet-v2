# Backend/app_legacy_migration.py

import os
import sqlite3
import uuid
import datetime
import bcrypt
from config import Config

def run_migration(db):
    """Handles critical seeding and schema updates from legacy app.py"""
    conn = sqlite3.connect(Config.DB_NAME)
    conn.row_factory = sqlite3.Row
    
    # 1. Schema Hardening
    columns = [
        ("institutions", "code_expires_at", "TEXT"),
        ("users", "lockout_until", "TEXT"),
        ("incidents", "forensics", "TEXT")
    ]
    
    for table, col, col_type in columns:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
            print(f"[DB_MIGRATE] Added {col} to {table}")
        except sqlite3.OperationalError:
            pass # Already exists

    # 2. Seeding
    count = conn.execute("SELECT COUNT(*) FROM institutions").fetchone()[0]
    if count == 0:
        inst_id = str(uuid.uuid4())
        code = os.getenv("SEED_INST_CODE", "KAVACH2026")
        now = datetime.datetime.now()
        expiry = (now + datetime.timedelta(days=365)).isoformat()
        
        conn.execute(
            "INSERT INTO institutions (id, name, email, contact_person, institution_code, status, created_at, approved_at, code_expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (inst_id, "Kavach Net Sentinel HQ", "sentinel@kavachnet.com", "Operations Lead", code, "approved", now.isoformat(), now.isoformat(), expiry)
        )
        
        # Admin Seed
        username = os.getenv("SEED_ADMIN_USER", "sentinel_admin")
        password = os.getenv("SEED_ADMIN_PASS", "DemoAdmin123!")
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        
        conn.execute(
            "INSERT INTO users (id, username, password, email, role, institution_code, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), username, hashed, "admin@kavachnet.com", "admin", code, "approved", now.isoformat())
        )
        print(f"[DB_SEED] Seeded initial admin: {username}")

    conn.commit()
    conn.close()
