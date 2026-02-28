# Backend/test_email_tasks.py

import os
# Force dry run for testing without spamming
os.environ["EMAIL_DRY_RUN"] = "True"

from models.db import Database
from utils.email_tasks import (
    send_otp_task,
    send_institution_approval_task,
    send_institution_code_update_task,
    send_threat_alert_task,
    send_incident_report_task
)
from utils.logger import app_logger

def verify_email_infrastructure():
    db = Database()
    
    # 1. Setup Mock Data
    print("\n[TEST] Setting up mock institution...")
    inst_name = "Cyber Ops Testing"
    email = "test-admin" + str(id({}))[-4:] + "@kavachnet.test"
    db.register_institution(inst_name, email, "Alice Security", "+1 555-0199")
    
    conn = db._connect()
    inst = conn.execute("SELECT id FROM institutions WHERE email=?", (email,)).fetchone()
    inst_id = inst['id']
    conn.close()

    # 2. Test Approval Task
    print("\n[TEST] 1. Institution Approval Task")
    code, expiry = db.approve_institution(inst_id)
    send_institution_approval_task(inst_id, code, expiry)
    
    # 3. Test OTP Task
    print("\n[TEST] 2. OTP Task")
    send_otp_task("test_user", email, "837194")
    
    # 4. Test Code Rotation Task
    print("\n[TEST] 3. Code Rotation Task")
    old_code, new_code, expiry2 = db.rotate_institution_code(inst_id)
    send_institution_code_update_task(inst_id, old_code, new_code, expiry2)
    
    # 5. Test Threat Alert Task
    print("\n[TEST] 4. Threat Alert Task")
    send_threat_alert_task(new_code, "Unusual geovelocity access detected from 3 distinct IP subnets within 5 minutes.", "HIGH")

    # 6. Test Incident Report Task
    print("\n[TEST] 5. Incident Report Task")
    send_incident_report_task(new_code, "DDoS Mitigation Triggered", "Edge layer wAF activated. Dropping 5,000 req/s.", "CRITICAL_ATTACK")

    # 7. Audit DB Verification
    print("\n[TEST] Verifying Forensic DB Logs...")
    conn = db._connect()
    logs = conn.execute("SELECT recipient, type, status, attempts FROM email_logs WHERE recipient=?", (email,)).fetchall()
    
    print("-" * 50)
    for log in logs:
        print(f"[{log['type']}] -> {log['status']} (Attempts: {log['attempts']})")
    print("-" * 50)
    
    conn.close()

if __name__ == "__main__":
    verify_email_infrastructure()
