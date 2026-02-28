import time
import os
os.environ["EMAIL_DRY_RUN"] = "True"

from models.db import Database
from utils.email_tasks import send_institution_approval_task
from utils.email_queue import email_worker
from utils.json_logger import json_metrics_logger

def verify_async_queue():
    db = Database()
    
    # Let the worker start in the background
    print("[*] Starting EmailQueueWorker Daemon...")
    email_worker.start()
    
    # 1. Setup Mock Inst
    inst_name = "Async Ops Labs"
    email = "test-async" + str(id({}))[-4:] + "@kavachnet.test"
    db.register_institution(inst_name, email, "Bob Async", "+1 555-0999")
    
    conn = db._connect()
    inst = conn.execute("SELECT id FROM institutions WHERE email=?", (email,)).fetchone()
    inst_id = inst['id']
    conn.close()

    # 2. Fire 3 rapid approvals to check Rate Limiting and Enqueue Speed
    print(f"\n[*] Firing rapid task commands off the main thread to {email}...")
    code, expiry = db.approve_institution(inst_id)
    
    t0 = time.time()
    
    # First attempt (should enqueue)
    res1 = send_institution_approval_task(inst_id, code, expiry)
    
    # Subsequent attempts (should be throttled within 1 hour limit of 10 for approval? Actually limit is 10)
    # Let's fire 11 times.
    for i in range(12):
         send_institution_approval_task(inst_id, code, expiry)
         
    dt = (time.time() - t0) * 1000
    print(f"[*] Main thread execution time for 13 dispatch calls: {dt:.2f} ms")

    # 3. Wait for Background Worker to process
    print(f"\n[*] Waiting for background daemon to consume the queue (approx 4 seconds)...")
    time.sleep(4)
    
    # 4. Check Queue State
    conn = db._connect()
    q_items = conn.execute("SELECT status, attempts FROM email_queue WHERE recipient=?", (email,)).fetchall()
    
    print("\n[QUEUE STATUS]")
    for idx, q in enumerate(q_items):
        print(f"  - Item {idx}: {q['status']} | Attempts: {q['attempts']}")
    conn.close()
    
    print("\n[*] Stopping Worker...")
    email_worker.stop()

if __name__ == "__main__":
    verify_async_queue()
