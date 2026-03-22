import sys
import os
import bcrypt
sys.path.append(os.getcwd())
from models.db import Database
from app import create_app

app = create_app()

with app.app_context():
    db = Database()
    conn = db._connect()
    # Create an institution
    inst_code = "TESTING123"
    try:
        db.register_institution("Test Inst", "test@inst.com", "Test Person")
        conn.execute("UPDATE institutions SET status='approved', institution_code=? WHERE email=?", (inst_code, "test@inst.com"))
        conn.commit()
    except Exception as e:
        print("Inst exists or err:", e)
    
    # Create a staff user
    hashed = bcrypt.hashpw("StaffStaff123!".encode(), bcrypt.gensalt()).decode()
    conn.execute("DELETE FROM users WHERE username='staff_test'")
    conn.commit()
    conn.close()

    db.save_user("staff_test", hashed, "staff@test.com", "staff", inst_code, "approved")
    
    # Text login_step1 directly via test client
    client = app.test_client()
    resp = client.post("/api/v1/auth/login/step1", json={
        "username": "staff_test",
        "password": "StaffStaff123!"
    })
    
    print("STATUS:", resp.status_code)
    print("DATA:", resp.get_json())
