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
    inst_code = "XYZ12345"
    try:
        db.register_institution("New Inst", "new@inst.com", "New Person")
        conn.execute("UPDATE institutions SET status='approved', institution_code=? WHERE email=?", (inst_code, "new@inst.com"))
        conn.commit()
    except Exception as e:
        print("Inst exists or err:", e)
    
    conn.execute("DELETE FROM users WHERE username='testguy'")
    conn.commit()
    conn.close()

    # Test staff registration directly via test client
    client = app.test_client()
    resp = client.post("/api/v1/auth/register/staff", json={
        "username": "testguy",
        "email": "testguy@test.com",
        "password": "StrongPassword123!",
        "institution_code": inst_code
    })
    
    print("STATUS:", resp.status_code)
    print("DATA:", resp.get_json())
