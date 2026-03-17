# Backend/verify_fix.py

import requests
import sqlite3
import os
import uuid

BASE_URL = "http://localhost:5000/api/v1"

def test_health():
    print("Testing /health endpoint...")
    try:
        res = requests.get(f"{BASE_URL}/health")
        print(f"Status: {res.status_code}")
        print(f"Body: {res.json()}")
        return res.status_code == 200
    except Exception as e:
        print(f"Health check failed: {e}")
        return False

def test_registration():
    print("\nTesting Staff Registration...")
    unique_user = f"testuser_{uuid.uuid4().hex[:6]}"
    data = {
        "username": unique_user,
        "password": "SecurePassword123!",
        "email": f"{unique_user}@example.com",
        "institution_code": "KAVACH2026"
    }
    try:
        res = requests.post(f"{BASE_URL}/auth/register/staff", json=data)
        print(f"Status: {res.status_code}")
        print(f"Body: {res.json()}")
        
        if res.status_code == 201:
            # Absolute path identification
            script_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(script_dir, "kavachnet.db")
            print(f"Checking database at: {db_path}")
            
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                user = conn.execute("SELECT * FROM users WHERE username=?", (unique_user,)).fetchone()
                conn.close()
                if user:
                    print(f"SUCCESS: User {unique_user} found in database.")
                    return True
                else:
                    print(f"FAILURE: User {unique_user} NOT found in database.")
            else:
                print(f"FAILURE: Database file not found at {db_path}")
        return False
    except Exception as e:
        print(f"Registration test failed: {e}")
        return False

def test_institution_registration():
    print("\nTesting Institution Registration...")
    unique_inst = f"Inst_{uuid.uuid4().hex[:6]}"
    data = {
        "name": unique_inst,
        "email": f"admin@{unique_inst.lower()}.com",
        "contact_person": "Verification Bot"
    }
    try:
        res = requests.post(f"{BASE_URL}/institutions/request", json=data)
        print(f"Status: {res.status_code}")
        print(f"Body: {res.json()}")
        
        if res.status_code == 201:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(script_dir, "kavachnet.db")
            
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                inst = conn.execute("SELECT * FROM institutions WHERE name=?", (unique_inst,)).fetchone()
                conn.close()
                if inst:
                    print(f"SUCCESS: Institution {unique_inst} found in database.")
                    return True
                else:
                    print(f"FAILURE: Institution {unique_inst} NOT found in database.")
            else:
                print(f"FAILURE: Database file not found at {db_path}")
        return False
    except Exception as e:
        print(f"Institution registration test failed: {e}")
        return False

if __name__ == "__main__":
    print("=== KavachNet Fix Verification ===")
    health_ok = test_health()
    reg_ok = test_registration()
    inst_ok = test_institution_registration()
    
    if health_ok and reg_ok and inst_ok:
        print("\n[PASSED] All critical fixes verified.")
    else:
        print("\n[FAILED] Some verification steps failed. Ensure server is running (python Backend/app.py)")
