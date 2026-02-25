
import requests
import time

BASE_URL = "http://localhost:5000"

def test_password_complexity():
    print("\n[TEST] Verifying Backend Password Complexity (Ultra-Level)...")
    # Weak password should fail even if frontend is bypassed
    resp = requests.post(BASE_URL + "/api/register/admin", json={
        "username": "ultra_test_user_" + str(time.time())[-4:],
        "password": "weak",
        "email": "test@kavachnet.com",
        "institution_code": "KAVACH2026"
    })
    print(f"  Weak Password Status: {resp.status_code} - {resp.json().get('error')}")
    if resp.status_code == 400 and "at least 12" in resp.json().get("error", "").lower():
        print("  ✅ Complexity Enforcement active!")
    else:
        print("  ❌ Complexity Enforcement failed.")

def test_rate_limiting():
    print("\n[TEST] Verifying API Rate Limiting (Ultra-Level)...")
    success_count = 0
    blocked_count = 0
    
    # Auth endpoints have a 5/min limit. Let's hit a public one with 50/hour.
    # Actually, let's hit /api/health which is subject to default limits.
    for i in range(10):
        resp = requests.get(BASE_URL + "/api/health")
        if resp.status_code == 429:
            blocked_count += 1
        else:
            success_count += 1
            
    print(f"  Requests made: 10 | Blocked: {blocked_count}")
    # Note: 10 might not hit the default day/hour limit if not burst, 
    # but the auth endpoints are stricter.
    
    print("  Testing Auth Throttling (5/min)...")
    for i in range(7):
        resp = requests.post(BASE_URL + "/api/login/step1", json={
            "username": "sentinel_admin",
            "password": "WrongPassword123!"
        })
        if resp.status_code == 429:
            print(f"  ✅ Request {i+1} blocked by Rate Limiter")
            blocked_count += 1
            break
        time.sleep(0.1)
    else:
         print("  ❌ Auth Throttling failed to trigger")

if __name__ == "__main__":
    time.sleep(2) # Wait for server to stabilize
    try:
        test_password_complexity()
        test_rate_limiting()
    except Exception as e:
        print(f"Error during tests: {e}")
