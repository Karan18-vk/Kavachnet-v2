
import requests
import time

BASE_URL = "http://localhost:5000"

def test_health():
    print("\n[TEST] Verifying Backend Health...")
    try:
        resp = requests.get(BASE_URL + "/health")
        print(f"  Status: {resp.status_code} - {resp.json()}")
        if resp.status_code == 200 and resp.json().get("status") == "healthy":
            print("  ✅ Health endpoint OK!")
        else:
            print("  ❌ Health endpoint FAIL.")
    except Exception as e:
        print(f"  ❌ Health check error: {e}")

def test_password_complexity():
    print("\n[TEST] Verifying Backend Password Complexity (Ultra-Level)...")
    # Prefix updated to /api/v1/auth
    try:
        resp = requests.post(BASE_URL + "/api/v1/auth/register/admin", json={
            "username": "ultra_test_user_" + str(time.time())[-4:],
            "password": "weak",
            "email": "test@kavachnet.com",
            "institution_code": "KAVACH2026"
        })
        print(f"  Weak Password Status: {resp.status_code}")
        data = resp.json()
        # Note: In production we might return a generic 400 or a specific error
        if resp.status_code == 400:
            print("  ✅ Complexity Enforcement active (Rejected weak password)!")
        else:
            print(f"  ❌ Complexity Enforcement failed: {data}")
    except Exception as e:
        print(f"  ❌ Password complexity test error: {e}")

def test_rate_limiting():
    print("\n[TEST] Verifying API Rate Limiting...")
    print("  Testing Auth Throttling (Default limits hit via rapid auth reqs)...")
    try:
        for i in range(120): 
            resp = requests.post(BASE_URL + "/api/v1/auth/login/step1", json={
                "username": "non_existent_sentinel",
                "password": "WrongPassword123!"
            })
            if resp.status_code == 429:
                print(f"  ✅ Request {i+1} successfully throttled (429)")
                return
            time.sleep(0.02)
        print("  ⚠️ Rate Limiting not triggered in 120 rapid bursts.")
    except Exception as e:
        print(f"  ❌ Rate limit test error: {e}")

if __name__ == "__main__":
    time.sleep(1)
    test_health()
    test_password_complexity()
    test_rate_limiting()
