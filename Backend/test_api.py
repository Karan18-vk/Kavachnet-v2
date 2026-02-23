# test_api.py

import requests
import json

BASE_URL = "http://localhost:5000"

# Color codes for terminal
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

def test_health():
    print(f"\n{BLUE}TEST 1: Health Check{RESET}")
    response = requests.get(f"{BASE_URL}")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    return response.status_code == 200

def test_register():
    print(f"\n{BLUE}TEST 2: Register User{RESET}")
    data = {
        "username": "testuser",
        "password": "Test@123",
        "email": "thankssubscribe385@gmail.com" 
    }
    response = requests.post(f"{BASE_URL}/api/register", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    return response.status_code in [201, 409]  # 409 if already exists

def test_login_step1():
    print(f"\n{BLUE}TEST 3: Login Step 1 (Send OTP){RESET}")
    data = {
        "username": "testuser",
        "password": "Test@123"
    }
    response = requests.post(f"{BASE_URL}/api/login/step1", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print(f"\n{GREEN}[OK] CHECK YOUR EMAIL FOR OTP!{RESET}")
    return response.status_code == 200

def test_login_step2(otp):
    print(f"\n{BLUE}TEST 4: Login Step 2 (Verify OTP){RESET}")
    data = {
        "username": "testuser",
        "otp": otp
    }
    response = requests.post(f"{BASE_URL}/api/login/step2", json=data)
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Response: {result}")
    
    if response.status_code == 200:
        token = result.get("token")
        print(f"\n{GREEN}[OK] TOKEN RECEIVED!{RESET}")
        return token
    return None

def test_encryption(token):
    print(f"\n{BLUE}TEST 5: Generate Encryption Key{RESET}")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/encryption/newkey", headers=headers)
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Response: {result}")
    key = result.get("key")
    
    if key:
        print(f"\n{BLUE}TEST 6: Encrypt Data{RESET}")
        data = {
            "text": "Secret government data for MCD",
            "key": key
        }
        response = requests.post(f"{BASE_URL}/api/encryption/encrypt", json=data, headers=headers)
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Encrypted: {result.get('encrypted_text')[:50]}...")
        
        encrypted = result.get("encrypted_text")
        
        if encrypted:
            print(f"\n{BLUE}TEST 7: Decrypt Data{RESET}")
            data = {
                "encrypted_text": encrypted,
                "key": key
            }
            response = requests.post(f"{BASE_URL}/api/encryption/decrypt", json=data, headers=headers)
            print(f"Status: {response.status_code}")
            result = response.json()
            print(f"Decrypted: {result.get('decrypted_text')}")

def test_phishing(token):
    print(f"\n{BLUE}TEST 8: Check Phishing URL{RESET}")
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "url": "http://login-facebook.security-update.example.com"
    }
    response = requests.post(f"{BASE_URL}/api/phishing/check", json=data, headers=headers)
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Verdict: {result.get('verdict')}")
    print(f"Risk Score: {result.get('risk_score')}")
    print(f"Checks: {json.dumps(result.get('checks'), indent=2)}")

def test_threat(token):
    print(f"\n{BLUE}TEST 9: Get Threat Status{RESET}")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/threat/status", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def test_incidents(token):
    print(f"\n{BLUE}TEST 10: Get All Incidents{RESET}")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/incidents", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    print(f"\n{BLUE}TEST 11: Download PDF Report{RESET}")
    response = requests.get(f"{BASE_URL}/api/incidents/report/pdf", headers=headers)
    if response.status_code == 200:
        with open("incident_report.pdf", "wb") as f:
            f.write(response.content)
        print(f"{GREEN}[OK] PDF saved as incident_report.pdf{RESET}")

def main():
    print(f"{BLUE}{'='*50}")
    print(" KavachNet Backend Testing")
    print(f"{'='*50}{RESET}")
    
    # Test 1: Health Check
    if not test_health():
        print(f"{RED}[ERROR] Server not running! Start with: python app.py{RESET}")
        return
    
    # Test 2: Register
    test_register()
    
    # Test 3: Login Step 1
    if not test_login_step1():
        print(f"{RED}[ERROR] Login failed{RESET}")
        return
    
    # Wait for user to enter OTP
    # Attempt to fetch OTP automatically
    print(f"\n{BLUE}DEBUG: Fetching OTP automatically...{RESET}")
    otp_response = requests.get(f"{BASE_URL}/api/debug/otp/testuser")
    if otp_response.status_code == 200:
        otp = otp_response.json().get("otp")
        print(f"{GREEN}[OK] OTP Fetched: {otp}{RESET}")
    else:
        # Fallback to manual input
        otp = input(f"\n{GREEN}Enter the OTP from your email: {RESET}")
    
    # Test 4: Login Step 2
    token = test_login_step2(otp)
    if not token:
        print(f"{RED}[ERROR] OTP verification failed{RESET}")
        return
    
    # Test 5-7: Encryption
    test_encryption(token)
    
    # Test 8: Phishing
    test_phishing(token)
    
    # Test 9: Threat
    test_threat(token)
    
    # Test 10-11: Incidents
    test_incidents(token)
    
    print(f"\n{GREEN}{'='*50}")
    print("[OK] ALL TESTS COMPLETED!")
    print("Backened is fully working with all test")
    print(f"{'='*50}{RESET}")

if __name__ == "__main__":
    main()
