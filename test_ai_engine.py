
import os
import sys

# Add Backend to path
sys.path.append(os.path.join(os.getcwd(), 'Backend'))

# Mock Flask current_app for logging
class MockApp:
    def __init__(self):
        self.logger = type('Logger', (), {'info': print, 'error': print, 'warning': print})()
        self.config = {}

from unittest.mock import MagicMock
import flask
flask.current_app = MockApp()

try:
    from Backend.routes.ai_chatbot import full_scan
    
    test_url = "http://paypa1-secure-login.tk"
    print(f"\n--- Scanning URL: {test_url} ---")
    result = full_scan(test_url)
    
    import json
    print(json.dumps(result, indent=2))
    
    print("\n--- Summary ---")
    print(f"Verdict: {result['verdict']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Mode: {result['mode']}")
    print(f"Layer 2 Details: {result['layers']['layer2']}")
    print(f"Layer 3 Details: {result['layers']['layer3']}")

except Exception as e:
    print(f"Error during test: {e}")
    import traceback
    traceback.print_exc()
