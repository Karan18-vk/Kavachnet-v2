
# modules/phishing.py

import requests
import re
from urllib.parse import urlparse
from config import Config

def check_phishing(url: str):
    """
    Check if a URL is potentially phishing/malicious
    Returns risk score and detailed check results
    """
    result = {
        "url": url,
        "checks": {},
        "verdict": "SAFE",
        "risk_score": 0
    }

    # Check 1: Google Safe Browsing API
    try:
        payload = {
            "client": {
                "clientId": "kavachnet",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={Config.GOOGLE_API_KEY}",
            json=payload,
            timeout=5
        ).json()
        
        if resp.get("matches"):
            result["checks"]["google_safe_browsing"] = "FLAGGED — Known threat"
            result["risk_score"] += 50
        else:
            result["checks"]["google_safe_browsing"] = "CLEAN"
    except Exception as e:
        result["checks"]["google_safe_browsing"] = f"ERROR: {str(e)}"

    # Check 2: HTTPS check
    if not url.startswith("https://"):
        result["checks"]["https"] = "MISSING — Insecure connection"
        result["risk_score"] += 20
    else:
        result["checks"]["https"] = "OK"

    # Check 3: Suspicious keyword check
    suspicious_keywords = ["login", "verify", "update", "secure", "account", "confirm", 
                          "banking", "suspended", "urgent", "alert", "mcd-gov", "ration"]
    domain = urlparse(url).netloc.lower()
    hits = [kw for kw in suspicious_keywords if kw in domain]
    
    if hits:
        result["checks"]["suspicious_keywords"] = f"Found: {', '.join(hits)}"
        result["risk_score"] += 20
    else:
        result["checks"]["suspicious_keywords"] = "CLEAN"

    # Check 4: IP address as domain (very suspicious)
    if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
        result["checks"]["ip_as_domain"] = "FLAGGED — Using IP instead of domain name"
        result["risk_score"] += 30
    else:
        result["checks"]["ip_as_domain"] = "OK"

    # Check 5: URL length (phishing URLs are often very long)
    if len(url) > 100:
        result["checks"]["url_length"] = f"SUSPICIOUS — {len(url)} characters (very long)"
        result["risk_score"] += 10
    else:
        result["checks"]["url_length"] = "OK"

    # Final verdict based on risk score
    if result["risk_score"] >= 50:
        result["verdict"] = "PHISHING — DO NOT OPEN"
    elif result["risk_score"] >= 30:
        result["verdict"] = "HIGH RISK — Proceed with extreme caution"
    elif result["risk_score"] >= 15:
        result["verdict"] = "SUSPICIOUS — Be careful"
    else:
        result["verdict"] = "SAFE — No major threats detected"

    return result