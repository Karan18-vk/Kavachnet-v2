# Backend/routes/threat_routes.py

from flask import Blueprint, request
from flask_jwt_extended import jwt_required
from services.threat_service import ThreatService
from models.db import Database
from utils.response import api_response, api_error
from utils.validation import validate_payload, sanitize_input

threat_bp = Blueprint('threat', __name__)
db = Database()
threat_service = ThreatService(db)

@threat_bp.route("/status", methods=["GET"])
@jwt_required()
def get_threat_status():
    result = threat_service.get_summary()
    return api_response(data=result)

@threat_bp.route("/scan", methods=["POST"])
@jwt_required()
def trigger_scan():
    result = threat_service.run_scan()
    return api_response(data=result)

@threat_bp.route("/check-brute-force/<username>", methods=["GET"])
@jwt_required()
def check_brute_force(username):
    result = threat_service.check_brute_force(sanitize_input(username))
    return api_response(data=result)

@threat_bp.route("/phishing/check", methods=["POST"])
@jwt_required()
def check_phishing():
    """Enhanced phishing URL check using the email threat detection module."""
    if not request.is_json:
        return api_error("Missing JSON in request", code=400)
    
    url = request.json.get("url", "").strip()
    if not url:
        return api_error("URL is required", code=400)
    
    url = sanitize_input(url)
    
    # Use the advanced MaliciousLinkDetector for URL heuristics
    try:
        from email_threat.core import ThreatConfig
        from email_threat.link_detector import MaliciousLinkDetector
        
        config = ThreatConfig()
        detector = MaliciousLinkDetector(config)
        heuristic = detector._url_heuristics(url)
        
        risk_score = int(heuristic["score"] * 100)
        checks = []
        for reason in heuristic.get("reasons", []):
            checks.append({"check": reason, "result": "FLAGGED"})
        
        if not checks:
            checks.append({"check": "Basic pattern analysis", "result": "CLEAR"})
        
        if risk_score >= 60:
            verdict = "HIGH_RISK"
        elif risk_score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LOW_RISK"
        
        return api_response(data={
            "url": url,
            "verdict": verdict,
            "risk_score": risk_score,
            "checks": checks
        })
    except ImportError:
        # Fallback to basic heuristic checks if email_threat module fails
        risk_score = 0
        checks = []
        
        suspicious_keywords = ["login", "verify", "secure", "account", "update", "confirm", "banking", "paypal", "signin"]
        url_lower = url.lower()
        
        for keyword in suspicious_keywords:
            if keyword in url_lower:
                risk_score += 10
                checks.append({"check": f"Suspicious keyword '{keyword}'", "result": "FLAGGED"})
        
        import re
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            risk_score += 30
            checks.append({"check": "IP address in URL", "result": "FLAGGED"})
        
        risk_score = min(risk_score, 100)
        
        if risk_score >= 60:
            verdict = "HIGH_RISK"
        elif risk_score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LOW_RISK"
        
        if not checks:
            checks.append({"check": "Basic pattern analysis", "result": "CLEAR"})
        
        return api_response(data={
            "url": url,
            "verdict": verdict,
            "risk_score": risk_score,
            "checks": checks
        })


@threat_bp.route("/email/scan", methods=["POST"])
@jwt_required()
def scan_email_text():
    """Scan email text content for phishing, spam, and social engineering threats."""
    if not request.is_json:
        return api_error("Missing JSON in request", code=400)
    
    subject = request.json.get("subject", "").strip()
    body = request.json.get("body", "").strip()
    sender = request.json.get("sender", "").strip()
    urls = request.json.get("urls", [])
    
    if not body and not subject:
        return api_error("Email subject or body is required", code=400)
    
    try:
        import asyncio
        from email_threat.core import ThreatConfig
        from email_threat.threat_models import EmailMessage
        from email_threat.orchestrator import ThreatOrchestrator
        import logging
        
        config = ThreatConfig()
        logger = logging.getLogger("email_threat")
        orchestrator = ThreatOrchestrator(config, logger)
        
        # Build an EmailMessage from the request data
        email_msg = EmailMessage(
            message_id="api-scan",
            subject=subject,
            sender=sender,
            sender_name=sender.split("<")[0].strip() if sender else "",
            recipients=[],
            date=None,
            body_text=body,
            body_html="",
            headers={},
            attachments=[],
            urls=urls if isinstance(urls, list) else [],
            provider="api"
        )
        
        # Run the analysis
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(orchestrator.analyze_single(email_msg))
        finally:
            loop.close()
        
        # Build response
        indicators = []
        for ind in result.indicators:
            indicators.append({
                "type": ind.threat_type.value,
                "score": round(ind.score, 4),
                "description": ind.description,
                "source": ind.source,
            })
        
        return api_response(data={
            "overall_score": round(result.overall_score, 4),
            "severity": result.severity.value,
            "primary_threat": result.primary_threat.value,
            "is_threat": result.is_threat,
            "indicators": indicators,
            "threat_types": [t.value for t in result.threat_types],
        })
        
    except ImportError as e:
        return api_error(f"Email threat detection module not available: {str(e)}", code=500)
    except Exception as e:
        return api_error(f"Scan failed: {str(e)}", code=500)

