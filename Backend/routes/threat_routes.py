from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from services.threat_service import ThreatService
from utils.response import api_response, api_error
from utils.validation import validate_payload, sanitize_input
from utils.security import authenticated_required, admin_or_above_required

threat_bp = Blueprint('threat', __name__)
threat_service = ThreatService()

@threat_bp.route("/scan-url", methods=["POST"])
@jwt_required()
@validate_payload({"url": str})
def scan_url():
    url = sanitize_input(request.json.get("url"))
    # Integration logic for URL detector
    try:
        from email_threat.core import ThreatConfig
        from email_threat.link_detector import MaliciousLinkDetector
        detector = MaliciousLinkDetector(ThreatConfig())
        heuristic = detector._url_heuristics(url)
        risk_score = int(heuristic["score"] * 100)
        
        verdict = "BLOCK" if risk_score >= 70 else "FLAG" if risk_score >= 40 else "SAFE"
        
        # Log to DB
        threat_service.log_threat(
            threat_type="phishing_url",
            status="blocked" if verdict == "BLOCK" else "flagged",
            risk_level="high" if risk_score >= 70 else "medium" if risk_score >= 40 else "low",
            user_email=get_jwt_identity(),
            details=f"URL: {url} | Score: {risk_score}"
        )
        
        return api_response(data={
            "url": url,
            "verdict": verdict,
            "risk_score": risk_score,
            "details": heuristic.get("reasons", [])
        })
    except Exception as e:
        return api_error(f"URL scan failed: {str(e)}", code=500)

@threat_bp.route("/scan-email", methods=["POST"])
@jwt_required()
@validate_payload({"body": str})
def scan_email():
    body = sanitize_input(request.json.get("body"))
    subject = sanitize_input(request.json.get("subject", ""))
    
    try:
        import asyncio
        from email_threat.core import ThreatConfig
        from email_threat.threat_models import EmailMessage
        from email_threat.orchestrator import ThreatOrchestrator
        import logging
        
        orchestrator = ThreatOrchestrator(ThreatConfig(), logging.getLogger("email_threat"))
        email_msg = EmailMessage(
            message_id="api-scan", subject=subject, body_text=body, 
            sender="", sender_name="", recipients=[], date=None,
            body_html="", headers={}, attachments=[], urls=[], provider="api"
        )
        
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(orchestrator.analyze_single(email_msg))
        finally:
            loop.close()
            
        verdict = "BLOCK" if result.is_threat and result.severity.value in ["HIGH", "CRITICAL"] else "SAFE"
        
        threat_service.log_threat(
            threat_type="email_content",
            status="blocked" if verdict == "BLOCK" else "flagged" if result.is_threat else "safe",
            risk_level=result.severity.value.lower(),
            user_email=get_jwt_identity(),
            details=f"Primary Threat: {result.primary_threat.value}"
        )
        
        return api_response(data={
            "verdict": verdict,
            "is_threat": result.is_threat,
            "severity": result.severity.value,
            "primary_threat": result.primary_threat.value,
            "score": round(result.overall_score, 4)
        })
    except Exception as e:
        return api_error(f"Email scan failed: {str(e)}", code=500)

@threat_bp.route("/dashboard-stats", methods=["GET"])
@jwt_required()
def dashboard_stats():
    claims = get_jwt()
    inst_id = claims.get("institution_id")
    stats = threat_service.get_dashboard_stats(inst_id)
    return api_response(data=stats)

@threat_bp.route("/threat-logs", methods=["GET"])
@jwt_required()
def threat_logs():
    claims = get_jwt()
    inst_id = claims.get("institution_id")
    logs = threat_service.get_threat_logs(inst_id)
    return api_response(data=logs)
