import json
from flask import Blueprint, request, jsonify
from models.phishing_detector import analyze_url
from models.email_scanner import scan_email
from models.threat_analyzer import analyze_ip, generate_threat_feed
from models.user import ScanResult, Incident
from utils.jwt_helper import token_required
from database import db

scanner_bp = Blueprint("scanner", __name__)

def _save(scan_type, input_data, result, user):
    db.session.add(ScanResult(scan_type=scan_type, input_data=input_data[:500],
        verdict=result.verdict, confidence=result.confidence,
        details=json.dumps(result.to_dict()), scanned_by=user.id,
        institution_id=user.institution_id))
    if result.verdict == "malicious":
        db.session.add(Incident(institution_id=user.institution_id,
            title=f"Malicious {scan_type.upper()} detected",
            description=f"Scanner flagged: {input_data[:200]}",
            threat_type="phishing" if scan_type=="url" else "malware",
            severity="high", confidence=result.confidence, target=input_data[:200]))
    db.session.commit()

@scanner_bp.route("/url", methods=["POST"])
@token_required
def scan_url():
    data = request.get_json() or {}
    url = (data.get("url") or data.get("target") or data.get("link") or data.get("query") or "").strip()
    if not url: return jsonify({"error":"URL required"}), 400
    result = analyze_url(url); _save("url", url, result, request.current_user)
    return jsonify({"result":result.to_dict()}), 200

@scanner_bp.route("/email", methods=["POST"])
@token_required
def scan_email_route():
    data = request.get_json() or {}
    subject, sender, body = data.get("subject",""), data.get("sender",""), data.get("body","")
    if not body and not subject: return jsonify({"error":"Subject or body required"}), 400
    result = scan_email(subject, sender, body, data.get("headers",""), data.get("attachments",[]))
    _save("email", f"Subject: {subject[:100]}", result, request.current_user)
    return jsonify({"result":result.to_dict()}), 200

@scanner_bp.route("/ip", methods=["POST"])
@token_required
def scan_ip():
    data = request.get_json() or {}
    ip   = data.get("ip","").strip()
    if not ip: return jsonify({"error":"IP required"}), 400
    return jsonify({"result":analyze_ip(ip).to_dict()}), 200

@scanner_bp.route("/threat-feed", methods=["GET"])
@token_required
def threat_feed():
    feed = generate_threat_feed(request.current_user.institution_id)
    return jsonify({"feed":feed,"count":len(feed)}), 200

@scanner_bp.route("/history", methods=["GET"])
@token_required
def scan_history():
    page  = request.args.get("page",1,type=int)
    scans = (ScanResult.query.filter_by(institution_id=request.current_user.institution_id)
             .order_by(ScanResult.created_at.desc()).paginate(page=page,per_page=20,error_out=False))
    return jsonify({"scans":[s.to_dict() for s in scans.items],"total":scans.total,"page":page}), 200

@scanner_bp.route("/url/batch", methods=["POST"])
@token_required
def scan_url_batch():
    data = request.get_json() or {}
    urls = data.get("urls",[])
    if not urls: return jsonify({"error":"Provide a list of URLs"}), 400
    if len(urls) > 50: return jsonify({"error":"Max 50 URLs per batch"}), 400
    results = [analyze_url(str(u).strip()).to_dict() for u in urls]
    mal = sum(1 for r in results if r["verdict"]=="malicious")
    sus = sum(1 for r in results if r["verdict"]=="suspicious")
    return jsonify({"results":results,"summary":{"total":len(results),"malicious":mal,
                    "suspicious":sus,"safe":len(results)-mal-sus}}), 200
