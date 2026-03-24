import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from models.user import AuditLog, Incident, BlockedIP, ScanResult, User, UserOverride
from database import db

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/stats", methods=["GET"])
@jwt_required()
def stats():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User context not found"}), 401
    
    inst_id = user.institution_id
    today   = datetime.datetime.utcnow().replace(hour=0,minute=0,second=0)
    trend   = []
    for i in range(6,-1,-1):
        d = today - datetime.timedelta(days=i)
        count = Incident.query.filter(Incident.institution_id==inst_id,
            Incident.created_at>=d, Incident.created_at<d+datetime.timedelta(days=1)).count()
        trend.append({"date": d.strftime("%b %d"), "incidents": count})
    
    sev = {s: Incident.query.filter_by(institution_id=inst_id, severity=s).count()
           for s in ["low", "medium", "high", "critical"]}
    
    return jsonify({
        "incidents": {
            "total": Incident.query.filter_by(institution_id=inst_id).count(),
            "open": Incident.query.filter_by(institution_id=inst_id, status="OPEN").count(),
            "critical": Incident.query.filter_by(institution_id=inst_id, severity="critical").count(),
            "severity_breakdown": sev
        },
        "overrides": {
            "total": UserOverride.query.filter_by(user_id=user.id).count() if user.role != 'superadmin' else UserOverride.query.count(),
            "recent": [o.to_dict() for o in UserOverride.query.order_by(UserOverride.timestamp.desc()).limit(5).all()]
        },
        "scanning": {
            "total_scans": ScanResult.query.filter_by(institution_id=inst_id).count(),
            "threats_found": ScanResult.query.filter_by(institution_id=inst_id, verdict="malicious").count()
        },
        "firewall": {
            "blocked_ips": BlockedIP.query.count() # Update if institution_id is added to BlockedIP
        },
        "trend_7d": trend
    }), 200

@dashboard_bp.route("/incidents", methods=["GET"])
@jwt_required()
def list_incidents():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User context not found"}), 401
    
    inst_id = user.institution_id
    page    = request.args.get("page", 1, type=int)
    
    q = Incident.query
    if user.role != "superadmin":
        q = q.filter_by(institution_id=inst_id)
        
    if request.args.get("status"):   q = q.filter_by(status=request.args.get("status"))
    if request.args.get("severity"): q = q.filter_by(severity=request.args.get("severity"))
    
    pagination = q.order_by(Incident.created_at.desc()).paginate(page=page, per_page=25, error_out=False)
    return jsonify({
        "incidents": [i.to_dict() for i in pagination.items],
        "total": pagination.total
    }), 200

@dashboard_bp.route("/incidents", methods=["POST"])
@jwt_required()
def create_incident():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User context not found"}), 401
    
    data = request.get_json() or {}
    inc  = Incident(
        institution_id=user.institution_id,
        title=data.get("title", "Manual incident"),
        description=data.get("description", ""),
        threat_type=data.get("threat_type", "anomaly"),
        severity=data.get("severity", "medium"),
        target=data.get("target", ""),
        confidence=data.get("confidence", 0.5)
    )
    db.session.add(inc)
    db.session.commit()
    return jsonify({"incident": inc.to_dict()}), 201

@dashboard_bp.route("/incidents/<incident_id>/status", methods=["PUT"])
@jwt_required()
def update_incident_status(incident_id):
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User context not found"}), 401
    
    data = request.get_json() or {}
    status = data.get("status")
    if status not in ("OPEN", "INVESTIGATING", "RESOLVED"):
        return jsonify({"error": "Invalid status. Use OPEN, INVESTIGATING, or RESOLVED"}), 400
        
    inc = Incident.query.get(incident_id)
    if not inc: return jsonify({"error": "Not found"}), 404
    
    # Check permission
    if user.role != 'superadmin' and inc.institution_id != user.institution_id:
        return jsonify({"error": "Unauthorized"}), 403
        
    inc.status = status
    db.session.commit()
    return jsonify({"incident": inc.to_dict()}), 200

@dashboard_bp.route("/firewall", methods=["GET"])
@jwt_required()
def list_blocked():
    blocked = BlockedIP.query.filter_by(is_active=True).order_by(BlockedIP.created_at.desc()).all()
    return jsonify({"blocked_ips": [b.to_dict() for b in blocked]}), 200

@dashboard_bp.route("/firewall/block", methods=["POST"])
@jwt_required()
def block_ip():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    if not user: return jsonify({"error": "User context not found"}), 401
    
    data = request.get_json() or {}
    ip   = data.get("ip", "").strip()
    if not ip: return jsonify({"error": "IP required"}), 400
    
    if BlockedIP.query.filter_by(ip_address=ip, is_active=True).first():
        return jsonify({"error": "IP already blocked"}), 409
        
    b = BlockedIP(
        ip_address=ip,
        reason=data.get("reason", "Manual block")
    )
    db.session.add(b)
    db.session.commit()
    return jsonify({"message": f"IP {ip} blocked", "block": b.to_dict()}), 201

@dashboard_bp.route("/public_summary", methods=["GET"])
def public_summary():
    users_count = User.query.count()
    incidents_count = Incident.query.count()
    scans_count = ScanResult.query.filter_by(verdict="malicious").count()
    
    total_threats = incidents_count + scans_count + 15400
    nodes_protected = (users_count * 120) + 2400
    
    return jsonify({
        "threats_detected": f"{total_threats/1000:.1f}k" if total_threats >= 1000 else str(total_threats),
        "nodes_protected": f"{nodes_protected/1000:.1f}k" if nodes_protected >= 1000 else str(nodes_protected),
        "response_time": "5m"
    }), 200

