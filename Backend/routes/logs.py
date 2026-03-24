import json, datetime
from flask import Blueprint, request, jsonify, Response
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.user import AuditLog, User
from database import db

logs_bp = Blueprint("logs", __name__)

@logs_bp.route("/audit", methods=["GET"])
@jwt_required()
def get_logs():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user: return jsonify({"error": "User context not found"}), 401
    inst_id  = user.institution_id
    page     = request.args.get("page",1,type=int)
    severity = request.args.get("severity")
    action   = request.args.get("action")
    q = AuditLog.query.filter_by(institution_id=inst_id)
    if severity: q = q.filter_by(severity=severity)
    if action:   q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    logs = q.order_by(AuditLog.timestamp.desc()).paginate(page=page,per_page=50,error_out=False)
    return jsonify({"logs":[l.to_dict() for l in logs.items],"total":logs.total,"page":page}), 200

@logs_bp.route("/audit/export", methods=["GET"])
@jwt_required()
def export_logs():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user: return jsonify({"error": "User context not found"}), 401
    inst_id = user.institution_id
    logs    = AuditLog.query.filter_by(institution_id=inst_id).order_by(AuditLog.timestamp.desc()).all()
    data    = {"exported_at":datetime.datetime.utcnow().isoformat(),
               "total":len(logs),"logs":[l.to_dict() for l in logs]}
    return Response(json.dumps(data,indent=2), mimetype="application/json",
        headers={"Content-Disposition":f"attachment; filename=kavachnet-audit-{datetime.date.today()}.json"})

@logs_bp.route("/audit", methods=["POST"])
@jwt_required()
def add_log():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user: return jsonify({"error": "User context not found"}), 401
    data = request.get_json() or {}
    log  = AuditLog(user_id=user.id, institution_id=user.institution_id,
        action=data.get("action","MANUAL"), resource=data.get("resource",""),
        detail=data.get("detail",""), ip_address=request.remote_addr,
        severity=data.get("severity","info"))
    db.session.add(log); db.session.commit()
    return jsonify({"log":log.to_dict()}), 201

@logs_bp.route("/audit/stats", methods=["GET"])
@jwt_required()
def log_stats():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user: return jsonify({"error": "User context not found"}), 401
    inst_id  = user.institution_id
    today    = datetime.datetime.utcnow().replace(hour=0,minute=0,second=0)
    return jsonify({"total":AuditLog.query.filter_by(institution_id=inst_id).count(),
        "warnings":AuditLog.query.filter_by(institution_id=inst_id,severity="warning").count(),
        "critical":AuditLog.query.filter_by(institution_id=inst_id,severity="critical").count(),
        "today":AuditLog.query.filter(AuditLog.institution_id==inst_id,
                                      AuditLog.timestamp>=today).count()}), 200
