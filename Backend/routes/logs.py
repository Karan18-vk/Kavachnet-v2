import json, datetime
from flask import Blueprint, request, jsonify, Response
from models.user import AuditLog
from utils.jwt_helper import token_required
from database import db

logs_bp = Blueprint("logs", __name__)

@logs_bp.route("/audit", methods=["GET"])
@token_required
def get_logs():
    inst_id  = request.current_user.institution_id
    page     = request.args.get("page",1,type=int)
    severity = request.args.get("severity")
    action   = request.args.get("action")
    q = AuditLog.query.filter_by(institution_id=inst_id)
    if severity: q = q.filter_by(severity=severity)
    if action:   q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    logs = q.order_by(AuditLog.timestamp.desc()).paginate(page=page,per_page=50,error_out=False)
    return jsonify({"logs":[l.to_dict() for l in logs.items],"total":logs.total,"page":page}), 200

@logs_bp.route("/audit/export", methods=["GET"])
@token_required
def export_logs():
    inst_id = request.current_user.institution_id
    logs    = AuditLog.query.filter_by(institution_id=inst_id).order_by(AuditLog.timestamp.desc()).all()
    data    = {"exported_at":datetime.datetime.utcnow().isoformat(),
               "total":len(logs),"logs":[l.to_dict() for l in logs]}
    return Response(json.dumps(data,indent=2), mimetype="application/json",
        headers={"Content-Disposition":f"attachment; filename=kavachnet-audit-{datetime.date.today()}.json"})

@logs_bp.route("/audit", methods=["POST"])
@token_required
def add_log():
    data = request.get_json() or {}
    log  = AuditLog(user_id=request.current_user.id, institution_id=request.current_user.institution_id,
        action=data.get("action","MANUAL"), resource=data.get("resource",""),
        detail=data.get("detail",""), ip_address=request.remote_addr,
        severity=data.get("severity","info"))
    db.session.add(log); db.session.commit()
    return jsonify({"log":log.to_dict()}), 201

@logs_bp.route("/audit/stats", methods=["GET"])
@token_required
def log_stats():
    inst_id  = request.current_user.institution_id
    today    = datetime.datetime.utcnow().replace(hour=0,minute=0,second=0)
    return jsonify({"total":AuditLog.query.filter_by(institution_id=inst_id).count(),
        "warnings":AuditLog.query.filter_by(institution_id=inst_id,severity="warning").count(),
        "critical":AuditLog.query.filter_by(institution_id=inst_id,severity="critical").count(),
        "today":AuditLog.query.filter(AuditLog.institution_id==inst_id,
                                      AuditLog.timestamp>=today).count()}), 200
