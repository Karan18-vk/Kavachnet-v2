from flask import Blueprint, request, send_file
from flask_jwt_extended import jwt_required
from services.incident_service import IncidentService
from utils.response import api_response, api_error
from utils.validation import validate_payload, sanitize_input

incident_bp = Blueprint('incident', __name__)
incident_service = IncidentService()

@incident_bp.route("/", methods=["GET"])
@jwt_required()
def get_incidents():
    result = incident_service.get_incidents_list()
    return api_response(data=result)

@incident_bp.route("/<incident_id>", methods=["GET"])
@jwt_required()
def get_incident(incident_id):
    res, code = incident_service.get_incident(sanitize_input(incident_id))
    if code != 200:
        return api_error(res.get("error", "Not found"), code=code)
    return api_response(data=res)

@incident_bp.route("/<incident_id>", methods=["PATCH"])
@jwt_required()
def update_incident(incident_id):
    if not request.is_json:
        return api_error("Missing JSON in request", code=400)
    status = request.json.get("status")
    if not status:
        return api_error("status field is required", code=400)
    res, code = incident_service.update_status(sanitize_input(incident_id), sanitize_input(status))
    return api_response(message=res.get("message", "Updated")) if code == 200 else api_error(res.get("error", "Failed"), code=code)

@incident_bp.route("/report/pdf", methods=["GET"])
@jwt_required()
def download_report():
    try:
        buffer = incident_service.generate_report()
        return send_file(buffer, as_attachment=True, download_name="kavachnet_report.pdf", mimetype='application/pdf')
    except Exception as e:
        return api_error(f"Failed to generate report: {str(e)}", code=500)
