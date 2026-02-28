# Backend/routes/threat_routes.py

from flask import Blueprint, request
from flask_jwt_extended import jwt_required
from services.threat_service import ThreatService
from models.db import Database
from utils.response import api_response, api_error

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
    result = threat_service.check_brute_force(username)
    return api_response(data=result)
