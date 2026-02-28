# Backend/utils/response.py

from flask import jsonify

def api_response(status="success", message="", data=None, code=200):
    """
    Standardized API response format for enterprise consistency.
    """
    response = {
        "status": status,
        "message": message,
        "data": data if data is not None else {}
    }
    return jsonify(response), code

def api_error(message="An internal error occurred", data=None, code=400):
    return api_response(status="error", message=message, data=data, code=code)
