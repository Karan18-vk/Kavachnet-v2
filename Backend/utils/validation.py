# Backend/utils/validation.py

import html
import re
from functools import wraps
from flask import request
from utils.response import api_error

def sanitize_input(value):
    """
    Sanitizes string input to prevent XSS and injection.
    """
    if not isinstance(value, str):
        return value
    # Basic HTML escaping
    clean = html.escape(value)
    # Remove potentially dangerous characters if needed, 
    # but html.escape covers most XSS.
    return clean

def validate_payload(schema):
    """
    Decorator for validating JSON payload against a key schema.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return api_error("Missing JSON in request", code=400)
            
            data = request.get_json()
            for key, types in schema.items():
                if key not in data:
                    return api_error(f"Missing required field: {key}", code=400)
                if not isinstance(data[key], types):
                    return api_error(f"Invalid type for {key}. Expected {types}", code=400)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
