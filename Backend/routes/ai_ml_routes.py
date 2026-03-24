from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import joblib
import os
import pandas as pd
import re
from utils.feature_extractor import URLFeatureExtractor
from utils.response import api_response, api_error
from models.user import User, ScanResult, Institution
from database import db

ai_ml_bp = Blueprint('ai_ml', __name__)

# Load Model
MODEL_PATH = os.path.join(os.path.dirname(__file__), '../model/phishing_model.pkl')
try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
    else:
        model = None
except Exception:
    model = None

extractor = URLFeatureExtractor()

def get_risk_level(prob):
    if prob > 0.8: return "CRITICAL"
    if prob > 0.6: return "HIGH"
    if prob > 0.4: return "MEDIUM"
    if prob > 0.2: return "LOW"
    return "NONE"

def get_reasons(features, prediction):
    reasons = []
    if prediction == 1:
        if features.get('is_https') == 0:
            reasons.append("Connection is not secure (HTTP)")
        if features.get('count_dots', 0) > 3:
            reasons.append("Suspiciously high number of subdomains")
        if features.get('count_keywords', 0) > 0:
            reasons.append("Contains sensitive keywords (login/verify/bank)")
        if features.get('hostname_length', 0) > 30:
            reasons.append("Unusually long domain name")
        if features.get('is_ip') == 1:
            reasons.append("Uses raw IP address instead of domain name")
    else:
        reasons.append("URL structure matches known safe patterns")
    
    return reasons if reasons else ["No immediate structural threats detected"]

@ai_ml_bp.route("/predict-url", methods=["POST"])
@jwt_required(optional=True)
def predict_url():
    if model is None:
        return api_error("AI Model not initialized on server", code=500)

    data = request.json
    url = data.get('url')
    if not url:
        return api_error("URL is required")

    try:
        # 1. Feature Extraction
        features = extractor.extract(url)
        X = pd.DataFrame([features])
        
        # 2. Prediction
        prediction = int(model.predict(X)[0])
        prob = float(model.predict_proba(X)[0][1])
        
        # 3. Enrichment
        verdict = "Malicious" if prediction == 1 else "Safe"
        risk = get_risk_level(prob)
        reasons = get_reasons(features, prediction)
        
        # 4. DB Persistence
        email = get_jwt_identity()
        user = User.query.filter_by(email=email).first() if email else None
        
        scan = ScanResult(
            input_data=url,
            scan_type="url",
            verdict=verdict,
            confidence=round(prob * 100, 2),
            details=", ".join(reasons),
            scanned_by=user.email if user else "anonymous",
            institution_id=user.institution_id if user else None
        )
        db.session.add(scan)
        db.session.commit()
        
        return api_response(data={
            "url": url,
            "verdict": verdict,
            "confidence": round(prob * 100, 2),
            "risk_level": risk,
            "reasons": reasons,
            "features_debug": features
        })
    except Exception as e:
        db.session.rollback()
        return api_error(f"Prediction failed: {str(e)}", code=500)

@ai_ml_bp.route("/predict-content", methods=["POST"])
@jwt_required(optional=True)
def predict_content():
    if model is None:
        return api_error("AI Model not initialized on server", code=500)

    data = request.json
    content = data.get('content')
    if not content:
        return api_error("Content text is required")

    try:
        # Extract URLs from content
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
        
        results = []
        highest_prob = 0.0
        overall_verdict = "Safe"
        
        if not urls:
            return api_response(message="No URLs found in content. Text-only analysis reports 'Safe'.", data={
                "verdict": "Safe",
                "confidence": 10.0,
                "risk_level": "NONE",
                "reasons": ["No malicious links detected in text"]
            })

        for url in urls:
            features = extractor.extract(url)
            X = pd.DataFrame([features])
            prob = float(model.predict_proba(X)[0][1])
            if prob > highest_prob:
                highest_prob = prob
                overall_verdict = "Malicious" if prob > 0.5 else "Safe"
        
        risk = get_risk_level(highest_prob)
        
        # Persistence
        email = get_jwt_identity()
        user = User.query.filter_by(email=email).first() if email else None
        
        scan = ScanResult(
            input_data=content[:500] + "..." if len(content) > 500 else content,
            scan_type="content",
            verdict=overall_verdict,
            confidence=round(highest_prob * 100, 2),
            details=f"Scanned {len(urls)} links within content",
            scanned_by=user.email if user else "anonymous",
            institution_id=user.institution_id if user else None
        )
        db.session.add(scan)
        db.session.commit()
        
        return api_response(data={
            "links_count": len(urls),
            "verdict": overall_verdict,
            "confidence": round(highest_prob * 100, 2),
            "risk_level": risk,
            "reasons": [f"Detected {len(urls)} URLs in content. Analysis identifies threats based on link structure."]
        })
    except Exception as e:
        db.session.rollback()
        return api_error(f"Content analysis failed: {str(e)}", code=500)

@ai_ml_bp.route("/history", methods=["GET"])
@jwt_required()
def get_history():
    email = get_jwt_identity()
    user = User.query.filter_by(email=email).first()
    if not user: return api_error("User not found", code=404)
    
    query = ScanResult.query
    if user.role != "superadmin":
        query = query.filter_by(institution_id=user.institution_id)
        
    scans = query.order_by(ScanResult.created_at.desc()).limit(50).all()
    return api_response(data=[s.to_dict() for s in scans])
