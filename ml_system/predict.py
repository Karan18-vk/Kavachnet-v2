import joblib
import os
from utils.feature_extractor import URLFeatureExtractor
import pandas as pd

class PhishingPredictor:
    """
    Production-ready wrapper for Phishing URL Prediction.
    """
    def __init__(self, model_path='model/phishing_model.pkl'):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at {model_path}. Please run train.py first.")
        self.model = joblib.load(model_path)
        self.extractor = URLFeatureExtractor()

    def predict(self, url):
        # 1. Extract features
        features = self.extractor.extract(url)
        
        # 2. Convert to DataFrame (matching training format)
        X = pd.DataFrame([features])
        
        # 3. Predict
        prediction = self.model.predict(X)[0]
        probability = self.model.predict_proba(X)[0][1] # Probability of malicious
        
        return {
            "url": url,
            "prediction": "Malicious" if prediction == 1 else "Safe",
            "malicious_probability": round(float(probability), 4),
            "score": int(probability * 100)
        }
