from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Ensure we can import from the parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from predict import PhishingPredictor

app = Flask(__name__)
CORS(app)

# Initialize Predictor (Lazy or Global)
# We assume the model exists, otherwise this will fail on startup (fail-fast)
try:
    predictor = PhishingPredictor(model_path=os.path.join(os.path.dirname(__file__), '../model/phishing_model.pkl'))
except Exception as e:
    print(f"CRITICAL ERROR: Could not load model: {e}")
    predictor = None

@app.route('/predict', methods=['POST'])
def predict():
    if not predictor:
        return jsonify({"error": "Model not loaded. Please run train.py."}), 500
    
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL required in JSON body"}), 400
    
    url = data['url']
    try:
        result = predictor.predict(url)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "model_ready": predictor is not None}), 200

if __name__ == '__main__':
    # Default port 5001 to avoid conflict with the main KavachNet backend (5000)
    app.run(host='0.0.0.0', port=5001, debug=False)
