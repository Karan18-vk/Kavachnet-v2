# KavachNet ML Phishing Detection System

A complete, production-ready machine learning system for detecting phishing URLs using structural and semantic features.

## 📁 System Structure
- `/data`: Contains training datasets (CSV)
- `/model`: Contains the saved `phishing_model.pkl`
- `/api`: Contains the Flask API (`app.py`)
- `/utils`: Contains the `feature_extractor.py` logic
- `train.py`: Main script for data cleaning and model training
- `predict.py`: Reusable wrapper for inference in production
- `requirements.txt`: Python dependencies

## 🚀 Step-by-Step Setup

### 1. Install Dependencies
Ensure you have Python 3.8+ installed. Run the following in your terminal:
```bash
cd ml_system
pip install -r requirements.txt
```

### 2. Train the Model
This step will clean the data, generate features, and compare RandomForest vs Logistic Regression. 
It saves the best model to `model/phishing_model.pkl`.
```bash
python train.py
```

### 3. Run the API
Start the Flask server on port 5001 (to avoid conflict with the main KavachNet backend).
```bash
python api/app.py
```

### 4. Test Predictions
You can test the system using `curl` or by sending a POST request to `http://127.0.0.1:5001/predict`.

**Example Request:**
```json
{
  "url": "http://secure-login-wellsfargo.com"
}
```

**Example Response:**
```json
{
  "url": "http://secure-login-wellsfargo.com",
  "prediction": "Malicious",
  "malicious_probability": 0.892,
  "score": 89
}
```

## 🛡 Features Extracted
- URL and Hostname Length
- Count of structural indicators (dots, hyphens, @, etc.)
- HTTPS/SSL presence
- Digit frequency
- Cybersecurity keyword matching (login, verify, bank, etc.)
- Domain IP detection
