import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from utils.feature_extractor import URLFeatureExtractor

def create_synthetic_data(filepath):
    """Generates a synthetic dataset for demonstration if none exists."""
    safe_urls = [
        "google.com", "facebook.com", "wikipedia.org", "github.com", "microsoft.com",
        "https://www.google.com/search?q=cybersecurity", "https://github.com/Karan18-vk",
        "https://linkedin.com/feed/", "https://stackoverflow.com/questions", "https://amazon.com/gp/cart",
        "https://reddit.com/r/security", "https://netflix.com/browse", "https://spotify.com",
        "https://apple.com/iphone", "https://dropbox.com/home", "https://zoom.us/join"
    ]
    phishing_urls = [
        "http://secure-login-wellsfargo.com", "http://paypal-security-update.xyz",
        "http://verify-bank-account.info", "http://amazon-gift-card.top", "http://netflix-suspended.ru",
        "http://urgent-alert-paypal.tk", "http://apple-id-verify.cf", "http://signin-google-account.ml",
        "http://account-update-banking.gq", "http://secure-paypal-login.win", "http://login-microsoft-office.xyz",
        "http://banking-verify-urgent.pw", "http://prize-winner-claim.online", "http://crypto-wallet-recover.site"
    ]
    
    data = []
    for url in safe_urls:
        data.append({"url": url, "label": 0})
    for url in phishing_urls:
        data.append({"url": url, "label": 1})
        
    df = pd.DataFrame(data)
    df.to_csv(filepath, index=False)
    print(f"Synthetic dataset created at {filepath}")

def train_model():
    data_path = 'data/phishing_dataset.csv'
    if not os.path.exists(data_path):
        create_synthetic_data(data_path)
    
    # 1. Load and Clean
    df = pd.read_csv(data_path)
    df.dropna(inplace=True)
    df.drop_duplicates(inplace=True)
    
    print(f"Dataset Size: {len(df)} samples")
    print(f"Class Distribution:\n{df['label'].value_counts()}")

    # 2. Feature Engineering
    extractor = URLFeatureExtractor()
    features_list = []
    for url in df['url']:
        features_list.append(extractor.extract(url))
    
    X = pd.DataFrame(features_list)
    y = df['label']

    # 3. Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 4. Train Random Forest (Primary)
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)
    
    # 5. Train Logistic Regression (Comparison)
    lr_model = LogisticRegression(max_iter=1000)
    lr_model.fit(X_train, y_train)

    # 6. Evaluate
    def evaluate(name, model, X_t, y_t):
        preds = model.predict(X_t)
        print(f"\n--- {name} Evaluation ---")
        print(f"Accuracy:  {accuracy_score(y_t, preds):.4f}")
        print(f"Precision: {precision_score(y_t, preds):.4f}")
        print(f"Recall:    {recall_score(y_t, preds):.4f}")
        print(f"F1-Score:  {f1_score(y_t, preds):.4f}")

    evaluate("Random Forest", rf_model, X_test, y_test)
    evaluate("Logistic Regression", lr_model, X_test, y_test)

    # 7. Save Model
    if not os.path.exists('model'):
        os.makedirs('model')
    
    joblib.dump(rf_model, 'model/phishing_model.pkl')
    print("\nModel saved to model/phishing_model.pkl")

if __name__ == "__main__":
    train_model()
