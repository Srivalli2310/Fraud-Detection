from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re


app = Flask(__name__)
CORS(app)

# Load model and vectorizer
model = joblib.load("internship_scam_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

def clean_text(text):
    text = text.lower()
    text = re.sub(r"http\S+", "", text)
    text = re.sub(r"[^a-z\s]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    text = data.get("text", "")

    text_lower = text.lower()

    # ---------- URL detection ----------
    contains_url = "http://" in text_lower or "https://" in text_lower or "www." in text_lower

    # Suspicious URL patterns
    suspicious_url_keywords = [
        "bit.ly", "tinyurl", "free", "offer", "pay", "verify",
        "login", "secure", "bonus", "reward"
    ]

    trusted_domains = [
        "google.com", "microsoft.com", "amazon.com",
        "linkedin.com", "internshala.com", "unstop.com","devpost.com",
        "naukri.com", "indeed.com", "glassdoor.com","niti.gov.in"
    ]

    url_risky = False

    if contains_url:
        # Check for suspicious words
        for word in suspicious_url_keywords:
            if word in text_lower:
                url_risky = True

        # Check for trusted domains
        is_trusted = any(domain in text_lower for domain in trusted_domains)

        if not is_trusted:
            url_risky = True

    # ---------- ML prediction ----------
    cleaned = clean_text(text)
    X = vectorizer.transform([cleaned])
    prediction = model.predict(X)[0]

    # ---------- FINAL DECISION ----------
    if (
        prediction == "Scam"
        or url_risky
        or "pay" in text_lower
        or "payment" in text_lower
        or "urgent" in text_lower
        or "fee" in text_lower
    ):
        risk = "HIGH RISK"
    else:
        risk = "SAFE"

    return jsonify({
        "prediction": prediction,
        "risk_level": risk
    })

@app.route("/")
def home():
    return "Internship Fraud Risk API is running"

if __name__ == "__main__":
    app.run(debug=True)