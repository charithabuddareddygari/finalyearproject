from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# =========================================================
# LOAD MACHINE LEARNING MODEL
# =========================================================

model = joblib.load("models/phishing_email_model.pkl")


# =========================================================
# SENDER ANALYSIS
# =========================================================

def analyze_sender(sender):

    reasons = []
    score = 0

    if not sender:
        return reasons, score

    sender = sender.lower().strip()

    if "@" not in sender:
        reasons.append("Sender email format appears unusual")
        score += 10
        return reasons, score

    domain = sender.split("@")[-1]

    # Suspicious domain words
    suspicious_domain_words = [
        "security",
        "verify",
        "verification",
        "account",
        "support",
        "login",
        "update",
        "secure",
        "service",
        "alert"
    ]

    found_words = [
        word for word in suspicious_domain_words
        if word in domain
    ]

    if found_words:
        reasons.append(
            "Sender domain contains suspicious security-related wording"
        )
        score += 10

    # Character substitution
    if re.search(r"[a-z]\d|\d[a-z]", domain):

        reasons.append(
            "Sender domain contains unusual numbers or character substitutions"
        )

        score += 15

    # Suspicious brands
    suspicious_brands = [
        "paypal",
        "microsoft",
        "apple",
        "amazon",
        "google",
        "facebook",
        "instagram",
        "bank"
    ]

    legitimate_domains = [
        "paypal.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "google.com",
        "facebook.com",
        "instagram.com"
    ]

    for brand in suspicious_brands:

        if brand in domain:

            if not any(
                domain == legitimate_domain or
                domain.endswith("." + legitimate_domain)
                for legitimate_domain in legitimate_domains
            ):

                reasons.append(
                    f"Sender domain may be impersonating {brand}"
                )

                score += 25

            break

    # Multiple hyphens
    if domain.count("-") >= 2:

        reasons.append(
            "Sender domain contains multiple hyphens"
        )

        score += 8

    return list(dict.fromkeys(reasons)), min(score, 40)


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_urls(email):

    reasons = []
    urls = []
    score = 0

    urls_found = re.findall(
        r"https?://[^\s<>\"]+",
        email
    )

    for url in urls_found:

        url = url.rstrip(".,!?;:)")

        urls.append(url)

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        # HTTP
        if parsed.scheme == "http":

            reasons.append(
                "URL uses HTTP instead of secure HTTPS"
            )

            score += 10

        # IP address
        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        if re.match(ip_pattern, domain):

            reasons.append(
                "URL uses an IP address instead of a normal domain"
            )

            score += 20

        # Suspicious URL words
        suspicious_url_words = [
            "login",
            "verify",
            "verification",
            "account",
            "password",
            "secure",
            "security",
            "update",
            "confirm",
            "signin",
            "authenticate"
        ]

        if any(
            word in url.lower()
            for word in suspicious_url_words
        ):

            reasons.append(
                "URL contains suspicious authentication-related words"
            )

            score += 15

        # Long URL
        if len(url) > 100:

            reasons.append(
                "URL is unusually long"
            )

            score += 8

        # @ symbol
        if "@" in url:

            reasons.append(
                "URL contains an unusual @ symbol"
            )

            score += 20

        # Multiple hyphens
        if domain.count("-") >= 2:

            reasons.append(
                "URL domain contains multiple hyphens"
            )

            score += 8

        # Brand impersonation
        brands = [
            "paypal",
            "microsoft",
            "apple",
            "amazon",
            "google",
            "facebook",
            "instagram"
        ]

        legitimate_domains = [
            "paypal.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
            "google.com",
            "facebook.com",
            "instagram.com"
        ]

        for brand in brands:

            if brand in domain:

                is_legitimate = any(
                    domain == legitimate_domain or
                    domain.endswith("." + legitimate_domain)
                    for legitimate_domain in legitimate_domains
                )

                if not is_legitimate:

                    reasons.append(
                        f"URL domain may be impersonating {brand}"
                    )

                    score += 25

                break

    return (
        urls,
        list(dict.fromkeys(reasons)),
        min(score, 40)
    )


# =========================================================
# SUBJECT ANALYSIS
# =========================================================

def analyze_subject(subject):

    reasons = []
    score = 0

    if not subject:
        return reasons, score

    subject = subject.lower().strip()

    # Urgent words
    urgent_subject_words = [
        "urgent",
        "immediately",
        "action required",
        "act now",
        "important",
        "warning",
        "alert",
        "final notice",
        "last warning"
    ]

    if any(
        word in subject
        for word in urgent_subject_words
    ):

        reasons.append(
            "Subject contains urgent or threatening language"
        )

        score += 15

    # Account security
    account_subject_words = [
        "account suspended",
        "account locked",
        "account disabled",
        "verify account",
        "verify your account",
        "account security"
    ]

    if any(
        word in subject
        for word in account_subject_words
    ):

        reasons.append(
            "Subject creates an account security concern"
        )

        score += 15

    # Financial
    financial_subject_words = [
        "payment",
        "refund",
        "invoice",
        "bank",
        "credit card",
        "debit card",
        "transaction"
    ]

    if any(
        word in subject
        for word in financial_subject_words
    ):

        reasons.append(
            "Subject contains financial-related wording"
        )

        score += 10

    # Credential
    credential_subject_words = [
        "password",
        "login",
        "sign in",
        "credentials",
        "verification"
    ]

    if any(
        word in subject
        for word in credential_subject_words
    ):

        reasons.append(
            "Subject requests or suggests account verification"
        )

        score += 12

    # Excessive exclamation
    if subject.count("!") >= 2:

        reasons.append(
            "Subject contains excessive exclamation marks"
        )

        score += 5

    return (
        list(dict.fromkeys(reasons)),
        min(score, 30)
    )


# =========================================================
# EMAIL TEXT ANALYSIS
# =========================================================

def analyze_text(email):

    reasons = []
    score = 0

    text = email.lower()

    # Urgent language
    urgent_words = [
        "urgent",
        "immediately",
        "within 24 hours",
        "act now",
        "verify now",
        "account suspended",
        "account will be closed",
        "limited time",
        "immediate action"
    ]

    if any(
        word in text
        for word in urgent_words
    ):

        reasons.append(
            "Urgent or threatening language detected"
        )

        score += 15

    # Credential request
    credential_words = [
        "password",
        "username",
        "login",
        "verify your account",
        "credentials",
        "sign in",
        "login details"
    ]

    if any(
        word in text
        for word in credential_words
    ):

        reasons.append(
            "Request for login credentials detected"
        )

        score += 20

    # Financial information
    financial_words = [
        "card details",
        "credit card",
        "debit card",
        "bank account",
        "account number",
        "cvv",
        "payment",
        "billing information"
    ]

    if any(
        word in text
        for word in financial_words
    ):

        reasons.append(
            "Request for financial information detected"
        )

        score += 20

    # Threatening language
    threat_words = [
        "suspended",
        "closed",
        "blocked",
        "terminated",
        "disabled",
        "lose access",
        "permanently"
    ]

    if any(
        word in text
        for word in threat_words
    ):

        reasons.append(
            "Threat of account loss or suspension detected"
        )

        score += 10

    return (
        list(dict.fromkeys(reasons)),
        min(score, 40)
    )


# =========================================================
# RISK ENGINE
# =========================================================

def calculate_risk(
    ml_probability,
    url_score,
    sender_score,
    text_score,
    subject_score
):

    # ML contribution
    risk_score = ml_probability * 0.50

    # Security-analysis contributions
    risk_score += url_score * 0.20
    risk_score += sender_score * 0.15
    risk_score += text_score * 0.10
    risk_score += subject_score * 0.05

    # Strong indicators
    if url_score >= 20:
        risk_score += 10

    if sender_score >= 20:
        risk_score += 10

    if text_score >= 20:
        risk_score += 10

    if subject_score >= 15:
        risk_score += 5

    # Keep between 0 and 100
    risk_score = max(
        0,
        min(100, risk_score)
    )

    risk_score = round(
        risk_score,
        2
    )

    # Threat level
    if risk_score >= 75:

        risk_level = "CRITICAL"

        recommendation = (
            "Do not click links or provide personal information. "
            "Report and delete this email."
        )

    elif risk_score >= 50:

        risk_level = "HIGH"

        recommendation = (
            "Avoid clicking links or providing credentials. "
            "Verify the sender through an official channel."
        )

    elif risk_score >= 25:

        risk_level = "MEDIUM"

        recommendation = (
            "Be cautious. Verify the sender and links "
            "before taking any action."
        )

    else:

        risk_level = "LOW"

        recommendation = (
            "No strong phishing indicators were detected. "
            "Continue normal email security precautions."
        )

    return (
        risk_score,
        risk_level,
        recommendation
    )


# =========================================================
# COMPLETE EMAIL ANALYSIS
# =========================================================

def analyze_email(
    email,
    sender="",
    subject=""
):

    # -----------------------------------------------------
    # MACHINE LEARNING
    # -----------------------------------------------------

    prediction = model.predict([email])[0]

    probabilities = model.predict_proba([email])[0]

    ml_phishing_probability = probabilities[1] * 100

    ml_legitimate_probability = probabilities[0] * 100


    # -----------------------------------------------------
    # URL ANALYSIS
    # -----------------------------------------------------

    urls, url_reasons, url_score = analyze_urls(email)


    # -----------------------------------------------------
    # TEXT ANALYSIS
    # -----------------------------------------------------

    text_reasons, text_score = analyze_text(email)


    # -----------------------------------------------------
    # SENDER ANALYSIS
    # -----------------------------------------------------

    sender_reasons, sender_score = analyze_sender(sender)


    # -----------------------------------------------------
    # SUBJECT ANALYSIS
    # -----------------------------------------------------

    subject_reasons, subject_score = analyze_subject(subject)


    # -----------------------------------------------------
    # COMBINE REASONS
    # -----------------------------------------------------

    reasons = []

    if urls:

        reasons.append(
            f"{len(urls)} URL(s) detected in the email"
        )

    reasons.extend(url_reasons)

    reasons.extend(text_reasons)

    reasons.extend(sender_reasons)

    reasons.extend(subject_reasons)

    reasons = list(
        dict.fromkeys(reasons)
    )


    # -----------------------------------------------------
    # CALCULATE RISK
    # -----------------------------------------------------

    risk_score, risk_level, recommendation = calculate_risk(

        ml_phishing_probability,

        url_score,

        sender_score,

        text_score,

        subject_score
    )


    # -----------------------------------------------------
    # FINAL PREDICTION
    # -----------------------------------------------------

    if risk_score >= 50:

        final_prediction = 1

    else:

        final_prediction = 0


    # -----------------------------------------------------
    # RETURN RESULT
    # -----------------------------------------------------

    return {

        "prediction": int(final_prediction),

        "ml_prediction": int(prediction),

        "ml_phishing_probability": round(
            ml_phishing_probability,
            2
        ),

        "ml_legitimate_probability": round(
            ml_legitimate_probability,
            2
        ),

        "phishing_probability": risk_score,

        "legitimate_probability": round(
            100 - risk_score,
            2
        ),

        "risk_score": risk_score,

        "risk_level": risk_level,

        "recommendation": recommendation,

        "reasons": reasons,

        "sender": sender,

        "subject": subject,

        "urls": urls,

        "analysis": {

            "sender_score": sender_score,

            "url_score": url_score,

            "text_score": text_score,

            "subject_score": subject_score,

            "ml_probability": round(
                ml_phishing_probability,
                2
            )

        }

    }


# =========================================================
# ANALYZE API
# =========================================================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    try:

        data = request.get_json()

        if not data:

            return jsonify({
                "error": "No data received"
            }), 400


        email = data.get(
            "email",
            ""
        ).strip()

        sender = data.get(
            "sender",
            ""
        ).strip()

        subject = data.get(
            "subject",
            ""
        ).strip()


        if not email:

            return jsonify({
                "error": "Email text is required"
            }), 400


        result = analyze_email(
            email,
            sender,
            subject
        )


        return jsonify(result)


    except Exception as error:

        print("ERROR:", error)

        return jsonify({
            "error": str(error)
        }), 500


# =========================================================
# HOME API
# =========================================================

@app.route(
    "/",
    methods=["GET"]
)
def home():

    return jsonify({

        "message":
        "AI Phishing Email Detection API is running",

        "status":
        "online",

        "version":
        "2.0"

    })


# =========================================================
# START SERVER
# =========================================================

import os

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )