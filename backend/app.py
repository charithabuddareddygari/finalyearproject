from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# =========================================================
# LOAD ML MODEL
# =========================================================

model = joblib.load("models/phishing_email_model.pkl")


# =========================================================
# SENDER ANALYSIS
# =========================================================

def analyze_sender(sender):

    reasons = []

    if not sender:
        return reasons

    sender = sender.lower().strip()

    if "@" in sender:
        domain = sender.split("@")[-1]
    else:
        domain = ""

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

    if any(word in domain for word in suspicious_domain_words):

        reasons.append(
            "Sender domain contains suspicious security-related wording"
        )

    # Example: paypa1 instead of paypal
    if re.search(r"[a-z]\d|\d[a-z]", domain):

        reasons.append(
            "Sender domain contains unusual numbers or character substitutions"
        )

    suspicious_brands = [
        "paypal",
        "microsoft",
        "apple",
        "amazon",
        "google",
        "bank"
    ]

    legitimate_domains = [
        "paypal.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "google.com"
    ]

    for brand in suspicious_brands:

        if brand in domain:

            if not any(
                domain.endswith(d)
                for d in legitimate_domains
            ):

                reasons.append(
                    f"Sender domain may be impersonating {brand}"
                )

            break

    return reasons


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_urls(email):

    reasons = []

    urls = re.findall(
        r"https?://[^\s<>\"]+",
        email
    )

    for url in urls:

        url = url.rstrip(".,!?;:)")

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        # HTTP instead of HTTPS
        if parsed.scheme == "http":

            reasons.append(
                "URL uses HTTP instead of secure HTTPS"
            )

        # IP address
        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        if re.match(ip_pattern, domain):

            reasons.append(
                "URL uses an IP address instead of a normal domain"
            )

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

        # Long URL
        if len(url) > 100:

            reasons.append(
                "URL is unusually long"
            )

        # @ symbol
        if "@" in url:

            reasons.append(
                "URL contains an unusual @ symbol"
            )

        # Multiple hyphens
        if domain.count("-") >= 2:

            reasons.append(
                "URL domain contains multiple hyphens"
            )

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

                if not any(
                    domain.endswith(d)
                    for d in legitimate_domains
                ):

                    reasons.append(
                        f"URL domain may be impersonating {brand}"
                    )

                break

    return urls, list(dict.fromkeys(reasons))


# =========================================================
# SUBJECT ANALYSIS
# =========================================================

def analyze_subject(subject):

    reasons = []

    if not subject:
        return reasons

    subject = subject.lower().strip()

    # Urgent words in subject
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

    # Account-related words
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

    # Financial words
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

    # Credential words
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

    # Too many exclamation marks
    if subject.count("!") >= 2:

        reasons.append(
            "Subject contains excessive exclamation marks"
        )

    return list(dict.fromkeys(reasons))


# =========================================================
# RISK ENGINE
# =========================================================

def calculate_risk(
    ml_probability,
    url_reasons,
    sender_reasons,
    text_reasons,
    subject_reasons
):

    # Start with ML probability
    risk_score = ml_probability

    # URL risk
    url_points = min(
        len(url_reasons) * 4,
        15
    )

    # Sender risk
    sender_points = min(
        len(sender_reasons) * 5,
        15
    )

    # Email text risk
    text_points = min(
        len(text_reasons) * 3,
        15
    )

    # Subject risk
    subject_points = min(
        len(subject_reasons) * 4,
        12
    )

    # Combine all signals
    risk_score = (
        risk_score * 0.65
        + url_points
        + sender_points
        + text_points
        + subject_points
    )

    # Keep score between 0 and 100
    risk_score = max(
        0,
        min(100, risk_score)
    )

    # Risk level
    if risk_score >= 80:

        risk_level = "CRITICAL"

    elif risk_score >= 60:

        risk_level = "HIGH"

    elif risk_score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    return round(risk_score, 2), risk_level


# =========================================================
# EMAIL ANALYSIS
# =========================================================

def analyze_email(
    email,
    sender="",
    subject=""
):

    # =====================================================
    # MACHINE LEARNING
    # =====================================================

    prediction = model.predict([email])[0]

    probabilities = model.predict_proba([email])[0]

    ml_phishing_probability = probabilities[1] * 100

    legitimate_probability = probabilities[0] * 100


    # =====================================================
    # TEXT
    # =====================================================

    text = email.lower()


    # =====================================================
    # URL ANALYSIS
    # =====================================================

    urls, url_reasons = analyze_urls(email)


    # =====================================================
    # TEXT ANALYSIS
    # =====================================================

    text_reasons = []


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

        text_reasons.append(
            "Urgent or threatening language detected"
        )


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

        text_reasons.append(
            "Request for login credentials detected"
        )


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

        text_reasons.append(
            "Request for financial information detected"
        )


    # =====================================================
    # SENDER ANALYSIS
    # =====================================================

    sender_reasons = analyze_sender(sender)


    # =====================================================
    # SUBJECT ANALYSIS
    # =====================================================

    subject_reasons = analyze_subject(subject)


    # =====================================================
    # COMBINE REASONS
    # =====================================================

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


    # =====================================================
    # RISK ENGINE
    # =====================================================

    risk_score, risk_level = calculate_risk(

        ml_phishing_probability,

        url_reasons,

        sender_reasons,

        text_reasons,

        subject_reasons
    )


    # =====================================================
    # FINAL PREDICTION
    # =====================================================

    if risk_score >= 50:

        final_prediction = 1

    else:

        final_prediction = 0


    # =====================================================
    # RETURN RESULT
    # =====================================================

    return {

        "prediction": int(final_prediction),

        "ml_prediction": int(prediction),

        "ml_phishing_probability": round(
            ml_phishing_probability,
            2
        ),

        "phishing_probability": risk_score,

        "legitimate_probability": round(
            100 - risk_score,
            2
        ),

        "risk_score": risk_score,

        "risk_level": risk_level,

        "reasons": reasons,

        "sender": sender,

        "subject": subject,

        "urls": urls

    }


# =========================================================
# ANALYZE API
# =========================================================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    data = request.get_json()

    if not data:

        return jsonify({
            "error": "No data received"
        }), 400


    email = data.get(
        "email",
        ""
    )

    sender = data.get(
        "sender",
        ""
    )

    subject = data.get(
        "subject",
        ""
    )


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
        "AI Phishing Email Detection API is running"

    })


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )