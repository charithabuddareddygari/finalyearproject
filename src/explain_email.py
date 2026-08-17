import re
import joblib

# Load trained model
model = joblib.load("models/phishing_email_model.pkl")


def analyze_email(email):
    # ML prediction
    prediction = model.predict([email])[0]
    probabilities = model.predict_proba([email])[0]

    phishing_probability = probabilities[1] * 100
    legitimate_probability = probabilities[0] * 100

    # Convert email to lowercase for checking
    text = email.lower()

    reasons = []

    # 1. Suspicious URL
    url_pattern = r"https?://[^\s]+"
    urls = re.findall(url_pattern, email)

    if urls:
        reasons.append("Suspicious URL detected")

    # 2. Urgent language
    urgent_words = [
        "urgent",
        "immediately",
        "within 24 hours",
        "act now",
        "verify now",
        "account suspended",
        "account will be closed"
    ]

    if any(word in text for word in urgent_words):
        reasons.append("Urgent or threatening language detected")

    # 3. Password / credential request
    credential_words = [
        "password",
        "username",
        "login",
        "verify your account",
        "credentials"
    ]

    if any(word in text for word in credential_words):
        reasons.append("Request for login credentials detected")

    # 4. Financial information request
    financial_words = [
        "card details",
        "credit card",
        "debit card",
        "bank account",
        "account number",
        "cvv",
        "payment"
    ]

    if any(word in text for word in financial_words):
        reasons.append("Request for financial information detected")

    return (
        prediction,
        phishing_probability,
        legitimate_probability,
        reasons
    )


# Test email
email = input("\nPaste your email here:\n\n")

prediction, phishing_probability, legitimate_probability, reasons = analyze_email(email)

print("\n==============================================")
print("        AI PHISHING EMAIL DETECTOR")
print("==============================================")

if prediction == 1:
    print("🚨 RESULT: PHISHING EMAIL")
else:
    print("✅ RESULT: LEGITIMATE EMAIL")

print(f"\nPhishing Probability: {phishing_probability:.2f}%")
print(f"Legitimate Probability: {legitimate_probability:.2f}%")

print("\n🔍 WHY IS THIS EMAIL SUSPICIOUS?")

if reasons:
    for reason in reasons:
        print(f"✓ {reason}")
else:
    print("✓ No obvious suspicious features detected")

print("==============================================")