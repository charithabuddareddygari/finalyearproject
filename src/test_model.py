import joblib

# Load trained model
model = joblib.load("models/phishing_email_model.pkl")

print("\n========== AI PHISHING EMAIL DETECTOR ==========")

# Get email from user
email = input("\nPaste your email here:\n\n")

# Prediction
prediction = model.predict([email])[0]

# Probability
probability = model.predict_proba([email])[0]

phishing_probability = probability[1] * 100
legitimate_probability = probability[0] * 100

print("\n==============================================")

if prediction == 1:
    print("🚨 RESULT: PHISHING EMAIL")
else:
    print("✅ RESULT: LEGITIMATE EMAIL")

print(f"Phishing Probability: {phishing_probability:.2f}%")
print(f"Legitimate Probability: {legitimate_probability:.2f}%")

print("==============================================")