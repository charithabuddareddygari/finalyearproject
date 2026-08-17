import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report


# Load processed dataset
df = pd.read_csv("data/processed/email_dataset.csv")

# Input and target
X = df["email_text"]
y = df["label"]


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# Create ML pipeline
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            max_features=50000
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000
        )
    )
])


print("🚀 Training model...")

# Train model
model.fit(X_train, y_train)

print("✅ Model training completed!")


# Predict test data
y_pred = model.predict(X_test)


# Accuracy
accuracy = accuracy_score(y_test, y_pred)

print("\nModel Accuracy:")
print(f"{accuracy * 100:.2f}%")


# Detailed report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))


# Create models folder if needed
import os
os.makedirs("models", exist_ok=True)


# Save trained model
joblib.dump(model, "models/phishing_email_model.pkl")

print("\n✅ Model saved successfully!")
print("Location: models/phishing_email_model.pkl")