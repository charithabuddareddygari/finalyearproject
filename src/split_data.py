import pandas as pd
from sklearn.model_selection import train_test_split

# Load processed dataset
df = pd.read_csv("data/processed/email_dataset.csv")

# Input and target
X = df["email_text"]
y = df["label"]

# Split into training and testing data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("✅ Dataset split completed!")

print("\nTraining emails:", len(X_train))
print("Testing emails:", len(X_test))

print("\nTraining label distribution:")
print(y_train.value_counts())

print("\nTesting label distribution:")
print(y_test.value_counts())