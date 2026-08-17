import pandas as pd
from pathlib import Path

# Dataset location
file_path = Path("data/raw/CEAS_08.csv")

# Load dataset
df = pd.read_csv(file_path)

# Replace missing subjects with empty text
df["subject"] = df["subject"].fillna("")

# Combine subject and body
df["email_text"] = df["subject"] + " " + df["body"]

# Keep only the columns needed for text classification
data = df[["email_text", "label"]].copy()

# Remove empty emails
data = data[data["email_text"].str.strip() != ""]

# Save processed dataset
output_path = Path("data/processed/email_dataset.csv")
data.to_csv(output_path, index=False)

print("✅ Dataset preparation completed!")
print("Total emails:", len(data))
print("Columns:", data.columns.tolist())

print("\nLabel distribution:")
print(data["label"].value_counts())

print("\nSaved to:")
print(output_path)