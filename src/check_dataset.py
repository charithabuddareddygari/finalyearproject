import pandas as pd
from pathlib import Path

# Find CSV files inside data/raw
raw_folder = Path("data/raw")
csv_files = list(raw_folder.glob("*.csv"))

if not csv_files:
    print("❌ No CSV file found inside data/raw")
    exit()

# Use the first CSV file found
file_path = csv_files[0]

print("Dataset found:", file_path)

# Read dataset
df = pd.read_csv(file_path)

print("\nDataset shape:")
print(df.shape)

print("\nColumn names:")
print(df.columns.tolist())

print("\nFirst 5 rows:")
print(df.head())

print("\nMissing values:")
print(df.isnull().sum())

print("\nLabel distribution:")
if "label" in df.columns:
    print(df["label"].value_counts())
else:
    print("No column named 'label' found.")