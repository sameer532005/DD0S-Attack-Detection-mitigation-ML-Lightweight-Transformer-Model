import pandas as pd
import numpy as np
import joblib
from tabpfn import TabPFNClassifier
from sklearn.model_selection import train_test_split

FEATURES = [
    "src_ip_int", "dst_ip_int", "protocol",
    "packet_count", "byte_count", "duration_sec", "duration_nsec",
    "packet_rate", "byte_rate",
]

# Load dataset
df = pd.read_csv("flow_stats.csv")

# Clean data
df.replace([np.inf, -np.inf], 0, inplace=True)
df.fillna(0, inplace=True)

# Ensure numeric
for col in FEATURES:
    df[col] = pd.to_numeric(df[col], errors="coerce")

df["label"] = pd.to_numeric(df["label"], errors="coerce")

df = df.dropna()

# Split
X = df[FEATURES]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Limit dataset (important for TabPFN)
if len(X_train) > 10000:
    X_train = X_train.sample(10000)
    y_train = y_train.loc[X_train.index]

# Train model
model = TabPFNClassifier(device="cpu")

print("Training TabPFN...")
model.fit(X_train.values, y_train.values)

# Accuracy
acc = model.score(X_test.values, y_test.values)
print("Accuracy:", acc)

# Save model
joblib.dump(model, "tabpfn_model.joblib")
print("✅ Model saved as tabpfn_model.joblib")
