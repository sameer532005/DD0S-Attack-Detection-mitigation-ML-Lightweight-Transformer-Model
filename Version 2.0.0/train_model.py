#!/usr/bin/env python3
"""
Train a Random Forest model for the SDN DDoS detection demo.

Typical usage:
    python3 train_model.py --dataset flow_stats.csv --model ddos_random_forest.joblib

For a quick dry run before collecting real traffic:
    python3 train_model.py --generate-sample --dataset sample_flow_stats.csv
"""

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split


FEATURES = [
    "src_ip_int", "dst_ip_int", "protocol",
    "packet_count", "byte_count", "duration_sec", "duration_nsec",
    "packet_rate", "byte_rate",
]


def generate_sample_dataset(path):
    rng = np.random.default_rng(seed=42)
    rows = []
    for _ in range(200):
        duration = rng.integers(5, 60)
        packet_rate = rng.uniform(1, 50)
        byte_rate = packet_rate * rng.uniform(64, 700)
        rows.append({
            "src_ip_int": 167772161 + rng.integers(0, 6),
            "dst_ip_int": 167772161 + rng.integers(0, 6),
            "protocol": int(rng.choice([1, 6, 17])),
            "packet_count": int(packet_rate * duration),
            "byte_count": int(byte_rate * duration),
            "duration_sec": int(duration),
            "duration_nsec": 0,
            "packet_rate": round(packet_rate, 6),
            "byte_rate": round(byte_rate, 6),
            "label": 0,
        })
    for _ in range(200):
        duration = rng.integers(1, 20)
        packet_rate = rng.uniform(500, 5000)
        byte_rate = packet_rate * rng.uniform(60, 1200)
        rows.append({
            "src_ip_int": 167772161 + rng.integers(0, 6),
            "dst_ip_int": 167772161 + rng.integers(0, 6),
            "protocol": int(rng.choice([1, 6, 17])),
            "packet_count": int(packet_rate * duration),
            "byte_count": int(byte_rate * duration),
            "duration_sec": int(duration),
            "duration_nsec": 0,
            "packet_rate": round(packet_rate, 6),
            "byte_rate": round(byte_rate, 6),
            "label": 1,
        })
    pd.DataFrame(rows).to_csv(path, index=False)
    print(f"Generated sample dataset: {path} ({len(rows)} rows)")


def load_dataset(path):
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    data = pd.read_csv(path)
    missing = [c for c in FEATURES + ["label"] if c not in data.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")
    data = data.replace([np.inf, -np.inf], np.nan)
    data[FEATURES] = data[FEATURES].apply(pd.to_numeric, errors="coerce")
    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    data = data.dropna(subset=FEATURES + ["label"])
    data["label"] = data["label"].astype(int)
    # Remove zero-packet rows
    data = data[data["packet_count"] > 0]
    if data["label"].nunique() < 2:
        raise ValueError("Need both label=0 and label=1 rows. Collect attack traffic first.")
    print(f"Loaded {len(data)} rows. Label counts:\n{data['label'].value_counts()}")
    return data


def train(dataset_path, model_path):
    data = load_dataset(dataset_path)
    x = data[FEATURES]
    y = data["label"]

    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100, max_depth=None,
        random_state=42, class_weight="balanced"
    )
    model.fit(x_train.values, y_train)

    predictions = model.predict(x_test.values)
    print("Confusion matrix:")
    print(confusion_matrix(y_test, predictions))
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(classification_report(y_test, predictions, target_names=["Legitimate", "DDoS"]))

    joblib.dump(model, model_path)
    print(f"Saved model: {model_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="flow_stats.csv")
    parser.add_argument("--model", default="ddos_random_forest.joblib")
    parser.add_argument("--generate-sample", action="store_true")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    model_path = Path(args.model)

    if args.generate_sample:
        generate_sample_dataset(dataset_path)

    train(dataset_path, model_path)


if __name__ == "__main__":
    main()
