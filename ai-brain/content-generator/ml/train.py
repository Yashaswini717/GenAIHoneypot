import joblib
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from .feature_engineering import extract_features

# Better sample dataset
data = [
    ("GET /admin", "Reconnaissance"),
    ("GET /config", "Reconnaissance"),
    ("GET /hidden/api", "Reconnaissance"),
    ("POST /login", "Normal"),
    ("sudo su", "Priv-Esc"),
    ("scp file", "Data Exfiltration"),
    ("GET /user/profile", "Normal")
]

logs = [d[0] for d in data]
labels = [d[1] for d in data]

X = [extract_features(log) for log in logs]
y = labels

model = RandomForestClassifier(n_estimators=50)
model.fit(X, y)

MODEL_PATH = Path(__file__).with_name("model.pkl")
joblib.dump(model, MODEL_PATH)

print("Model trained ✅")
