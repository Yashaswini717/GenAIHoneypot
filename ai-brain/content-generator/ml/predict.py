from pathlib import Path

import joblib

from .feature_engineering import extract_features

MODEL_PATH = Path(__file__).with_name("model.pkl")
model = joblib.load(MODEL_PATH)

def predict_intent(log):
    features = extract_features(log)
    return model.predict([features])[0]
