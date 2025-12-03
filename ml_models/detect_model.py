# ml_models/detect_model.py

import joblib
import os
from utils import preprocess

# Load vectorizer and model once
model_dir = os.path.join(os.getcwd(), 'ml_models')
vectorizer = joblib.load(os.path.join(model_dir, 'vectorizer.pkl'))
model = joblib.load(os.path.join(model_dir, 'sqli_detector_model.pkl'))

def detect_with_model(query):
    processed = preprocess(query)
    features = vectorizer.transform([processed])
    prediction = model.predict(features)[0]
    confidence = model.predict_proba(features)[0][int(prediction)]
    return ("SQLi" if prediction == 1 else "Benign"), float(confidence)
