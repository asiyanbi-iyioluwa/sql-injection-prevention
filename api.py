from flask import Flask, request, jsonify
import re
import joblib
import os
from utils import preprocess_query
import logging
from logging.handlers import RotatingFileHandler
import tensorflow as tf


app = Flask(__name__)

# Logging setup
log_handler = RotatingFileHandler('sqli_system.log', maxBytes=1024*1024, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger('').addHandler(log_handler)
logging.getLogger('').setLevel(logging.INFO)

# Load classical models
try:    
    rf_model = joblib.load("ml_models/rf_model.joblib")
    dt_model = joblib.load("ml_models/dt_model.joblib")
    svm_model = joblib.load("ml_models/svm_model.joblib")
    vectorizer = joblib.load("ml_models/vectorizer.joblib")

# Load CNN model and tokenizer
    cnn_model = tf.keras.models.load_model("ml_models/cnn_model.h5")
    tokenizer = joblib.load("ml_models/tokenizer.joblib")
except Exception as e:
    logging.error(f"Error loading CNN models: {str(e)}")
    raise


# Load ML models
# try:
#     vectorizer = joblib.load('ml_models/vectorizer.pkl')
#     model = joblib.load('ml_models/sqli_detector_model.pkl')
# except Exception as e:
#     logging.error(f"Error loading ML models: {str(e)}")
#     raise

# WAF patterns for SQL injection
SQLI_PATTERNS = [
    r'(\bunion\s+select\b)',  # Union-based injections
    r'(\b(or|and)\s+1=1\b)',  # Tautology attacks
    r'(--|#|/\*)',  # SQL comments
    r'(\bexec\s+\w+|\bdeclare\s+@\w+|\bcast\s*\()',  # Dangerous functions
    r'(\bwaitfor\s+delay\b)',  # Time-based attacks
    r'(\b;.*?\b(select|drop)\b)',  # Multiple statements
    r'(\bselect\s+.*?\s+from\s+.*?\s*(where\s+.*?\s*(or|and)\s+.*?\b(select|union)\b))',  # Nested/subquery attacks
]

def is_sqli(query):
    query_lower = query.lower()
    for i, pattern in enumerate(SQLI_PATTERNS):
        if re.search(pattern, query_lower):
            logging.info(f"WAF pattern {i} matched: {pattern} in query: {query_lower}")
            return True
    return False

@app.route('/filter_query', methods=['POST'])
def filter_query():
    data = request.get_json()
    query = data.get('query', '')
    if not query:
        logging.warning("No query provided to /filter_query")
        return jsonify({"error": "No query provided"}), 400
    if is_sqli(query):
        logging.info(f"Blocked by WAF: {query}")
        return jsonify({"error": "Potential SQL Injection Detected"}), 403
    logging.info(f"WAF passed: {query}")
    return jsonify({"status": "Query is clean"}), 200

@app.route('/detect', methods=['POST'])
def detect():
    data = request.get_json()
    query = data.get('query', '')
    if not query:
        logging.warning("No query provided to /detect")
        return jsonify({"error": "No query provided"}), 400
    try:
        processed_query = preprocess_query(query)
        features = vectorizer.transform([processed_query])
        prediction = model.predict(features)[0]
        confidence = model.predict_proba(features)[0][1] if prediction == 1 else model.predict_proba(features)[0][0]
        result = "SQLi" if prediction == 1 else "Safe"
        logging.info(f"ML detection: Query: {query}, Result: {result}, Confidence: {confidence:.2f}")
        return jsonify({"result": result, "confidence": float(confidence)})
    except Exception as e:
        logging.error(f"ML detection error: {str(e)}")
        return jsonify({"error": f"ML detection error: {str(e)}"}), 500

@app.route('/detect_sql_injection', methods=['POST'])
def detect_sql_injection():
    data = request.get_json()
    query = data.get('query', '')

    # === Classical Model Preprocessing ===
    vec_input = vectorizer.transform([query])

    prob_rf = rf_model.predict_proba(vec_input)[0][1]
    prob_dt = dt_model.predict_proba(vec_input)[0][1]
    prob_svm = svm_model.predict_proba(vec_input)[0][1]

    # === CNN Preprocessing ===
    seq = tokenizer.texts_to_sequences([query])
    padded = tf.keras.preprocessing.sequence.pad_sequences(seq, maxlen=100)
    prob_cnn = cnn_model.predict(padded, verbose=0)[0][0]

    # === Hybrid Voting ===
    raw_probs = np.array([[prob_rf, prob_dt, prob_svm, prob_cnn]])

    # Normalize all probabilities to [0, 1]
    scaler = MinMaxScaler()
    normalized_probs = scaler.fit_transform(raw_probs)

    # Soft Voting: Average all normalized probs
    avg_prob = np.mean(normalized_probs)

    label = "sql_injection" if avg_prob > 0.5 else "benign"

    return {
        "query": query,
        "prediction": label,
        "confidence": float(avg_prob)
    }
   

if __name__ == "__main__":
    app.run(port=5002, debug=True)