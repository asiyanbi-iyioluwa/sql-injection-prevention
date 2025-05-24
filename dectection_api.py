# from flask import Flask, request, jsonify
# import joblib
# import re
# import os
# import logging
# from utils import log_event, send_email_alert
# from models.detect_model import detect_with_model

# app = Flask(__name__)

# # Load models - adjust paths as needed
# def load_models():
#     global vectorizer, model
#     try:
#         model_dir = os.path.join(os.getcwd(), 'models')
#         vectorizer_path = os.path.join(model_dir, 'vectorizer.pkl')
#         sqli_detector_model_path = os.path.join(model_dir, 'sqli_detector_model.pkl')

#         if not os.path.exists(vectorizer_path) or not os.path.exists(sqli_detector_model_path):
#             raise FileNotFoundError("Model files not found. Make sure 'vectorizer.pkl' and 'sqli_detector_model.pkl' are in the 'models' directory.")

#         vectorizer = joblib.load(vectorizer_path)
#         model = joblib.load(sqli_detector_model_path)  # Corrected this line
#         print("Models loaded successfully!")
#     except Exception as e:
#         print(f"Error loading models: {str(e)}")
#         raise e  # Crash early if models can't load


# load_models()  # Call this during startup

# @app.route('/detect', methods=['POST'])
# def detect_sqli():
#     # Verify models are loaded
#     if vectorizer is None or model is None:
#         return jsonify({'error': 'ML models not loaded'}), 500
        
#     # Validate input
#     if not request.is_json:
#         return jsonify({'error': 'Request must be JSON'}), 400
        
#     data = request.get_json()
#     query = data.get('query', '').strip()
    
#     if not query:
#         return jsonify({'error': 'Query cannot be empty'}), 400
    
#     try:
#         # Process query
#         processed_query = preprocess(query)
#         features = vectorizer.transform([processed_query])
#         prediction = model.predict(features)
        
#         return jsonify({
#             'is_sqli': bool(prediction[0]),
#             'confidence': float(prediction[0])  # Adjust based on your model
#         })
#     except Exception as e:
#         return jsonify({'error': f'Detection failed: {str(e)}'}), 500

# def preprocess(query):
#     # Basic preprocessing (should match your training pipeline)
#     return re.sub(r"[^\w\s]", "", query.lower())

# if __name__ == "__main__":
#     app.run(port=5002, debug=True)

# # Debugging - Show model directory contents and file sizes
# print("\nDebugging Information:")
# model_dir = os.path.join(os.getcwd(), 'models')
# if os.path.exists(model_dir):
#     print(f"Models directory found: {model_dir}")
#     print(f"Files in models directory: {os.listdir(model_dir)}")
#     for file in os.listdir(model_dir):
#         file_path = os.path.join(model_dir, file)
#         print(f"{file} - Size: {os.path.getsize(file_path)} bytes")
# else:
#     print("Models directory not found.")


# # Logging Setup
# logging.basicConfig(
#     filename='logs/sqli_detection.log',
#     level=logging.INFO,
#     format='%(asctime)s - %(levelname)s - %(message)s'
# )

# def log_event(ip, url, query, result, confidence=None, action='allowed'):
#     log_msg = f"IP: {ip} | URL: {url} | Query: {query} | Result: {result} | Action: {action}"
#     if confidence is not None:
#         log_msg += f" | Confidence: {confidence:.2f}"
#     logging.info(log_msg)
    
    
# @app.post("/detect")
# async def detect_sql_injection(request: Request):
#     data = await request.json()
#     query = data["query"]
#     ip = request.client.host
#     url = str(request.url)

#     result, confidence = detect_with_model(query)
#     action = "blocked" if result == "SQLi" else "allowed"

#     log_event(ip, url, query, result, confidence, action)
#     return {"result": result, "confidence": confidence, "action": action}


from flask import Flask, request, jsonify
import joblib
import re
import os
from ml_models.detect_model import detect_with_model
from utils import log_event, send_email_alert  # ✅ Logging + alerting in separate file
import requests


app = Flask(__name__)

# Load vectorizer and ML model
def load_models():
    global vectorizer, model
    try:
        model_dir = os.path.join(os.getcwd(), 'ml_models')  # <-- Corrected path
        vectorizer_path = os.path.join(model_dir, 'vectorizer.pkl')
        model_path = os.path.join(model_dir, 'sqli_detector_model.pkl')

        vectorizer = joblib.load(vectorizer_path)
        model = joblib.load(model_path)
        print("Models loaded successfully.")
    except Exception as e:
        print(f"Failed to load models: {e}")
        raise

load_models()

# Preprocess input query
def preprocess(query):
    return re.sub(r"[^\w\s]", "", query.lower())


# Telegram Bot Config — replace these with your real values
BOT_TOKEN = "8051760598:AAGG8JQYrAW2YFr6MCBP4I6q2JcjJBOmRao"
CHAT_ID = "6374862287"

def send_telegram_alert(ip, url, query, confidence):
    message = (
        f"<b>🚨 SQL Injection Alert 🚨</b>\n"
        f"<b>IP:</b> {ip}\n"
        f"<b>URL:</b> {url}\n"
        f"<b>Query:</b> <code>{query}</code>\n"
        f"<b>Confidence:</b> {confidence:.4f}"
    )
import requests
import os

def send_telegram_alert(message):
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message
    }
    try:
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            print("Telegram alert sent successfully.")
        else:
            print(f"Failed to send Telegram alert: {response.status_code} {response.text}")
    except Exception as e:
        print(f"Error sending Telegram alert: {e}")



@app.route('/detect', methods=['POST'])
def detect_sqli():
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400

    data = request.get_json()
    query = data.get('query', '').strip()
    if not query:
        return jsonify({'error': 'Query cannot be empty'}), 400

    try:
        processed = preprocess(query)
        features = vectorizer.transform([processed])
        prediction = model.predict(features)[0]
        confidence = model.predict_proba(features)[0][int(prediction)]  # Adjust if your model doesn't support `predict_proba`

        result = "SQLi" if prediction == 1 else "Benign"
        action = "blocked" if prediction == 1 else "allowed"

        # Logging and alerting
        ip = request.remote_addr
        url = request.url
        log_event(ip, url, query, result, confidence, action)
        if prediction == 1:
            send_email_alert(ip, url, query, confidence)

        return jsonify({
            'result': result,
            'confidence': round(confidence, 4),
            'action': action
        })

    except Exception as e:
        return jsonify({'error': f'Detection failed: {str(e)}'}), 500

if __name__ == "__main__":
    app.run(port=5002, debug=True)

