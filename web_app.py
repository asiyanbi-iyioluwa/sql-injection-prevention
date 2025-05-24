# web_app.py
from flask import Flask, request, render_template, jsonify
import requests
import smtplib
from email.message import EmailMessage
import logging
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)

WAF_URL = "http://127.0.0.1:5001/filter_query"
DETECTION_API_URL = "http://127.0.0.1:5002/detect"

@app.route("/test-telegram")
def test_telegram():
    send_telegram_alert("Test alert from /test-telegram")
    return "Test sent"


@app.route("/home", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Simulated query (vulnerable)
        sql_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"Generated SQL Query: {sql_query}")

        try:
            # Step 1: WAF
            waf_response = requests.post(WAF_URL, json={"query": sql_query})
            waf_result = waf_response.json()
            
            if waf_response.status_code != 200 or "error" in waf_result:
                log_event("Blocked by WAF", sql_query)
                send_alert_email("SQLi Blocked by WAF", f"Blocked Query: {sql_query}")
                send_telegram_alert(f"*SQLi Blocked by WAF*\n```{sql_query}```")
                return render_template("blocked.html"), 403  # Serve the blocked page

            # Step 2: ML Detection
            detection_response = requests.post(DETECTION_API_URL, json={"query": sql_query})
            result = detection_response.json()
            if result.get("prediction") == "SQL Injection Detected":
                log_event("ML detected SQLi", sql_query)
                send_alert_email("SQLi Blocked by ML", f"Blocked Query: {sql_query}")
                send_telegram_alert(f"*SQLi Blocked by ML*\n```{sql_query}```")
                return render_template("blocked.html"), 403  # Serve the blocked page
            
            log_event("Safe login attempt", sql_query)
            return render_template(
                "success.html",
                username=username  # Pass variables to template if needed
            )
            
        except requests.exceptions.RequestException as e:
            return jsonify({"error": f"Error connecting to WAF or ML API: {str(e)}"})

    return render_template("login.html")


import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

def send_alert_email(subject, body):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = os.getenv("SMTP_EMAIL")
        msg["To"] = os.getenv("ADMIN_EMAIL")
        msg.set_content(body)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(os.getenv("SMTP_EMAIL"), os.getenv("SMTP_APP_PASSWORD"))
            smtp.send_message(msg)
        print("Alert email sent successfully.")
    except Exception as e:
        print(f"Failed to send alert email: {str(e)}")


def send_telegram_alert(message):
    try:
        token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")
        if not token or not chat_id:
            print("Missing Telegram credentials in environment variables.")
            return
        
        
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("Telegram alert sent successfully.")
        else:
            print(f"Failed to send Telegram alert: {response.text}")
    except Exception as e:
        print(f"Telegram alert error: {e}")

def log_event(event_type, query):
    logging.info(f"{event_type}: {query}")

logging.basicConfig(
    filename="sqli_system.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

if __name__ == "__main__":
    app.run(port=5000, debug=True)


