# utils.py
import logging
import smtplib
from email.message import EmailMessage
import requests
import os
from dotenv import load_dotenv
load_dotenv()

# --- Logging Setup ---
logging.basicConfig(
    filename='sql_system.log',  # Or change path if you want
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_event(ip, url, query, result, confidence=None, action='allowed'):
    log_msg = f"IP: {ip} | URL: {url} | Query: {query} | Result: {result} | Action: {action}"
    if confidence is not None:
        log_msg += f" | Confidence: {confidence:.2f}"
    logging.info(log_msg)

# --- Alerting Function ---
def send_email_alert(ip, url, query, confidence):
    sender_email = os.getenv("ALERT_SENDER_EMAIL", "iyioluwaasiyanbi@gmail.com")
    receiver_email = os.getenv("ALERT_RECEIVER_EMAIL", "asiyanbiiyioluwa@gmail.com")
    email_password = os.getenv("ALERT_EMAIL_PASSWORD")  # Read from env variable
    
    
    msg = EmailMessage()
    msg['Subject'] = "🚨 SQL Injection Detected"
    msg['From'] = 'iyioluwaasiyanbi@gmail.com'
    msg['To'] = 'asiyanbiiyioluwa@gmail.com.com'

    msg.set_content(
        f"SQL Injection Attempt!\nIP: {ip}\nURL: {url}\nQuery: {query}\nConfidence: {confidence:.2f}"
    )

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()
            smtp.login('sender_email', 'email_password')  # Use env var in real code
            smtp.send_message(msg)
    except Exception as e:
        print(f"[ERROR] Failed to send email alert: {e}")

BOT_TOKEN = "8051760598:AAGG8JQYrAW2YFr6MCBP4I6q2JcjJBOmRao"
CHAT_ID = "6374862287"

def send_telegram_alert(ip, url, query, confidence):
    message = (
        f"<b>🚨 SQL Injection Alert 🚨</b>\n"
        f"<b>IP:</b> {ip}\n"
        f"<b>URL:</b> {url}\n"
        f"<b>Query:</b> <code>{query}</code>\n"
        f"<b>Confidence:</b> {confidence:.2f}"
    )
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Telegram notification failed: {e}")