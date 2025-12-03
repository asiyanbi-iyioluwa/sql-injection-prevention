import re
import logging
from logging.handlers import RotatingFileHandler
import requests
from dotenv import load_dotenv
import os

load_dotenv()

# Logging setup
log_handler = RotatingFileHandler('sqli_system.log', maxBytes=1024*1024, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger('').addHandler(log_handler)
logging.getLogger('').setLevel(logging.INFO)

def preprocess_query(query):
    query = query.lower()
    query = re.sub(r'\s+', ' ', query.strip())
    query = re.sub(r'[^\w\s=<>]', '', query)
    return query

def send_telegram_alert(ip, url, query, confidence):
    try:
        bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")
        message = f"SQLi Alert\nIP: {ip}\nURL: {url}\nQuery: {query}\nConfidence: {confidence:.2f}"
        telegram_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        params = {"chat_id": chat_id, "text": message}
        response = requests.get(telegram_url, params=params)
        response.raise_for_status()
        print("Telegram alert sent successfully.")
    except Exception as e:
        print(f"Failed to send Telegram alert: {str(e)}")