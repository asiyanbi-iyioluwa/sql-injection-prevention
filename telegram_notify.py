import requests
from datetime import datetime

BOT_TOKEN = "8051760598:AAGG8JQYrAW2YFr6MCBP4I6q2JcjJBOmRao"    # Replace with your Telegram bot token
CHAT_ID = "6374862287"        # Replace with your Telegram chat ID

def send_telegram_message(message: str):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Telegram API error: {e}")
        return None

def notify_sqli_attempt(query: str, attack_type: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = (
        f"<b>SQL Injection Alert!</b>\n"
        f"Type: {attack_type}\n"
        f"Query: {query}\n"
        f"Timestamp: {timestamp}"
    )
    return send_telegram_message(message)
