import requests

BOT_TOKEN = '8051760598:AAGG8JQYrAW2YFr6MCBP4I6q2JcjJBOmRao'
CHAT_ID = '6374862287'
TEXT = 'This is a test SQLi alert from your bot!'

url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
payload = {"chat_id": CHAT_ID, "text": TEXT}

response = requests.post(url, json=payload)
print(response.json())
