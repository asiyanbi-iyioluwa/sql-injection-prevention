from flask import Flask, request, render_template, jsonify, redirect, session
import requests
import os
import smtplib
from email.message import EmailMessage
import logging
from dotenv import load_dotenv
import sqlite3
from functools import wraps
from logging.handlers import RotatingFileHandler
from datetime import datetime
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key")

WAF_URL = "http://127.0.0.1:5002/filter_query"
DETECTION_API_URL = "http://127.0.0.1:5002/detect"


query_log = []  # in-memory list to store query events


def init_db():
    try:
        with sqlite3.connect('sqli.db') as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY)''')
            c.execute('''CREATE TABLE IF NOT EXISTS blacklist (ip TEXT PRIMARY KEY)''')
            c.execute('''CREATE TABLE IF NOT EXISTS whitelist (ip TEXT PRIMARY KEY)''')
            c.execute('''CREATE TABLE IF NOT EXISTS query_log (id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT, ip TEXT, status TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS admin_users (username TEXT PRIMARY KEY, password TEXT)''')
            c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", "password123"))
            c.execute("INSERT OR IGNORE INTO admin_users (username, password) VALUES (?, ?)", ("admin", "admin123"))
            conn.commit()
    except sqlite3.Error as e:
        log_event("Database initialization error", f"Failed to initialize database: {str(e)}")
        raise

init_db()

def get_db_connection():
    try:
        return sqlite3.connect('sqli.db')
    except sqlite3.Error as e:
        log_event("Database connection error", f"Failed to connect to database: {str(e)}")
        raise

log_handler = RotatingFileHandler('sqli_system.log', maxBytes=1024*1024, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger('').addHandler(log_handler)
logging.getLogger('').setLevel(logging.INFO)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return render_template("admin_login.html", error="Missing username or password"), 400

        ip = request.remote_addr
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT ip FROM blocked_ips WHERE ip = ?", (ip,))
                if c.fetchone() or c.execute("SELECT ip FROM blacklist WHERE ip = ?", (ip,)).fetchone():
                    log_event("Blocked IP tried admin access", f"IP: {ip}")
                    return render_template("blocked.html"), 403
        except sqlite3.Error as e:
            log_event("Database error in admin_login", f"IP check failed: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500

        sql_query = f"SELECT * FROM admin_users WHERE username = '{username}' AND password = '{password}'"
        print(f"Generated SQL Query for Admin Testing: {sql_query}")
        log_event("Generated admin test query", sql_query)

        try:
            waf_response = requests.post(WAF_URL, json={"query": sql_query})
            waf_result = waf_response.json()
            log_event("WAF response for admin login", f"Query: {sql_query}, Result: {waf_result}")
            if waf_response.status_code != 200 or "error" in waf_result:
                log_event("Blocked by WAF in admin login", sql_query)
                send_alert_email("SQLi Blocked by WAF (Admin)", f"Blocked Query: {sql_query}")
                from utils import send_telegram_alert
                send_telegram_alert(ip, request.url, sql_query, 1.0)
                return render_template("blocked.html"), 403

            detection_response = requests.post(DETECTION_API_URL, json={"query": sql_query})
            result = detection_response.json()
            log_event("ML detection response for admin login", f"Query: {sql_query}, Result: {result}")
            if result.get("result") == "SQLi":
                try:
                    with get_db_connection() as conn:
                        c = conn.cursor()
                        c.execute("INSERT INTO query_log (query, ip, status) VALUES (?, ?, ?)", (sql_query, ip, "pending"))
                        conn.commit()
                except sqlite3.Error as e:
                    log_event("Database error in admin_login", f"Query log insertion failed: {str(e)}")
                    return jsonify({"error": "Database error occurred"}), 500
                log_event("ML detected SQLi in admin login", sql_query)
                send_alert_email("SQLi Suspicion Logged (Admin)", f"Query awaiting review: {sql_query}")
                from utils import send_telegram_alert
                send_telegram_alert(ip, request.url, sql_query, result.get("confidence", 1.0))
                return render_template("blocked.html"), 403

            try:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute("SELECT username FROM admin_users WHERE username = ? AND password = ?", (username, password))
                    admin = c.fetchone()
                    if admin:
                        session['admin_logged_in'] = True
                        log_event("Successful admin login", f"Username: {username}")
                        return redirect("/dashboard")
                    else:
                        log_event("Failed admin login attempt", f"Username: {username}")
                        return render_template("admin_login.html", error="Invalid credentials"), 401
            except sqlite3.Error as e:
                log_event("Database error in admin_login", f"Authentication failed: {str(e)}")
                return jsonify({"error": "Database error occurred"}), 500

        except requests.exceptions.RequestException as e:
            log_event("API error in admin_login", f"Error connecting to WAF or ML API: {str(e)}")
            return jsonify({"error": f"Error connecting to detection services: {str(e)}"}), 500

    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect("/admin/login")

@app.route("/test-telegram")
def test_telegram():
    from utils import send_telegram_alert
    send_telegram_alert("127.0.0.1", request.url, "Test alert", 1.0)
    return "Test sent"

@app.route("/home", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            return render_template("login.html", error="Missing username or password"), 400

        ip = request.remote_addr
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT ip FROM blocked_ips WHERE ip = ?", (ip,))
                if c.fetchone() or c.execute("SELECT ip FROM blacklist WHERE ip = ?", (ip,)).fetchone():
                    log_event("Blocked IP tried access", f"IP: {ip}")
                    return render_template("blocked.html"), 403
        except sqlite3.Error as e:
            log_event("Database error in login", f"IP check failed: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500

        sql_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"Generated SQL Query for Testing: {sql_query}")
        log_event("Generated user test query", sql_query)

        try:
            waf_response = requests.post(WAF_URL, json={"query": sql_query})
            waf_result = waf_response.json()
            log_event("WAF response for user login", f"Query: {sql_query}, Result: {waf_result}")
            if waf_response.status_code != 200 or "error" in waf_result:
                log_event("Blocked by WAF", sql_query)
                send_alert_email("SQLi Blocked by WAF", f"Blocked Query: {sql_query}")
                from utils import send_telegram_alert
                send_telegram_alert(ip, request.url, sql_query, 1.0)
                return render_template("blocked.html"), 403

            detection_response = requests.post(DETECTION_API_URL, json={"query": sql_query})
            result = detection_response.json()
            log_event("ML detection response for user login", f"Query: {sql_query}, Result: {result}")
            if result.get("result") == "SQLi":
                try:
                    with get_db_connection() as conn:
                        c = conn.cursor()
                        c.execute("INSERT INTO query_log (query, ip, status) VALUES (?, ?, ?)", (sql_query, ip, "pending"))
                        conn.commit()
                except sqlite3.Error as e:
                    log_event("Database error in login", f"Query log insertion failed: {str(e)}")
                    return jsonify({"error": "Database error occurred"}), 500
                log_event("ML detected SQLi", sql_query)
                send_alert_email("SQLi Suspicion Logged", f"Query awaiting review: {sql_query}")
                from utils import send_telegram_alert
                send_telegram_alert(ip, request.url, sql_query, result.get("confidence", 1.0))
                return render_template("blocked.html"), 403

            try:
                with get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute("SELECT username FROM users WHERE username = ? AND password = ?", (username, password))
                    user = c.fetchone()
                    if not user:
                        log_event("Failed login attempt", f"Username: {username}")
                        return render_template("login.html", error="Invalid credentials"), 401
            except sqlite3.Error as e:
                log_event("Database error in login", f"Authentication failed: {str(e)}")
                return jsonify({"error": "Database error occurred"}), 500

            log_event("Safe login attempt", sql_query)
            return render_template("success.html", username=username)
            
        except requests.exceptions.RequestException as e:
            log_event("API error in login", f"Error connecting to WAF or ML API: {str(e)}")
            return jsonify({"error": f"Error connecting to detection services: {str(e)}"}), 500

    return render_template("login.html")

@app.route("/dashboard")
@admin_required
def dashboard():
    logs = [
        {"timestamp": "2025-05-24 10:30", "event": "Safe login attempt", "query": "SELECT * FROM users WHERE username = 'admin' AND password = '123'"},
        {"timestamp": "2025-05-24 10:35", "event": "ML detected SQLi", "query": "SELECT * FROM users WHERE username = 'admin' OR 1=1--' AND password = ''"},
    ]
    return render_template("dashboard.html", logs=query_log)

LOG_FILE = "sqli_system.log"

@app.route('/logs/latest')
def get_latest_logs():
    try:
        if not os.path.exists(LOG_FILE):
            return jsonify({"logs": ["Log file not found."]})
        
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
        last_lines = lines[-100:] if len(lines) > 100 else lines
        last_lines = [line.rstrip('\n') for line in last_lines]
        return jsonify({"logs": last_lines})
    except Exception as e:
        return jsonify({"logs": [f"Error reading logs: {str(e)}"]})

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
        log_event("Email alert sent", f"Subject: {subject}")
    except Exception as e:
        print(f"Failed to send alert email: {str(e)}")
        log_event("Email alert failed", f"Subject: {subject}, Error: {str(e)}")

def log_event(event_type, query):
    logging.info(f"{event_type}: {query}")

@app.route("/profile", methods=["GET"])
@admin_required
def profile_dashboard():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT ip FROM blocked_ips")
            blocked_ips = {row[0] for row in c.fetchall()}
            c.execute("SELECT ip FROM blacklist")
            blacklist = {row[0] for row in c.fetchall()}
            c.execute("SELECT ip FROM whitelist")
            whitelist = {row[0] for row in c.fetchall()}
            c.execute("SELECT id, query, ip, status FROM query_log")
            query_log = [{"id": row[0], "query": row[1], "ip": row[2], "status": row[3]} for row in c.fetchall()]
    except sqlite3.Error as e:
        log_event("Database error in profile", f"Failed to fetch data: {str(e)}")
        return jsonify({"error": "Database error occurred"}), 500
    logs = read_logs()
    return render_template(
        "profile.html",
        logs=logs,
        blocked_ips=blocked_ips,
        blacklist=blacklist,
        whitelist=whitelist,
        query_log=query_log
    )

@app.route("/block_ip", methods=["POST"])
@admin_required
def block_ip():
    ip = request.form.get("ip")
    if ip:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)", (ip,))
                conn.commit()
        except sqlite3.Error as e:
            log_event("Database error in block_ip", f"Failed to block IP: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500
    return redirect("/profile")

@app.route("/unblock_ip", methods=["POST"])
@admin_required
def unblock_ip():
    ip = request.form.get("ip")
    if ip:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
                conn.commit()
        except sqlite3.Error as e:
            log_event("Database error in unblock_ip", f"Failed to unblock IP: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500
    return redirect("/profile")

@app.route("/blacklist_ip", methods=["POST"])
@admin_required
def blacklist_ip():
    ip = request.form.get("ip")
    if ip:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO blacklist (ip) VALUES (?)", (ip,))
                conn.commit()
        except sqlite3.Error as e:
            log_event("Database error in blacklist_ip", f"Failed to blacklist IP: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500
    return redirect("/profile")

@app.route("/whitelist_ip", methods=["POST"])
@admin_required
def whitelist_ip():
    ip = request.form.get("ip")
    if ip:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO whitelist (ip) VALUES (?)", (ip,))
                conn.commit()
        except sqlite3.Error as e:
            log_event("Database error in whitelist_ip", f"Failed to whitelist IP: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500
    return redirect("/profile")

@app.route("/allow_query", methods=["POST"])
@admin_required
def allow_query():
    idx = request.form.get("query_id")
    if idx:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("UPDATE query_log SET status = ? WHERE id = ?", ("allowed", idx))
                conn.commit()
        except sqlite3.Error as e:
            log_event("Database error in allow_query", f"Failed to allow query: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500
    return redirect("/profile")

@app.route("/block_query", methods=["POST"])
@admin_required
def block_query():
    idx = request.form.get("query_id")
    if idx:
        try:
            with get_db_connection() as conn:
                c = conn.cursor()
                c.execute("UPDATE query_log SET status = ? WHERE id = ?", ("blocked", idx))
                conn.commit()
        except sqlite3.Error as e:
            log_event("Database error in block_query", f"Failed to block query: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500
    return redirect("/profile")

import re

import re

def read_logs(limit=100):
    logs = []
    try:
        with open("sqli_system.log", "r") as f:
            lines = f.readlines()
        last_lines = lines[-limit:] if len(lines) > limit else lines

        for line in last_lines:
            line = line.strip()
            if not line:
                continue

            # Default entry
            log_entry = {
                "id": "",
                "time": "",
                "query": "",
                "ip": "",
                "status": ""
            }

            # Match "ID: X Time: Y Query: Z IP: A Status: B"
            match = re.search(r"ID:\s*(\S*)\s*Time:\s*(\S*)\s*Query:\s*(\S*)\s*IP:\s*(\S*)\s*Status:\s*(\S*)", line)
            if match:
                log_entry["id"] = match.group(1)
                log_entry["time"] = match.group(2)
                log_entry["query"] = match.group(3)
                log_entry["ip"] = match.group(4)
                log_entry["status"] = match.group(5)
            else:
                # fallback: raw line
                log_entry["status"] = line

            logs.append(log_entry)

    except Exception as e:
        logs.append({
            "id": "",
            "time": "",
            "query": "",
            "ip": "",
            "status": f"Failed to read logs: {str(e)}"
        })

    return logs

def log_query(event, query):
    query_log.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "query": query
    })


@app.route("/logs/system")
def get_system_logs():
    try:
        with open("sqli_system.log", "r") as f:
            lines = f.readlines()
        # take last 50 lines
        last_lines = lines[-50:] if len(lines) > 50 else lines
        return jsonify({"logs": last_lines})
    except Exception as e:
        return jsonify({"error": str(e), "logs": []}), 500


if __name__ == "__main__":
    app.run(port=5000, debug=True)