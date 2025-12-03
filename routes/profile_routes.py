from flask import Flask, render_template, request, redirect, url_for
import json
import os

app = Flask(__name__)

# In-memory storage (replace with DB in production)
blocked_ips = set()
blacklist = set()
whitelist = set()
query_log = []  # Each item: {"query": str, "ip": str, "status": "pending"/"blocked"/"allowed"}

# Utility to read log file
def read_logs():
    if os.path.exists("sqli_system.log"):
        with open("sqli_system.log", "r") as f:
            return f.readlines()
    return []

@app.route("/profile", methods=["GET"])
def profile_dashboard():
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
def block_ip():
    ip = request.form.get("ip")
    if ip:
        blocked_ips.add(ip)
    return redirect(url_for("profile_dashboard"))

@app.route("/unblock_ip", methods=["POST"])
def unblock_ip():
    ip = request.form.get("ip")
    if ip in blocked_ips:
        blocked_ips.remove(ip)
    return redirect(url_for("profile_dashboard"))

@app.route("/blacklist_ip", methods=["POST"])
def blacklist_ip():
    ip = request.form.get("ip")
    if ip:
        blacklist.add(ip)
    return redirect(url_for("profile_dashboard"))

@app.route("/whitelist_ip", methods=["POST"])
def whitelist_ip():
    ip = request.form.get("ip")
    if ip:
        whitelist.add(ip)
    return redirect(url_for("profile_dashboard"))

@app.route("/allow_query", methods=["POST"])
def allow_query():
    idx = int(request.form.get("query_id"))
    query_log[idx]["status"] = "allowed"
    return redirect(url_for("profile_dashboard"))

@app.route("/block_query", methods=["POST"])
def block_query():
    idx = int(request.form.get("query_id"))
    query_log[idx]["status"] = "blocked"
    return redirect(url_for("profile_dashboard"))
