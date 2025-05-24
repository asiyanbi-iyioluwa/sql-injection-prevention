# waf.py
from flask import Flask, request, jsonify
import re

app = Flask(__name__)

@app.route("/filter_query", methods=["POST"])
def filter_query():
    data = request.get_json()
    query = data["query"]

    # Stricter patterns that are more likely to indicate SQLi
    sql_injection_patterns = [
        r"(?i)(\bor\b|\band\b)\s+\d+=\d+",      # e.g., OR 1=1
        r"(?i)'[\s]*or[\s]*'",                  # e.g., ' OR '
        r"(?i)(--|#)",                          # SQL comments
        r"(?i)(union(\s+all)?\s+select)",       # UNION SELECT
        r"(?i)drop\s+table",                    # DROP TABLE
        r"(?i)insert\s+into",                   # INSERT INTO
        r"(?i)update\s+\w+\s+set",              # UPDATE ... SET
    ]

    for pattern in sql_injection_patterns:
        if re.search(pattern, query):
            return jsonify({"error": "Potential SQL Injection Detected"}), 403

    return jsonify({"status": "Query allowed"})

if __name__ == "__main__":
    app.run(port=5001)
