@echo off
echo Starting WAF API on port 5002...
start "" python api.py

timeout /t 2 > nul

echo Starting Flask Web App on port 5000...
start "" python web_app.py

echo All servers are starting...
pause
