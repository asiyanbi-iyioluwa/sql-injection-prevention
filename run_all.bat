@echo off
echo Starting WAF API on port 5001...
start cmd /k python waf.py

timeout /t 2 > nul

echo Starting ML Detection API on port 5002...
start cmd /k python dectection_api.py

timeout /t 2 > nul

echo Starting Flask Web App on port 5000...
start cmd /k python web_app.py

echo All servers are starting...
pause
