import mysql.connector
import re
import requests
import logging
import datetime
import os
from flask import Flask, request, jsonify, render_template

# Configure Logging
if not os.path.exists("logs"):
    os.makedirs("logs")
logging.basicConfig(filename="logs/forensics.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Initialize Flask App
app = Flask(__name__)

# Database Connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="123",
    database="web_honeytoken"
)
cursor = db.cursor()

# Function to Log Attack
def log_attack(endpoint, ip, user_agent, payload, attack_type):
    log_entry = f"Attack Detected! Type: {attack_type} | Endpoint: {endpoint} | IP: {ip} | User-Agent: {user_agent} | Payload: {payload}"
    logging.info(log_entry)
    
    # Store in MySQL
    cursor.execute("INSERT INTO attacks (endpoint, ip, user_agent, payload, attack_type, timestamp) VALUES (%s, %s, %s, %s, %s, NOW())",
                   (endpoint, ip, user_agent, payload, attack_type))
    db.commit()

    # Send Alert
    send_alert(log_entry)

# Function to Detect SQL Injection
def detect_sql_injection(payload):
    sql_patterns = ["'", "--", " OR ", " UNION ", "SELECT ", "DROP ", "INSERT "]
    for pattern in sql_patterns:
        if pattern in payload:
            return True
    return False

# Function to Detect Brute Force Attack (Multiple Login Failures)
failed_login_attempts = {}

def detect_brute_force(ip):
    failed_login_attempts[ip] = failed_login_attempts.get(ip, 0) + 1
    if failed_login_attempts[ip] > 3:
        return True
    return False

# Function to Check for Suspicious IP (Using AbuseIPDB)
def check_suspicious_ip(ip):
    api_key = "YOUR_ABUSEIPDB_API_KEY"
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": api_key, "Accept": "application/json"}
    response = requests.get(url, headers=headers).json()
    
    if response.get("data", {}).get("abuseConfidenceScore", 0) > 50:
        return True
    return False

# Function to Send Real-time Alert (Telegram)
def send_alert(message):
    telegram_token = "YOUR_TELEGRAM_BOT_TOKEN"
    chat_id = "YOUR_CHAT_ID"
    url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
    requests.post(url, data={"chat_id": chat_id, "text": message})

# Fake API Endpoint (Honeytoken)
@app.route('/api/private-key', methods=['GET'])
def fake_private_key():
    attacker_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    if check_suspicious_ip(attacker_ip):
        log_attack("/api/private-key", attacker_ip, user_agent, "None", "Suspicious IP Detected")

    log_attack("/api/private-key", attacker_ip, user_agent, "None", "Unauthorized Access")
    return jsonify({"error": "Unauthorized access detected"}), 403

# Fake Admin Login Page (Brute Force & SQL Injection Detection)
@app.route('/admin-login', methods=['POST'])
def fake_admin_login():
    attacker_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    username = request.form.get("username")
    password = request.form.get("password")

    # Detect SQL Injection
    if detect_sql_injection(username) or detect_sql_injection(password):
        log_attack("/admin-login", attacker_ip, user_agent, f"Username: {username}, Password: {password}", "SQL Injection Attempt")

    # Detect Brute Force
    if detect_brute_force(attacker_ip):
        log_attack("/admin-login", attacker_ip, user_agent, f"Username: {username}, Password: {password}", "Brute Force Attack")

    return jsonify({"error": "Unauthorized access detected"}), 403

# Run Flask App
if __name__ == '__main__':
    app.run(debug=True, port=5000)
