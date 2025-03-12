from flask import Flask, request, jsonify, render_template
from collections import defaultdict
import time
import logging
import datetime
import os
import mysql.connector
import requests

# Set up logging
if not os.path.exists("logs"):
    os.makedirs("logs")
logging.basicConfig(filename="logs/honeytoken_access.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

app = Flask(__name__, template_folder='templates', static_folder='static')
app.logger.info("Server started!")

# MySQL Database Connection
db = mysql.connector.connect(
    host="127.0.0.1", 
    user="root",
    password="",  
    database="web_honeytoken"
)

cursor = db.cursor()

# Ensure tables exist
cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_type VARCHAR(255),
        endpoint VARCHAR(255),
        attacker_ip VARCHAR(255),
        user_agent TEXT,
        payload TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")
db.commit()

# Suspicious IP Detection API (AbuseIPDB)
ABUSEIPDB_API_KEY = "aa0ed8e5f267e7b8853310efe79604db23643fd7ecdc3e1afec6d2f78f2735050c5ec37d8c92b21c"

# Dictionary to track login attempts (Brute Force Detection)
failed_login_attempts = {}


def log_attack(endpoint, attacker_ip, user_agent, payload, event_type="Unauthorized Access"):
    log_entry = f"Event: {event_type} | Endpoint: {endpoint} | IP: {attacker_ip} | User-Agent: {user_agent} | Payload: {payload}"
    logging.info(log_entry)

    # Debugging: Print IP check
    logging.info(f"Checking IP {attacker_ip} against AbuseIPDB")

    is_suspicious = check_suspicious_ip(attacker_ip)
    if is_suspicious:
        logging.info(f"⚠️ IP {attacker_ip} flagged as suspicious by AbuseIPDB")
        send_alert(f"🚨 Suspicious IP Detected: {attacker_ip} triggered a honeytoken on {endpoint}!")

    try:
        db.ping(reconnect=True)  # Ensure connection is active
        cursor.execute(
            "INSERT INTO logs (event_type, endpoint, attacker_ip, user_agent, payload) VALUES (%s, %s, %s, %s, %s)",
            (event_type, endpoint, attacker_ip, user_agent, payload)
        )
        db.commit()
    except mysql.connector.Error as err:
        logging.error(f"MySQL Error: {err}")

def detect_nikto(user_agent, attacker_ip, endpoint):
    nikto_patterns = ["Nikto", "nikto", "NIKTO"]

    if any(pattern in user_agent for pattern in nikto_patterns):
        log_attack(endpoint, attacker_ip, user_agent, "Nikto Scan Detected", "Nikto Scan")
        send_alert(f"🚨 Nikto Scan Detected from IP {attacker_ip} on {endpoint}!")
        return True  # Attack detected
    return False

request_counter = defaultdict(list)  # Store timestamps for each IP

def detect_nikto_rate_limit(attacker_ip):
    current_time = time.time()
    request_counter[attacker_ip].append(current_time)

    # Keep only recent requests (last 10 seconds)
    request_counter[attacker_ip] = [t for t in request_counter[attacker_ip] if current_time - t < 10]

    if len(request_counter[attacker_ip]) > 15:  # More than 15 requests in 10 sec
        log_attack("Multiple Endpoints", attacker_ip, "Nikto-like Behavior", "High-Request Rate", "Nikto Scan")
        send_alert(f"⚠️ Possible Nikto Scan detected from {attacker_ip} - Rapid requests observed!")
        return True
    return False

# Nikto Scan Path List
nikto_scan_paths = ["/admin.php", "/phpinfo.php", "/config.php", "/robots.txt", "/server-status"]

@app.before_request
def detect_nikto_scan():
    attacker_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')

    # Detect Nikto User-Agent
    if detect_nikto(user_agent, attacker_ip, request.path):
        return jsonify({"error": "Nikto scan detected"}), 403

    # Detect Nikto High Request Rate
    if detect_nikto_rate_limit(attacker_ip):
        return jsonify({"error": "Excessive requests detected"}), 429

    # Detect Nikto Scan Paths
    if request.path in nikto_scan_paths:
        log_attack(request.path, attacker_ip, user_agent, "Nikto Scan Attempt", "Nikto Scan")
        send_alert(f"🚨 Nikto scan detected! Suspicious access to {request.path} from {attacker_ip}")
        return jsonify({"error": "Blocked - Possible Nikto Scan"}), 403


# Function to check suspicious IP (AbuseIPDB)
def check_suspicious_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response_data = response.json()
        
        # Debugging: Log the response
        logging.info(f"AbuseIPDB Response: {response_data}")

        if response.status_code == 200:
            confidence_score = response_data.get("data", {}).get("abuseConfidenceScore", 0)
            return confidence_score > 50  # Mark as suspicious if confidence score > 50
        else:
            logging.error(f"AbuseIPDB API Error: {response_data}")
    
    except Exception as e:
        logging.error(f"AbuseIPDB check failed: {e}")
    
    return False


# Function to detect SQL Injection attempts
def detect_sql_injection(payload):
    sql_patterns = ["'", "--", " OR ", " UNION ", "SELECT ", "DROP ", "INSERT "]
    for pattern in sql_patterns:
        if pattern in payload:
            return True
    return False

# Function to detect brute force attacks
def detect_brute_force(ip):
    failed_login_attempts[ip] = failed_login_attempts.get(ip, 0) + 1
    if failed_login_attempts[ip] > 3:  # If more than 3 failed attempts, mark as brute force
        return True
    return False

# Slack Webhook URL (Replace with your actual webhook URL)
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"

# Function to send alerts to Slack
def send_alert(message):
    payload = {"text": message}
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, headers=headers)
        if response.status_code != 200:
            logging.error(f"Slack Notification Failed: {response.text}")
    except Exception as e:
        logging.error(f"Error sending Slack notification: {e}")

@app.route('/')
def home():
    return render_template("index.html")

# Fake API Endpoint as a honeytoken
@app.route('/api/private-key', methods=['GET'])
def fake_private_key():
    attacker_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    log_attack("/api/private-key", attacker_ip, user_agent, "None", "Honeytoken Triggered")
    
    return render_template("unauthorized.html"), 403 


# Fake admin login page
@app.route('/admin-login', methods=['GET', 'POST'])
def fake_admin_login():
    if request.method == 'POST':
        attacker_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        username = request.form.get("username")
        password = request.form.get("password")

        # Detect SQL Injection
        if detect_sql_injection(username) or detect_sql_injection(password):
            log_attack("/admin-login", attacker_ip, user_agent, f"SQL Injection Attempt - Username: {username}, Password: {password}", "SQL Injection Detected")
            return jsonify({"error": "SQL Injection detected"}), 403

        # Detect Brute Force
        if detect_brute_force(attacker_ip):
            log_attack("/admin-login", attacker_ip, user_agent, f"Brute Force Attempt - Username: {username}, Password: {password}", "Brute Force Attack Detected")
            return jsonify({"error": "Brute Force detected"}), 403

        # Log Unauthorized Login Attempt
        log_attack("/admin-login", attacker_ip, user_agent, f"Username: {username}, Password: {password}", "Unauthorized Login Attempt")

        # Flag fake credentials
        if username == "admin" and password == "admin":
            log_attack("/admin-login", attacker_ip, user_agent, f"Suspicious Login - Username: {username}, Password: {password}", "Suspicious Login")
            send_alert(f"⚠️ Suspicious Login Attempt Detected! IP: {attacker_ip}")

            return jsonify({"error": "Suspicious login attempt detected"}), 403

        return jsonify({"error": "Unauthorized access detected"}), 403
    
    return render_template("login.html")

if __name__ == '__main__':
    app.run(debug=True, port=5000)
