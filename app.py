from flask import Flask, request, jsonify, render_template
import logging
import datetime
import os

app = Flask(__name__, template_folder='templates', static_folder='static')

# Configure logging
if not os.path.exists("logs"):
    os.makedirs("logs")
logging.basicConfig(filename="logs/honeytoken_access.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

def log_attack(endpoint, attacker_ip, user_agent, payload):
    log_entry = f"Endpoint Accessed: {endpoint} | IP: {attacker_ip} | User-Agent: {user_agent} | Payload: {payload}"
    logging.info(log_entry)

@app.route('/')
def home():
    return render_template("index.html")

# Fake API Endpoint as a honeytoken
@app.route('/api/private-key', methods=['GET'])
def fake_private_key():
    attacker_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    log_attack("/api/private-key", attacker_ip, user_agent, "None")
    return jsonify({"error": "Unauthorized access detected"}), 403

# Fake admin login page
@app.route('/admin-login', methods=['GET', 'POST'])
def fake_admin_login():
    if request.method == 'POST':
        attacker_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        username = request.form.get("username")
        password = request.form.get("password")
        log_attack("/admin-login", attacker_ip, user_agent, f"Username: {username}, Password: {password}")
        return jsonify({"error": "Unauthorized access detected"}), 403
    return render_template("login.html")

if __name__ == '__main__':
    app.run(debug=True, port=5000)
