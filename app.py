from flask import Flask, request, render_template_string, redirect
import time
import random
from datetime import datetime

app = Flask(__name__)

# ─── CONFIG ───────────────────────────────────────────────────
VALID_USERS = {
    "admin"    : "admin123",
    "devops"   : "dev@123",
    "sec_admin": "secure@123"
}

# Honeypot IP — change to Laptop 2's IP when deploying cross-machine
HONEYPOT_IP = "10.24.167.9"
HONEYPOT_PORT = 5001

# Per-IP failed attempt tracking
# Format: { 'ip': {'count': int, 'threshold': int} }
failed_attempts = {}

# ─────────────────────────────────────────────────────────────

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Access Portal — Gateway</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', 'Segoe UI', sans-serif;
            background: #07101f;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            position: relative;
        }
        body::before {
            content: '';
            position: fixed; inset: 0;
            background-image:
                linear-gradient(rgba(20,50,110,0.18) 1px, transparent 1px),
                linear-gradient(90deg, rgba(20,50,110,0.18) 1px, transparent 1px);
            background-size: 44px 44px;
            animation: gridMove 22s linear infinite;
            pointer-events: none;
        }
        @keyframes gridMove {
            0%   { background-position: 0 0; }
            100% { background-position: 44px 44px; }
        }
        .orb {
            position: fixed; border-radius: 50%;
            filter: blur(90px); opacity: 0.28; pointer-events: none;
        }
        .orb-1 { width: 420px; height: 420px; background: #1a3a8f; top: -120px; left: -120px; }
        .orb-2 { width: 360px; height: 360px; background: #4f10a8; bottom: -100px; right: -100px; }

        .wrap {
            position: relative; z-index: 10;
            display: flex; flex-direction: column; align-items: center; gap: 16px;
        }

        .top-bar {
            width: 440px;
            background: rgba(239,68,68,0.1);
            border: 1px solid rgba(239,68,68,0.3);
            border-radius: 10px;
            padding: 10px 18px;
            display: flex; align-items: center; gap: 10px;
            color: #fca5a5; font-size: 0.8rem;
        }
        .top-bar-icon { color: #ef4444; font-size: 0.95rem; }

        .card {
            background: rgba(255,255,255,0.035);
            border: 1px solid rgba(90,150,255,0.18);
            border-radius: 20px;
            backdrop-filter: blur(22px);
            -webkit-backdrop-filter: blur(22px);
            padding: 48px 42px;
            width: 440px;
            box-shadow:
                0 0 0 1px rgba(90,150,255,0.05) inset,
                0 30px 80px rgba(0,0,0,0.75);
        }

        .logo { text-align: center; margin-bottom: 30px; }
        .shield {
            width: 70px; height: 70px;
            background: linear-gradient(145deg, #1a3a8f, #2563eb);
            border-radius: 16px;
            display: inline-flex; align-items: center; justify-content: center;
            font-size: 1.9rem; color: #fff; margin-bottom: 14px;
            box-shadow: 0 8px 30px rgba(37,99,235,0.45);
            animation: pulse 3s ease-in-out infinite;
        }
        @keyframes pulse {
            0%,100% { box-shadow: 0 8px 30px rgba(37,99,235,0.45); }
            50%      { box-shadow: 0 8px 46px rgba(37,99,235,0.75), 0 0 22px rgba(37,99,235,0.28); }
        }
        .logo h1 { color: #e8f0ff; font-size: 1.4rem; font-weight: 700; margin-bottom: 4px; }
        .logo .sub { color: #5070a0; font-size: 0.74rem; letter-spacing: 2.5px; text-transform: uppercase; }

        hr { border: none; border-top: 1px solid rgba(90,150,255,0.1); margin: 22px 0; }

        .msg-box { min-height: 28px; margin-bottom: 12px; text-align: center; }
        .error-msg {
            color: #fca5a5;
            background: rgba(239,68,68,0.1);
            border: 1px solid rgba(239,68,68,0.25);
            border-radius: 8px;
            padding: 8px 14px;
            font-size: 0.83rem;
            font-weight: 500;
        }
        .notice-msg { color: #4a7ab0; font-size: 0.8rem; }

        label {
            display: block;
            color: #7a9acc; font-size: 0.8rem; font-weight: 500;
            margin-bottom: 7px;
        }
        .field { position: relative; margin-bottom: 18px; }
        .field-icon {
            position: absolute; left: 13px; top: 50%; transform: translateY(-50%);
            color: #304060; font-size: 0.85rem; pointer-events: none;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(90,150,255,0.18);
            color: #dce8ff;
            border-radius: 10px;
            padding: 11px 14px 11px 36px;
            font-size: 0.92rem;
            font-family: inherit;
            transition: all 0.2s;
        }
        input::placeholder { color: #283850; }
        input:focus {
            outline: none;
            background: rgba(255,255,255,0.07);
            border-color: rgba(78,140,255,0.55);
            box-shadow: 0 0 0 3px rgba(78,140,255,0.1);
            color: #fff;
        }

        #loader {
            display: none;
            width: 20px; height: 20px;
            border: 3px solid rgba(78,140,255,0.2);
            border-top-color: #4e8cff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 10px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        #authText { display: none; color: #4e8cff; font-size: 0.82rem; text-align: center; margin-bottom: 10px; font-weight: 500; }

        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #1d4ed8 0%, #4f46e5 100%);
            border: none; border-radius: 10px;
            color: #fff; font-weight: 600; font-size: 0.93rem;
            font-family: inherit; cursor: pointer;
            box-shadow: 0 4px 20px rgba(79,70,229,0.3);
            transition: all 0.2s;
        }
        button:hover {
            background: linear-gradient(135deg, #1a45c5 0%, #4338ca 100%);
            box-shadow: 0 6px 28px rgba(79,70,229,0.5);
            transform: translateY(-1px);
        }
        button:active { transform: translateY(0); }

        .footer {
            text-align: center; margin-top: 20px;
            color: #253555; font-size: 0.73rem; line-height: 1.8;
        }
        .foot-dot { color: #3a5580; margin: 0 5px; }
    </style>
</head>
<body>
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>

<div class="wrap">
    <div class="top-bar">
        <span class="top-bar-icon">&#9888;</span>
        <span><strong>RESTRICTED SYSTEM</strong> — Authorized personnel only. All access is monitored.</span>
    </div>

    <div class="card">
        <div class="logo">
            <div class="shield">&#128737;</div>
            <h1>System Gateway</h1>
            <div class="sub">Secure Access Portal &nbsp;&middot;&nbsp; Port 3000</div>
        </div>

        <hr>

        <div class="msg-box">
            {% if error %}
                <div class="error-msg">&#10005; &nbsp;{{ error }}</div>
            {% else %}
                <div class="notice-msg">Enter your credentials to proceed.</div>
            {% endif %}
        </div>

        <form id="loginForm" method="POST" action="/">
            <label>Username</label>
            <div class="field">
                <span class="field-icon">&#128100;</span>
                <input type="text" name="username" placeholder="Enter username" autocomplete="username" required>
            </div>
            <label>Password</label>
            <div class="field">
                <span class="field-icon">&#128274;</span>
                <input type="password" name="password" placeholder="Enter password" autocomplete="current-password" required>
            </div>
            <div id="loader"></div>
            <p id="authText">Authenticating&hellip;</p>
            <button type="submit" id="submitBtn">&#8594; &nbsp;Sign In</button>
        </form>

        <div class="footer">
            &#128275; SSL Encrypted
            <span class="foot-dot">&middot;</span>
            Session Monitored
            <span class="foot-dot">&middot;</span>
            Zero-Trust Policy
        </div>
    </div>
</div>

<script>
    document.getElementById("loginForm").addEventListener("submit", function() {
        document.getElementById("submitBtn").style.display = "none";
        document.getElementById("loader").style.display  = "block";
        document.getElementById("authText").style.display = "block";
    });
</script>
</body>
</html>
"""


def get_real_system_url(req):
    host_ip = req.host.split(':')[0]
    return f"http://{host_ip}:8080"


def get_honeypot_url(req):
    return f"http://{HONEYPOT_IP}:{HONEYPOT_PORT}"


def log_event(ip, username, attempts, decision):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if decision == "REAL":
        msg = f"[GATEWAY] SUCCESS login -> REAL SYSTEM | User: {username}"
    elif decision == "HONEYPOT":
        msg = f"[GATEWAY] HONEYPOT redirect after {attempts} failed attempts | IP: {ip} | User: {username}"
    elif decision == "FAIL":
        msg = f"[GATEWAY] FAILED login | IP: {ip} | User: {username} | Attempt: {attempts}"
    else:
        msg = f"[GATEWAY] {decision}"

    print(msg)
    with open("gateway_logs.txt", "a", encoding="utf-8") as f:
        f.write(f"{timestamp} | IP: {ip} | User: {username} | Attempts: {attempts} | Decision: {decision}\n")


@app.route("/", methods=["GET", "POST"])
def login():
    ip_address = request.remote_addr

    # Initialize per-IP tracking with a random threshold (5–10)
    if ip_address not in failed_attempts:
        failed_attempts[ip_address] = {
            'count': 0,
            'threshold': random.randint(5, 10)
        }

    attempts_info = failed_attempts[ip_address]

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # Realistic delay
        time.sleep(random.uniform(1.0, 2.0))

        # Check if threshold already hit BEFORE evaluating credentials
        if attempts_info['count'] >= attempts_info['threshold']:
            log_event(ip_address, username, attempts_info['count'], "HONEYPOT")
            failed_attempts[ip_address]['count'] = 0
            failed_attempts[ip_address]['threshold'] = random.randint(5, 10)
            return redirect(get_honeypot_url(request))

        # Validate against VALID_USERS
        if username in VALID_USERS and VALID_USERS[username] == password:
            log_event(ip_address, username, attempts_info['count'], "REAL")
            failed_attempts[ip_address]['count'] = 0
            return redirect(get_real_system_url(request))
        else:
            attempts_info['count'] += 1
            log_event(ip_address, username, attempts_info['count'], "FAIL")

            # Immediately redirect if this attempt crossed the threshold
            if attempts_info['count'] >= attempts_info['threshold']:
                log_event(ip_address, username, attempts_info['count'], "HONEYPOT")
                failed_attempts[ip_address]['count'] = 0
                failed_attempts[ip_address]['threshold'] = random.randint(5, 10)
                return redirect(get_honeypot_url(request))

            remaining = attempts_info['threshold'] - attempts_info['count']
            return render_template_string(
                LOGIN_TEMPLATE,
                error=f"Invalid credentials. {remaining} attempt(s) remaining."
            )

    return render_template_string(LOGIN_TEMPLATE, error=None)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)
