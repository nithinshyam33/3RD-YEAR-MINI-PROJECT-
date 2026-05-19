import time
import json
import os
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, send_file, make_response

app = Flask(__name__)

# --- Configuration & Storage ---
LOG_TXT_FILE = "honeypot_log.txt"
LOG_JSON_FILE = "honeypot_events.json"

# In-memory tracking for alerts
# Dictionary to track timestamps of requests per IP
request_tracker = {}
# Alert threshold: X requests within Y seconds
ALERT_THRESHOLD_COUNT = 5
ALERT_THRESHOLD_SECONDS = 10

# --- Helper Functions ---

def log_interaction(event_type, action, severity, is_alert=False):
    ip = request.remote_addr
    user_agent = request.user_agent.string
    timestamp = datetime.now().isoformat()
    route = request.path

    if is_alert:
        print(f"[ALERT] {action}")
        print(f"[ALERT] Suspicious behavior detected from IP: {ip}")
    else:
        print(f"[HONEYPOT] Intruder accessed system")
        print(f"[HONEYPOT] IP: {ip} accessed {route}")

    event_data = {
        "timestamp": timestamp,
        "ip": ip,
        "event_type": event_type,
        "action": action,
        "severity": severity,
        "route": route,
        "user_agent": user_agent
    }

    # Store JSON
    try:
        with open(LOG_JSON_FILE, "a") as f:
            f.write(json.dumps(event_data) + "\n")
    except Exception as e:
        print(f"Error writing to JSON log: {e}")

    # Store TXT
    try:
        with open(LOG_TXT_FILE, "a") as f:
            f.write(f"[{timestamp}] IP: {ip} | Route: {route} | Event: {event_type} | Action: {action} | Severity: {severity}\n")
    except Exception as e:
        print(f"Error writing to TXT log: {e}")

def check_for_alerts(ip):
    now = time.time()
    if ip not in request_tracker:
        request_tracker[ip] = []
    
    # Add current timestamp
    request_tracker[ip].append(now)
    
    # Remove timestamps older than the threshold
    request_tracker[ip] = [t for t in request_tracker[ip] if now - t <= ALERT_THRESHOLD_SECONDS]
    
    if len(request_tracker[ip]) > ALERT_THRESHOLD_COUNT:
        log_interaction("ALERT", "Possible data exfiltration or rapid scanning", "HIGH", is_alert=True)
        # Clear tracker to prevent continuous alert spamming for every subsequent request
        request_tracker[ip] = []


@app.before_request
def track_behavior():
    # Only track actual routes, ignore static if we had them (we use inline css)
    if not request.path.startswith('/static'):
        log_interaction("ACCESS", "Page visited", "INFO")
        check_for_alerts(request.remote_addr)

# --- Templates ---

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Admin Portal - System COMPROMISED</title>
    <style>
        :root {
            --bg-color: #121212;
            --sidebar-bg: #1e1e1e;
            --text-main: #e0e0e0;
            --text-muted: #888;
            --accent: #bb86fc;
            --danger: #cf6679;
            --success: #03dac6;
            --card-bg: #2d2d2d;
            --border: #333;
        }
        body {
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            display: flex;
            height: 100vh;
            overflow: hidden;
        }
        .sidebar {
            width: 250px;
            background-color: var(--sidebar-bg);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
        }
        .sidebar-header {
            padding: 20px;
            font-size: 1.2rem;
            font-weight: bold;
            border-bottom: 1px solid var(--border);
            color: var(--accent);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .nav-links {
            list-style: none;
            padding: 0;
            margin: 0;
            flex-grow: 1;
        }
        .nav-links li {
            border-bottom: 1px solid var(--border);
        }
        .nav-links a {
            display: block;
            padding: 15px 20px;
            color: var(--text-main);
            text-decoration: none;
            transition: background 0.2s;
        }
        .nav-links a:hover {
            background-color: rgba(187, 134, 252, 0.1);
            color: var(--accent);
            border-left: 3px solid var(--accent);
            padding-left: 17px;
        }
        .main-content {
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }
        .header {
            height: 60px;
            background-color: var(--sidebar-bg);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 30px;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.9rem;
            color: var(--text-muted);
        }
        .content-area {
            padding: 30px;
        }
        .page-title {
            margin-top: 0;
            margin-bottom: 30px;
            font-size: 1.8rem;
            font-weight: 300;
        }
        .card {
            background-color: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
            border: 1px solid var(--border);
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border);
        }
        th {
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
        }
        tr:hover {
            background-color: rgba(255,255,255,0.05);
        }
        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        .badge-success { background: rgba(3, 218, 198, 0.2); color: var(--success); }
        .badge-warning { background: rgba(207, 102, 121, 0.2); color: var(--danger); }
        .code-block {
            background: #111;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            color: #0f0;
            overflow-x: auto;
        }
        .download-btn {
            display: inline-block;
            background-color: var(--card-bg);
            border: 1px solid var(--accent);
            color: var(--accent);
            padding: 10px 15px;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.2s;
            margin-right: 10px;
            margin-bottom: 10px;
        }
        .download-btn:hover {
            background-color: var(--accent);
            color: #000;
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">
            Acme Corp Admin
        </div>
        <ul class="nav-links">
            <li><a href="/">Dashboard</a></li>
            <li><a href="/users">User Management</a></li>
            <li><a href="/database">Database Access</a></li>
            <li><a href="/logs">Server Logs</a></li>
            <li><a href="/backup">Backup System</a></li>
            <li style="margin-top: 20px; border-top: 1px solid var(--danger);"><a href="/config" style="color: var(--danger);">Configuration</a></li>
        </ul>
    </div>
    
    <div class="main-content">
        <div class="header">
            <div>Root Access Enabled - Terminal Session Active</div>
            <div class="user-info">
                <span>admin@acme-core-01</span>
                <span class="badge badge-warning">Elevated Privileges</span>
            </div>
        </div>
        <div class="content-area">
            {% block content %}{% endblock %}
        </div>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
    <h1 class="page-title">System Overview</h1>
    <div class="grid">
        <div class="card">
            <h3>System Status</h3>
            <p>Overall Health: <span class="badge badge-warning">WARNING</span></p>
            <p>Last Login Time: {{ now }}</p>
            <p>Active Root Sessions: 3</p>
            <p>Intrusion Detection: <span class="badge badge-warning">OFFLINE</span></p>
        </div>
        <div class="card">
            <h3>Resource Usage</h3>
            <p>CPU Usage: 87.4%</p>
            <div style="width: 100%; background: #444; height: 10px; border-radius: 5px; margin-bottom: 15px;">
                <div style="width: 87%; background: var(--danger); height: 100%; border-radius: 5px;"></div>
            </div>
            <p>Memory Usage: 14.2 GB / 16.0 GB</p>
            <div style="width: 100%; background: #444; height: 10px; border-radius: 5px;">
                <div style="width: 89%; background: var(--danger); height: 100%; border-radius: 5px;"></div>
            </div>
        </div>
    </div>
    <div class="card">
        <h3>Recent Critical Alerts</h3>
        <table>
            <tr>
                <th>Time</th>
                <th>Alert Component</th>
                <th>Description</th>
                <th>Severity</th>
            </tr>
            <tr>
                <td>{{ time_1 }}</td>
                <td>Firewall</td>
                <td>Multiple failed SSH logins root/admin</td>
                <td><span class="badge badge-warning">CRITICAL</span></td>
            </tr>
            <tr>
                <td>{{ time_2 }}</td>
                <td>Auth Service</td>
                <td>Unauthorized key added to authorized_keys</td>
                <td><span class="badge badge-warning">CRITICAL</span></td>
            </tr>
            <tr>
                <td>{{ time_3 }}</td>
                <td>Web Server</td>
                <td>Suspicious payload detected in memory</td>
                <td><span class="badge badge-warning">HIGH</span></td>
            </tr>
        </table>
    </div>
''')

USERS_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
    <h1 class="page-title">User Management</h1>
    <div class="card">
        <h3>Employee Directory & Access Control</h3>
        <table>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Role</th>
                <th>Department</th>
                <th>Password Hash (Bcrypt)</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>001</td>
                <td>admin_a.smith</td>
                <td>Super Admin</td>
                <td>IT Infrastructure</td>
                <td style="font-family: monospace; color: var(--text-muted);">$2a$12$R9Z3hGq5...xZ1e</td>
                <td><span class="badge badge-success">Active</span></td>
            </tr>
            <tr>
                <td>002</td>
                <td>j.doe</td>
                <td>DBA</td>
                <td>Database Admin</td>
                <td style="font-family: monospace; color: var(--text-muted);">$2a$12$K8yUiM2a...aQ9p</td>
                <td><span class="badge badge-success">Active</span></td>
            </tr>
            <tr>
                <td>003</td>
                <td>m.jackson</td>
                <td>VP Finance</td>
                <td>Executive</td>
                <td style="font-family: monospace; color: var(--text-muted);">$2a$12$L2wNeT9v...wF2x</td>
                <td><span class="badge badge-success">Active</span></td>
            </tr>
            <tr>
                <td>004</td>
                <td>s.williams</td>
                <td>HR Director</td>
                <td>Human Resources</td>
                <td style="font-family: monospace; color: var(--text-muted);">$2a$12$P1qRsT5b...bN4m</td>
                <td><span class="badge badge-success">Active</span></td>
            </tr>
            <tr>
                <td>089</td>
                <td>svc_backup_acct</td>
                <td>Service Account</td>
                <td>Automated Ops</td>
                <td style="font-family: monospace; color: var(--text-muted);">$2a$12$V9zBxN7m...cZ7n</td>
                <td><span class="badge badge-success">Active</span></td>
            </tr>
        </table>
    </div>
''')

DATABASE_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
    <h1 class="page-title">Database Access [PROD-DB-01]</h1>
    <div class="grid">
        <div class="card">
            <h3>Connection Status</h3>
            <p>Status: <span class="badge badge-success">CONNECTED</span></p>
            <p>Driver: PostgreSQL 14.2</p>
            <p>Uptime: 124 days, 14:02:11</p>
            <p>Active Queries: 12</p>
        </div>
    </div>
    <div class="card">
        <h3>Available Schemas & Tables</h3>
        <table>
            <tr>
                <th>Schema</th>
                <th>Table Name</th>
                <th>Row Count</th>
                <th>Size</th>
                <th>Actions</th>
            </tr>
            <tr>
                <td>public</td>
                <td>users</td>
                <td>14,592</td>
                <td>2.4 MB</td>
                <td><a href="#" style="color: var(--accent);">View Records</a></td>
            </tr>
            <tr>
                <td>public</td>
                <td>customer_credit_cards</td>
                <td>89,104</td>
                <td>18.9 MB</td>
                <td><a href="#" style="color: var(--accent);">View Records</a></td>
            </tr>
            <tr>
                <td>public</td>
                <td>financial_transactions</td>
                <td>1,492,055</td>
                <td>450.2 MB</td>
                <td><a href="#" style="color: var(--accent);">View Records</a></td>
            </tr>
            <tr>
                <td>hr</td>
                <td>employee_salaries</td>
                <td>450</td>
                <td>120 KB</td>
                <td><a href="#" style="color: var(--accent);">View Records</a></td>
            </tr>
            <tr>
                <td>admin</td>
                <td>access_logs</td>
                <td>8,992,111</td>
                <td>1.2 GB</td>
                <td><a href="#" style="color: var(--accent);">View Records</a></td>
            </tr>
        </table>
    </div>
''')

LOGS_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
    <h1 class="page-title">Server Logs</h1>
    <div class="card">
        <h3>System Auth Logs (/var/log/auth.log)</h3>
        <div class="code-block">
[{{ time_1 }}] sshd[14920]: Accepted publickey for root from 192.168.1.104 port 49211 ssh2: RSA SHA256:x/...
[{{ time_1 }}] sshd[14920]: pam_unix(sshd:session): session opened for user root by (uid=0)
[{{ time_2 }}] sudo: admin_a.smith : TTY=pts/0 ; PWD=/home/admin_a.smith ; USER=root ; COMMAND=/bin/bash
[{{ time_2 }}] su: pam_unix(su:session): session opened for user root by admin_a.smith(uid=0)
[{{ time_3 }}] kernel: [12345.6789] TCP: Possible SYN flooding on port 443. Sending cookies.
        </div>
    </div>
    <div class="card">
        <h3>Application Logs (Production)</h3>
        <div class="code-block" style="color: #bbb;">
[INFO] [{{ time_1 }}] Worker 4 processing batch job 99120
[WARN] [{{ time_2 }}] High latency detected on database connection pool (1400ms)
[ERROR] [{{ time_3 }}] Unhandled Exception in payment processing module: ConnectionRefusedError
[INFO] [{{ now }}] Re-initializing configuration from S3 bucket...
        </div>
    </div>
''')

BACKUP_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
    <h1 class="page-title">Backup System</h1>
    <div class="card">
        <h3>Available Archives</h3>
        <p>Warning: Downloading full archives may cause high I/O wait times.</p>
        
        <div style="margin-top: 20px;">
            <a href="/backup/download?file=database_backup.sql" class="download-btn">
                🖴 database_backup.sql (4.2 GB)
            </a>
            <a href="/backup/download?file=users_backup.zip" class="download-btn">
                🗀 users_backup.zip (850 MB)
            </a>
            <a href="/backup/download?file=config_backup.env" class="download-btn">
                ⚙ config_backup.env (2 KB)
            </a>
            <a href="/backup/download?file=ssh_keys_archive.tar.gz" class="download-btn">
                🔑 ssh_keys_archive.tar.gz (1 MB)
            </a>
        </div>
    </div>
    <div class="card">
        <h3>Automated Backup Schedule</h3>
        <table>
            <tr>
                <th>Job Name</th>
                <th>Schedule (CRON)</th>
                <th>Last Run</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>Full DB Dump</td>
                <td>0 2 * * *</td>
                <td>Today, 02:00:15</td>
                <td><span class="badge badge-success">OK</span></td>
            </tr>
            <tr>
                <td>User Data Delta</td>
                <td>0 * * * *</td>
                <td>Today, {{ hour }}:00:05</td>
                <td><span class="badge badge-success">OK</span></td>
            </tr>
        </table>
    </div>
''')

CONFIG_TEMPLATE = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', '''
    <h1 class="page-title" style="color: var(--danger);">Critical Configuration Variables</h1>
    <div class="card" style="border-color: var(--danger);">
        <h3 style="color: var(--danger);">Environment Variables (.env)</h3>
        <p style="color: var(--text-muted);">Loaded from secure vault. Do not share.</p>
        <div class="code-block" style="color: #e0e0e0;">
# Database Configuration
POSTGRES_USER=admin_db_super
POSTGRES_PASSWORD=SuperSecr3t!AdminPass_9921
POSTGRES_DB=acme_production_main
POSTGRES_HOST=10.0.5.112

# API Integration Keys (Stripe, Twilio, SendGrid)
STRIPE_SECRET_KEY=sk_live_51HzX991A...
STRIPE_WEBHOOK_SECRET=whsec_8912nsj...
TWILIO_AUTH_TOKEN=aa9128nx...
SENDGRID_API_KEY=SG.82ns1xZ...

# Application Secrets
FLASK_SECRET_KEY=x9a!@#$njA921kndA!912lmnASD
JWT_SECRET=super_secret_jwt_signing_key_4412
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        </div>
    </div>
''')

# --- Routes ---

def get_times():
    now = datetime.now()
    t1 = now.replace(hour=(now.hour - 2) % 24).strftime('%b %d %H:%M:%S')
    t2 = now.replace(hour=(now.hour - 1) % 24).strftime('%b %d %H:%M:%S')
    t3 = now.replace(minute=(now.minute - 15) % 60).strftime('%b %d %H:%M:%S')
    return {
        'now': now.strftime('%Y-%m-%d %H:%M:%S'),
        'time_1': t1,
        'time_2': t2,
        'time_3': t3,
        'hour': str(now.hour).zfill(2)
    }

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE, **get_times())

@app.route('/users')
def users():
    return render_template_string(USERS_TEMPLATE)

@app.route('/database')
def database():
    return render_template_string(DATABASE_TEMPLATE)

@app.route('/logs')
def logs():
    return render_template_string(LOGS_TEMPLATE, **get_times())

@app.route('/backup')
def backup():
    return render_template_string(BACKUP_TEMPLATE, **get_times())

@app.route('/backup/download')
def download_backup():
    filename = request.args.get('file', 'unknown_file')
    # Trigger an alert specifically for data exfiltration attempts
    log_interaction("DL_ATTEMPT", f"Attempted to download {filename}", "CRITICAL", is_alert=True)
    
    # Simulate a delay for realism
    time.sleep(1)
    
    # Return fake data pretending to be the file
    fake_content = f"-- FAKE BACKUP CONTENT FOR {filename} --\\n" * 100
    response = make_response(fake_content)
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response

@app.route('/config')
def config():
    return render_template_string(CONFIG_TEMPLATE)

if __name__ == '__main__':
    print("================================================================")
    print(" [!] HONEYPOT SERVER STARTING")
    print(" [!] Emulating compromised enterprise administration portal")
    print(" [!] All unauthorized access will be logged and analyzed")
    print("================================================================")
    app.run(host="0.0.0.0", port=5000)
