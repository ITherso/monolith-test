# cyberapp/routes/vulnerable.py
# ⚠️ VULNERABLE BY DESIGN - RED TEAM TRAINING MODULE ⚠️
# Bu modül kasıtlı olarak güvensiz yazılmıştır. Üretim ortamında KULLANMAYIN!

import os
import pickle
import base64
import subprocess
import yaml
import jwt
import requests
from flask import Blueprint, request, jsonify, render_template_string, session, send_file, redirect

from cyberapp.models.db import db_conn

vulnerable_bp = Blueprint("vulnerable", __name__, url_prefix="/vuln")

# ==========================================
# 1. SQL INJECTION - Login Bypass
# ==========================================
@vulnerable_bp.route("/sqli/login", methods=["GET", "POST"])
def sqli_login():
    """
    SQL Injection vulnerable login.
    Payload: ' OR '1'='1' --
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        # ⚠️ VULNERABLE: Raw SQL with string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            with db_conn() as conn:
                result = conn.execute(query).fetchone()
                if result:
                    session["logged_in"] = True
                    session["user"] = result[1] if len(result) > 1 else username
                    session["role"] = "admin"
                    return jsonify({"success": True, "message": "Login successful!", "query": query})
                return jsonify({"success": False, "message": "Invalid credentials", "query": query})
        except Exception as e:
            return jsonify({"success": False, "error": str(e), "query": query})
    
    return '''
    <h2>🔓 SQL Injection Lab - Login</h2>
    <form method="post">
        <input name="username" placeholder="Username"><br><br>
        <input name="password" type="password" placeholder="Password"><br><br>
        <button type="submit">Login</button>
    </form>
    <p>💡 Hint: Try <code>' OR '1'='1' --</code></p>
    '''


@vulnerable_bp.route("/sqli/search")
def sqli_search():
    """
    SQL Injection in search - UNION based
    Payload: ' UNION SELECT 1,2,3,4,5--
    """
    query = request.args.get("q", "")
    
    # ⚠️ VULNERABLE: Direct string interpolation
    sql = f"SELECT id, target, status, date, user_id FROM scans WHERE target LIKE '%{query}%'"
    
    try:
        with db_conn() as conn:
            results = conn.execute(sql).fetchall()
            return jsonify({"results": results, "query": sql})
    except Exception as e:
        return jsonify({"error": str(e), "query": sql})


# ==========================================
# 2. COMMAND INJECTION - Ping/Nslookup
# ==========================================
@vulnerable_bp.route("/cmdi/ping", methods=["GET", "POST"])
def cmdi_ping():
    """
    Command Injection via ping.
    Payload: 127.0.0.1; cat /etc/passwd
    """
    output = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        
        # ⚠️ VULNERABLE: Direct shell command execution
        cmd = f"ping -c 2 {host}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
            output = output.decode("utf-8", errors="ignore")
        except subprocess.CalledProcessError as e:
            output = e.output.decode("utf-8", errors="ignore")
        except Exception as e:
            output = str(e)
    
    return f'''
    <h2>🖥️ Command Injection Lab - Network Tools</h2>
    <form method="post">
        <input name="host" placeholder="Enter IP/hostname" value="127.0.0.1"><br><br>
        <button type="submit">Ping</button>
    </form>
    <p>💡 Hint: Try <code>127.0.0.1; cat /etc/passwd</code> or <code>127.0.0.1 | id</code></p>
    <pre>{output}</pre>
    '''


@vulnerable_bp.route("/cmdi/nslookup", methods=["GET", "POST"])
def cmdi_nslookup():
    """
    Command Injection via nslookup.
    Payload: google.com; whoami
    """
    output = ""
    if request.method == "POST":
        domain = request.form.get("domain", "")
        
        # ⚠️ VULNERABLE: os.system with user input
        cmd = f"nslookup {domain}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
            output = output.decode("utf-8", errors="ignore")
        except Exception as e:
            output = str(e)
    
    return f'''
    <h2>🔍 Command Injection Lab - DNS Lookup</h2>
    <form method="post">
        <input name="domain" placeholder="Enter domain" value="google.com"><br><br>
        <button type="submit">Lookup</button>
    </form>
    <p>💡 Hint: Try <code>google.com; whoami</code> or <code>$(cat /etc/passwd)</code></p>
    <pre>{output}</pre>
    '''


# ==========================================
# 3. SSTI - Server Side Template Injection
# ==========================================
@vulnerable_bp.route("/ssti/greeting")
def ssti_greeting():
    """
    SSTI via Jinja2 render_template_string.
    Payload: {{config}} or {{''.__class__.__mro__[1].__subclasses__()}}
    """
    name = request.args.get("name", "Guest")
    
    # ⚠️ VULNERABLE: User input directly in template
    template = f"<h2>Hello, {name}!</h2><p>Welcome to SSTI Lab</p>"
    
    try:
        return render_template_string(template)
    except Exception as e:
        return f"Error: {e}"


@vulnerable_bp.route("/ssti/email")
def ssti_email():
    """
    SSTI in email template preview.
    Payload: {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
    """
    subject = request.args.get("subject", "Hello")
    body = request.args.get("body", "Welcome!")
    
    # ⚠️ VULNERABLE: Multiple user inputs in template
    template = f'''
    <div style="border:1px solid #ccc; padding:20px;">
        <h3>Email Preview</h3>
        <p><strong>Subject:</strong> {subject}</p>
        <p><strong>Body:</strong> {body}</p>
    </div>
    <p>💡 Hint: Try <code>{{{{config}}}}</code> or <code>{{{{7*7}}}}</code></p>
    '''
    
    try:
        return render_template_string(template)
    except Exception as e:
        return f"Error: {e}"


# ==========================================
# 4. INSECURE DESERIALIZATION
# ==========================================
@vulnerable_bp.route("/deserial/pickle", methods=["GET", "POST"])
def deserial_pickle():
    """
    Insecure pickle deserialization.
    Generate payload: base64.b64encode(pickle.dumps(exploit_class))
    """
    result = ""
    if request.method == "POST":
        data = request.form.get("data", "")
        
        try:
            # ⚠️ VULNERABLE: Unsafe pickle.loads
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            result = f"Deserialized object: {obj}"
        except Exception as e:
            result = f"Error: {e}"
    
    # Example safe payload for testing
    safe_payload = base64.b64encode(pickle.dumps({"test": "data"})).decode()
    
    return f'''
    <h2>🧪 Insecure Deserialization Lab - Pickle</h2>
    <form method="post">
        <textarea name="data" rows="5" cols="50" placeholder="Base64 encoded pickle data">{safe_payload}</textarea><br><br>
        <button type="submit">Deserialize</button>
    </form>
    <p>💡 Safe test payload: <code>{safe_payload}</code></p>
    <p>⚠️ This can lead to RCE with malicious pickle payload!</p>
    <pre>{result}</pre>
    '''


@vulnerable_bp.route("/deserial/yaml", methods=["GET", "POST"])
def deserial_yaml():
    """
    Insecure YAML deserialization.
    Payload: !!python/os.system 'id'
    """
    result = ""
    if request.method == "POST":
        data = request.form.get("data", "")
        
        try:
            # ⚠️ VULNERABLE: yaml.load without Loader (uses unsafe Loader)
            obj = yaml.load(data, Loader=yaml.UnsafeLoader)
            result = f"Parsed YAML: {obj}"
        except Exception as e:
            result = f"Error: {e}"
    
    return f'''
    <h2>🧪 Insecure Deserialization Lab - YAML</h2>
    <form method="post">
        <textarea name="data" rows="5" cols="50" placeholder="YAML data">name: test
value: 123</textarea><br><br>
        <button type="submit">Parse YAML</button>
    </form>
    <p>💡 Hint: Try <code>!!python/object/apply:os.system ["id"]</code></p>
    <pre>{result}</pre>
    '''


# ==========================================
# 5. JWT VULNERABILITIES
# ==========================================
JWT_WEAK_SECRET = "secret"  # ⚠️ VULNERABLE: Weak secret

@vulnerable_bp.route("/jwt/login", methods=["GET", "POST"])
def jwt_login():
    """
    JWT with weak secret and algorithm confusion.
    """
    if request.method == "POST":
        username = request.form.get("username", "guest")
        role = request.form.get("role", "user")
        
        # ⚠️ VULNERABLE: Weak secret, predictable payload
        token = jwt.encode(
            {"username": username, "role": role, "admin": False},
            JWT_WEAK_SECRET,
            algorithm="HS256"
        )
        
        return jsonify({
            "token": token,
            "hint": "Secret is 'secret'. Try changing 'admin' to true!"
        })
    
    return '''
    <h2>🔑 JWT Vulnerability Lab</h2>
    <form method="post">
        <input name="username" placeholder="Username" value="guest"><br><br>
        <input name="role" placeholder="Role" value="user"><br><br>
        <button type="submit">Get Token</button>
    </form>
    <p>💡 Hints:</p>
    <ul>
        <li>Secret key is: <code>secret</code></li>
        <li>Try algorithm confusion (alg: none)</li>
        <li>Modify payload and re-sign</li>
    </ul>
    '''


@vulnerable_bp.route("/jwt/verify")
def jwt_verify():
    """
    JWT verification with algorithm confusion vulnerability.
    """
    token = request.args.get("token", "")
    
    try:
        # ⚠️ VULNERABLE: algorithms list includes 'none'
        decoded = jwt.decode(token, JWT_WEAK_SECRET, algorithms=["HS256", "none"])
        
        if decoded.get("admin") == True:
            return jsonify({"success": True, "message": "Welcome Admin!", "decoded": decoded})
        return jsonify({"success": False, "message": "Access denied", "decoded": decoded})
    except Exception as e:
        return jsonify({"error": str(e)})


# ==========================================
# 6. IDOR - Insecure Direct Object Reference
# ==========================================
@vulnerable_bp.route("/idor/profile/<int:user_id>")
def idor_profile(user_id):
    """
    IDOR - Access any user's profile by changing ID.
    """
    # ⚠️ VULNERABLE: No authorization check
    try:
        with db_conn() as conn:
            # Simulated user data
            users = {
                1: {"id": 1, "username": "admin", "role": "admin", "email": "admin@monolith.local", "secret": "FLAG{IDOR_ADMIN_ACCESS}"},
                2: {"id": 2, "username": "analyst", "role": "analyst", "email": "analyst@monolith.local", "secret": "analyst_secret_data"},
                3: {"id": 3, "username": "guest", "role": "guest", "email": "guest@monolith.local", "secret": "guest_data"},
            }
            
            user = users.get(user_id, {"error": "User not found"})
            return jsonify(user)
    except Exception as e:
        return jsonify({"error": str(e)})


@vulnerable_bp.route("/idor/document/<path:filename>")
def idor_document(filename):
    """
    IDOR + Path Traversal in document access.
    Payload: ../../../etc/passwd
    """
    # ⚠️ VULNERABLE: No path validation
    base_path = "/tmp/documents"
    file_path = os.path.join(base_path, filename)
    
    try:
        if os.path.exists(file_path):
            return send_file(file_path)
        # Try without base path restriction
        if os.path.exists(filename):
            return send_file(filename)
        return f"File not found: {filename}", 404
    except Exception as e:
        return f"Error: {e}", 500


# ==========================================
# 7. FILE UPLOAD - Unrestricted
# ==========================================
UPLOAD_FOLDER = "/tmp/uploads"

@vulnerable_bp.route("/upload", methods=["GET", "POST"])
def file_upload():
    """
    Unrestricted file upload - allows webshell.
    """
    message = ""
    if request.method == "POST":
        if "file" not in request.files:
            message = "No file uploaded"
        else:
            file = request.files["file"]
            if file.filename:
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                
                # ⚠️ VULNERABLE: No file type validation, no filename sanitization
                filepath = os.path.join(UPLOAD_FOLDER, file.filename)
                file.save(filepath)
                message = f"File uploaded: {filepath}"
    
    return f'''
    <h2>📁 Unrestricted File Upload Lab</h2>
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file"><br><br>
        <button type="submit">Upload</button>
    </form>
    <p>💡 Hint: Try uploading a PHP/Python webshell!</p>
    <p>{message}</p>
    '''


@vulnerable_bp.route("/uploads/<path:filename>")
def serve_upload(filename):
    """
    Serve uploaded files - can execute webshells.
    """
    # ⚠️ VULNERABLE: Serves any file type
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(filepath):
        return send_file(filepath)
    return "File not found", 404


# ==========================================
# 8. SSRF - Server Side Request Forgery
# ==========================================
@vulnerable_bp.route("/ssrf/fetch")
def ssrf_fetch():
    """
    SSRF - Fetch any URL including internal services.
    Payload: http://169.254.169.254/latest/meta-data/
    """
    url = request.args.get("url", "")
    result = ""
    
    if url:
        try:
            # ⚠️ VULNERABLE: No URL validation, follows redirects
            response = requests.get(url, timeout=5, allow_redirects=True)
            result = response.text[:5000]  # Limit output
        except Exception as e:
            result = f"Error: {e}"
    
    return f'''
    <h2>🌐 SSRF Lab - URL Fetcher</h2>
    <form method="get">
        <input name="url" placeholder="Enter URL" value="{url}" style="width:400px"><br><br>
        <button type="submit">Fetch</button>
    </form>
    <p>💡 Hints:</p>
    <ul>
        <li>AWS metadata: <code>http://169.254.169.254/latest/meta-data/</code></li>
        <li>Internal services: <code>http://localhost:6379</code> (Redis)</li>
        <li>File protocol: <code>file:///etc/passwd</code></li>
    </ul>
    <pre>{result}</pre>
    '''


@vulnerable_bp.route("/ssrf/webhook", methods=["POST"])
def ssrf_webhook():
    """
    SSRF via webhook callback.
    """
    callback_url = request.json.get("callback_url", "") if request.is_json else request.form.get("callback_url", "")
    
    if callback_url:
        try:
            # ⚠️ VULNERABLE: Arbitrary callback
            response = requests.post(callback_url, json={"status": "completed"}, timeout=5)
            return jsonify({"success": True, "response": response.status_code})
        except Exception as e:
            return jsonify({"error": str(e)})
    
    return jsonify({"error": "No callback_url provided"})


# ==========================================
# 9. BROKEN ACCESS CONTROL
# ==========================================
@vulnerable_bp.route("/admin/users")
def admin_users():
    """
    Broken Access Control - No role verification.
    """
    # ⚠️ VULNERABLE: No admin check
    users = [
        {"id": 1, "username": "admin", "role": "admin", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
        {"id": 2, "username": "analyst", "role": "analyst", "password_hash": "e99a18c428cb38d5f260853678922e03"},
    ]
    return jsonify({"users": users, "hint": "This endpoint should require admin role!"})


@vulnerable_bp.route("/admin/delete/<int:user_id>", methods=["DELETE", "GET"])
def admin_delete_user(user_id):
    """
    Broken Access Control - Delete any user.
    """
    # ⚠️ VULNERABLE: No authorization, accepts GET
    return jsonify({
        "success": True, 
        "message": f"User {user_id} deleted (simulated)",
        "hint": "No admin verification performed!"
    })


@vulnerable_bp.route("/admin/config")
def admin_config():
    """
    Sensitive config exposure.
    """
    # ⚠️ VULNERABLE: Exposes sensitive configuration
    config = {
        "SECRET_KEY": "supersecretkey123",
        "DATABASE_URL": "sqlite:///monolith_supreme.db",
        "ADMIN_PASSWORD": "admin123",
        "API_KEY": "sk-1234567890abcdef",
        "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }
    return jsonify(config)


# ==========================================
# 10. WEAK PASSWORD RESET
# ==========================================
@vulnerable_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """
    Weak password reset - predictable token.
    """
    if request.method == "POST":
        email = request.form.get("email", "")
        
        # ⚠️ VULNERABLE: Predictable reset token (just base64 of email)
        import hashlib
        token = base64.b64encode(email.encode()).decode()
        
        return f'''
        <h2>Password Reset</h2>
        <p>Reset link sent to: {email}</p>
        <p>Reset URL: <a href="/vuln/reset-password?token={token}">/vuln/reset-password?token={token}</a></p>
        <p>💡 Hint: Token is just base64 of email!</p>
        '''
    
    return '''
    <h2>🔐 Weak Password Reset Lab</h2>
    <form method="post">
        <input name="email" placeholder="Email" value="admin@monolith.local"><br><br>
        <button type="submit">Reset Password</button>
    </form>
    '''


@vulnerable_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """
    Reset password with weak token validation.
    """
    token = request.args.get("token", "")
    
    if request.method == "POST":
        new_password = request.form.get("password", "")
        # ⚠️ VULNERABLE: Accepts any token
        return f"Password reset to: {new_password} (simulated)"
    
    try:
        email = base64.b64decode(token).decode()
        return f'''
        <h2>Reset Password for: {email}</h2>
        <form method="post">
            <input name="password" type="password" placeholder="New Password"><br><br>
            <button type="submit">Reset</button>
        </form>
        '''
    except:
        return "Invalid token"


# ==========================================
# VULNERABILITY INDEX PAGE
# ==========================================
@vulnerable_bp.route("/")
def vuln_index():
    """
    Index page listing all vulnerabilities.
    """
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔓 Vulnerable Labs - MONOLITH</title>
        <style>
            body { font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
            h1 { color: #ff6b6b; }
            h2 { color: #4ecdc4; margin-top: 30px; }
            a { color: #95e1d3; }
            .lab { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; }
            .warning { background: #ff6b6b; color: #000; padding: 10px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>🔓 MONOLITH Vulnerable Labs</h1>
        <div class="warning">
            ⚠️ WARNING: These endpoints are intentionally vulnerable for red team training!
        </div>
        
        <h2>1. SQL Injection</h2>
        <div class="lab">
            <a href="/vuln/sqli/login">→ SQLi Login Bypass</a><br>
            <a href="/vuln/sqli/search?q=test">→ SQLi Search (UNION)</a>
        </div>
        
        <h2>2. Command Injection</h2>
        <div class="lab">
            <a href="/vuln/cmdi/ping">→ Command Injection - Ping</a><br>
            <a href="/vuln/cmdi/nslookup">→ Command Injection - NSLookup</a>
        </div>
        
        <h2>3. Server Side Template Injection (SSTI)</h2>
        <div class="lab">
            <a href="/vuln/ssti/greeting?name=Guest">→ SSTI Greeting</a><br>
            <a href="/vuln/ssti/email?subject=Test&body=Hello">→ SSTI Email Preview</a>
        </div>
        
        <h2>4. Insecure Deserialization</h2>
        <div class="lab">
            <a href="/vuln/deserial/pickle">→ Pickle Deserialization</a><br>
            <a href="/vuln/deserial/yaml">→ YAML Deserialization</a>
        </div>
        
        <h2>5. JWT Vulnerabilities</h2>
        <div class="lab">
            <a href="/vuln/jwt/login">→ JWT Login (Weak Secret)</a><br>
            <a href="/vuln/jwt/verify?token=">→ JWT Verify (Algorithm Confusion)</a>
        </div>
        
        <h2>6. IDOR & Path Traversal</h2>
        <div class="lab">
            <a href="/vuln/idor/profile/1">→ IDOR Profile (Try /2, /3)</a><br>
            <a href="/vuln/idor/document/test.txt">→ Path Traversal</a>
        </div>
        
        <h2>7. File Upload</h2>
        <div class="lab">
            <a href="/vuln/upload">→ Unrestricted File Upload</a>
        </div>
        
        <h2>8. SSRF</h2>
        <div class="lab">
            <a href="/vuln/ssrf/fetch?url=http://localhost">→ SSRF URL Fetcher</a>
        </div>
        
        <h2>9. Broken Access Control</h2>
        <div class="lab">
            <a href="/vuln/admin/users">→ User List (No Auth)</a><br>
            <a href="/vuln/admin/delete/1">→ Delete User (No Auth)</a><br>
            <a href="/vuln/admin/config">→ Config Exposure</a>
        </div>
        
        <h2>10. Weak Password Reset</h2>
        <div class="lab">
            <a href="/vuln/forgot-password">→ Forgot Password (Predictable Token)</a>
        </div>
    </body>
    </html>
    '''
