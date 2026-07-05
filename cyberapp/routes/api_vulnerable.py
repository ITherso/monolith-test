# cyberapp/routes/api_vulnerable.py
# ⚠️ VULNERABLE API ENDPOINTS - RED TEAM TRAINING ⚠️

import os
import pickle
import base64
import jwt
from flask import Blueprint, request, jsonify
from functools import wraps

api_vuln_bp = Blueprint("api_vuln", __name__, url_prefix="/api/v1")

# ⚠️ VULNERABLE: Weak JWT Secret
JWT_SECRET = "monolith_secret_2024"

# ==========================================
# JWT Authentication (Weak)
# ==========================================
def jwt_required_weak(f):
    """
    ⚠️ VULNERABLE: Accepts 'none' algorithm
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Token required"}), 401
        try:
            # ⚠️ VULNERABLE: Accepts 'none' algorithm
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256", "HS384", "HS512", "none"])
            request.jwt_data = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception as e:
            return jsonify({"error": str(e)}), 401
        return f(*args, **kwargs)
    return decorated


@api_vuln_bp.route("/auth/token", methods=["POST"])
def get_token():
    """
    Get JWT token with weak secret.
    """
    data = request.get_json() or {}
    username = data.get("username", "guest")
    
    # ⚠️ VULNERABLE: No password verification, weak secret
    token = jwt.encode({
        "username": username,
        "role": "user",
        "admin": False,
        "kid": "key1"  # ⚠️ VULNERABLE: kid injection possible
    }, JWT_SECRET, algorithm="HS256")
    
    return jsonify({
        "token": token,
        "hint": "Secret is 'monolith_secret_2024'. Try algorithm:none or modify claims!"
    })


@api_vuln_bp.route("/auth/verify", methods=["GET"])
@jwt_required_weak
def verify_token():
    """
    Verify JWT - vulnerable to algorithm confusion.
    """
    if request.jwt_data.get("admin") == True:
        return jsonify({"message": "Welcome Admin!", "flag": "FLAG{JWT_ALGORITHM_BYPASS}", "data": request.jwt_data})
    return jsonify({"message": "Access denied", "data": request.jwt_data})


# ==========================================
# IDOR in API
# ==========================================
@api_vuln_bp.route("/users/<int:user_id>")
def get_user(user_id):
    """
    ⚠️ VULNERABLE: No authorization check - IDOR
    """
    users = {
        1: {"id": 1, "username": "admin", "email": "admin@monolith.local", "role": "admin", "api_key": "sk-admin-12345-secret"},
        2: {"id": 2, "username": "analyst", "email": "analyst@monolith.local", "role": "analyst", "api_key": "sk-analyst-67890"},
        3: {"id": 3, "username": "guest", "email": "guest@monolith.local", "role": "guest", "api_key": "sk-guest-xxxxx"},
    }
    user = users.get(user_id)
    if user:
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404


@api_vuln_bp.route("/users/<int:user_id>/secrets")
def get_user_secrets(user_id):
    """
    ⚠️ VULNERABLE: Exposes sensitive data without auth
    """
    secrets = {
        1: {"user_id": 1, "ssh_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...(truncated)", "db_password": "sup3r_s3cr3t_db"},
        2: {"user_id": 2, "ssh_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIC...(truncated)", "db_password": "analyst_db_pass"},
    }
    secret = secrets.get(user_id)
    if secret:
        return jsonify(secret)
    return jsonify({"error": "No secrets found"}), 404


# ==========================================
# Mass Assignment
# ==========================================
@api_vuln_bp.route("/users/register", methods=["POST"])
def register_user():
    """
    ⚠️ VULNERABLE: Mass assignment - can set 'role' and 'admin' fields
    """
    data = request.get_json() or {}
    
    # ⚠️ VULNERABLE: Accepts all fields from user input
    new_user = {
        "id": 999,
        "username": data.get("username", "newuser"),
        "email": data.get("email", "new@example.com"),
        "role": data.get("role", "guest"),  # ⚠️ Should not be user-controlled
        "admin": data.get("admin", False),  # ⚠️ Should not be user-controlled
        "verified": data.get("verified", False),  # ⚠️ Should not be user-controlled
    }
    
    return jsonify({
        "message": "User registered",
        "user": new_user,
        "hint": "Try adding 'role':'admin' or 'admin':true to your request!"
    })


# ==========================================
# GraphQL-like Introspection (Info Disclosure)
# ==========================================
@api_vuln_bp.route("/schema")
def api_schema():
    """
    ⚠️ VULNERABLE: Exposes internal API structure
    """
    schema = {
        "endpoints": [
            {"path": "/api/v1/auth/token", "method": "POST", "auth": False},
            {"path": "/api/v1/auth/verify", "method": "GET", "auth": "JWT"},
            {"path": "/api/v1/users/{id}", "method": "GET", "auth": False, "note": "IDOR possible"},
            {"path": "/api/v1/users/{id}/secrets", "method": "GET", "auth": False, "note": "Sensitive data"},
            {"path": "/api/v1/users/register", "method": "POST", "auth": False, "note": "Mass assignment"},
            {"path": "/api/v1/admin/exec", "method": "POST", "auth": "JWT", "note": "Command execution"},
            {"path": "/api/v1/internal/debug", "method": "GET", "auth": False, "note": "Debug info"},
        ],
        "jwt_secret_hint": "monolith_secret_2024",
        "admin_creds_hint": "admin / admin123",
    }
    return jsonify(schema)


# ==========================================
# Debug Endpoint (Info Disclosure)
# ==========================================
@api_vuln_bp.route("/internal/debug")
def internal_debug():
    """
    ⚠️ VULNERABLE: Exposes environment and config
    """
    import sys
    debug_info = {
        "python_version": sys.version,
        "environment": dict(os.environ),
        "cwd": os.getcwd(),
        "user": os.getenv("USER"),
        "path": os.getenv("PATH"),
        "database": "monolith_supreme.db",
        "secret_key": "supersecretkey123",
    }
    return jsonify(debug_info)


# ==========================================
# Command Execution via API
# ==========================================
@api_vuln_bp.route("/admin/exec", methods=["POST"])
@jwt_required_weak
def admin_exec():
    """
    ⚠️ VULNERABLE: Command injection via API
    """
    data = request.get_json() or {}
    command = data.get("command", "")
    
    if not command:
        return jsonify({"error": "No command provided"})
    
    # ⚠️ VULNERABLE: Direct command execution
    import subprocess
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return jsonify({"output": output.decode("utf-8", errors="ignore")})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": e.output.decode("utf-8", errors="ignore")})
    except Exception as e:
        return jsonify({"error": str(e)})


# ==========================================
# Insecure Object Reference via Path
# ==========================================
@api_vuln_bp.route("/files/<path:filepath>")
def read_file(filepath):
    """
    ⚠️ VULNERABLE: Path traversal
    Payload: ../../../etc/passwd
    """
    base = "/tmp/api_files"
    full_path = os.path.join(base, filepath)
    
    # ⚠️ VULNERABLE: No path validation
    try:
        # Also try absolute path
        if filepath.startswith("/"):
            full_path = filepath
        
        if os.path.exists(full_path):
            with open(full_path, "r") as f:
                return jsonify({"path": full_path, "content": f.read()})
        return jsonify({"error": "File not found", "attempted_path": full_path}), 404
    except Exception as e:
        return jsonify({"error": str(e)})
