import datetime

from flask import Blueprint, redirect, render_template, request, session

from cyberapp.settings import ADMIN_PASS, ADMIN_USER, ANALYST_PASS, ANALYST_USER
from cyberapp.services.audit import log_audit as audit_log

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("user")
        password = request.form.get("pass")
        
        # ⚠️ VULNERABLE: SQL Injection in main login
        # Normal login check first
        role = None
        if username == ADMIN_USER and password == ADMIN_PASS:
            role = "admin"
        elif username == ANALYST_USER and password == ANALYST_PASS:
            role = "analyst"
        
        # ⚠️ VULNERABLE: Raw SQL check (SQLi possible)
        if not role:
            try:
                from cyberapp.models.db import db_conn
                with db_conn() as conn:
                    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                    result = conn.execute(query).fetchone()
                    if result:
                        role = "admin"  # SQLi bypass grants admin
            except:
                pass

        if role:
            session["logged_in"] = True
            session["user"] = username
            session["role"] = role
            session["start_time"] = datetime.datetime.now().isoformat()
            audit_log(username, role, "login_success", f"user={username}", request.remote_addr)
            return redirect("/")

        audit_log(username, "unknown", "login_failed", f"user={username}", request.remote_addr)

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    audit_log(session.get("user"), session.get("role"), "logout", "user_logout", request.remote_addr)
    session.clear()
    return redirect("/login")
