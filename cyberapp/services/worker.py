import time

from cyberapp.models.db import db_conn
from cybermodules.social_engineering import GhostEngine
from cybermodules.arsenal import SupremeArsenalEngine
from cybermodules.ad_enum import ActiveDirectoryEnum
from cybermodules.waf_bypass import WAFBypassEngine
from cybermodules.llm_engine import LLMEngine
from cybermodules.gamification import GamificationEngine
from cybermodules.autoexploit import AutoExploit
from cyberapp.services.progress import update_scan_progress


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

        if run_python:
            try:
                ghost = GhostEngine(target, scan_id)
                ghost.start()
                update_scan_progress(scan_id, 25, _eta(start_time, 25))
            except Exception as e:
                with db_conn() as conn:
                    conn.execute(
                        "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                        (scan_id, "GHOST_ENGINE", f"Error: {str(e)[:100]}"),
                    )
                    conn.commit()

        if selected_tools:
            try:
                with db_conn() as conn:
                    conn.execute("UPDATE scans SET status = 'ARSENAL ⚔️' WHERE id = ?", (scan_id,))
                    conn.commit()

                arsenal = SupremeArsenalEngine(target, scan_id, selected_tools)
                arsenal.start()
                update_scan_progress(scan_id, 60, _eta(start_time, 60))
            except Exception as e:
                with db_conn() as conn:
                    conn.execute(
                        "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                        (scan_id, "ARSENAL", f"Error: {str(e)[:100]}"),
                    )
                    conn.commit()

        if "ad_enum" in selected_tools:
            try:
                ad = ActiveDirectoryEnum(target.replace("http://", "").replace("https://", ""), scan_id)
                ad.start()
            except Exception as e:
                with db_conn() as conn:
                    conn.execute(
                        "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                        (scan_id, "AD_ENUM", f"Error: {str(e)[:100]}"),
                    )
                    conn.commit()

        if "waf_bypass" in selected_tools:
            try:
                waf = WAFBypassEngine(target, scan_id)
                waf.start()
            except Exception as e:
                with db_conn() as conn:
                    conn.execute(
                        "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                        (scan_id, "WAF_BYPASS", f"Error: {str(e)[:100]}"),
                    )
                    conn.commit()

        if "llm_analysis" in selected_tools:
            try:
                llm = LLMEngine(scan_id)
                with db_conn() as conn:
                    vulns = conn.execute(
                        "SELECT type, url FROM vulns WHERE scan_id=?",
                        (scan_id,),
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
                with db_conn() as conn:
                    conn.execute(
                        "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                        (scan_id, "LLM_ANALYSIS", f"Error: {str(e)[:100]}"),
                    )
                    conn.commit()

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
                with db_conn() as conn:
                    conn.execute(
                        "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                        (scan_id, "GAMIFICATION", f"Error: {str(e)[:100]}"),
                    )
                    conn.commit()

        try:
            with db_conn() as conn:
                critical_vulns = conn.execute(
                    "SELECT COUNT(*) FROM vulns WHERE scan_id = ? AND type IN ('SQL_INJECTION', 'RCE', 'GIZLI ANAHTAR')",
                    (scan_id,),
                ).fetchone()[0]

            if critical_vulns > 0:
                with db_conn() as conn:
                    conn.execute(
                        "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                        (scan_id, "AUTOEXPLOIT_TRIGGERED", "Kritik zafiyet bulundu, AutoExploit başlatılıyor..."),
                    )
                    conn.commit()

                autoexploit = AutoExploit(scan_id, target)
                autoexploit.start()
        except Exception as e:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                    (scan_id, "AUTOEXPLOIT_AUTO", f"Error: {str(e)[:100]}"),
                )
                conn.commit()

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
            import gc

            gc.collect()
        except Exception:
            pass


def _eta(start_time, progress):
    if progress <= 0:
        return None
    elapsed = time.time() - start_time
    remaining = max(0, 100 - progress)
    return int((elapsed / max(progress, 1)) * remaining)
