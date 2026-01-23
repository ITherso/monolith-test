def main():

    import traceback
    import argparse
    import os
    try:
        print('[DEBUG] <main> TRY BAŞI')
        # ...existing code...
        from cyberapp.app import create_app
        from cyberapp.models.db import db_conn
        from cyberapp.migrations import create_revision, current_revision, run_migrations
        from cyberapp.settings import (
            ADMIN_PASS,
            ADMIN_USER,
            ANALYST_PASS,
            ANALYST_USER,
            DB_NAME,
            LHOST,
            LPORT,
        )
        from cyberapp.services.worker import run_worker
        from cybermodules.auto_update import AutoUpdater
        from cybermodules.arsenal import TOOLS
        from cybermodules.threat_hunter import ThreatHunter

        def check_tools():
            print("\n🔧 TOOL CHECK:")
            available = 0
            missing = []
            for tool, path in TOOLS.items():
                if path and os.path.exists(path.split()[0] if " " in path else path):
                    print(f"  ✓ {tool}")
                    available += 1
                else:
                    print(f"  ✗ {tool}")
                    missing.append(tool)
            print(f"\n📊 Summary: {available}/{len(TOOLS)} tools available")
            if missing:
                print(f"\n⚠️  Missing tools: {', '.join(missing[:5])}")
                if len(missing) > 5:
                    print(f"   ... and {len(missing)-5} more")
                print("\n💡 Installation commands:")
                if "Nmap" in missing:
                    print("   sudo apt install nmap")
                if "Nuclei" in missing:
                    print("   go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
                if "Gobuster" in missing:
                    print("   go install github.com/OJ/gobuster/v3@latest")
            return available >= 10

        parser = argparse.ArgumentParser(description="MONOLITH v68 Ultimate Pentest Framework")
        parser.add_argument("--target", "-t", help="Target URL to scan")
        parser.add_argument("--quick", "-q", action="store_true", help="Quick scan mode")
        parser.add_argument("--deep", "-d", action="store_true", help="Deep scan mode")
        parser.add_argument("--output", "-o", help="Output directory for reports")
        parser.add_argument("--update", "-u", action="store_true", help="Update payloads and tools")
        parser.add_argument("--headless", action="store_true", help="Run without web interface")
        parser.add_argument("--autoexploit", action="store_true", help="Run autoexploit on target")
        parser.add_argument("--threathunter", action="store_true", help="Start threat hunter")
        parser.add_argument("--publish-merkle", type=int, help="Publish merkle root for a scan id")
        parser.add_argument("--db-upgrade", action="store_true", help="Run Alembic migrations to head")
        parser.add_argument("--db-current", action="store_true", help="Show current Alembic revision")
        parser.add_argument("--db-revision", metavar="MESSAGE", help="Create Alembic revision with message")
        args = parser.parse_args()

        if args.db_current:
            current_revision()
            return
        if args.db_upgrade:
            run_migrations()
            return
        if args.db_revision:
            create_revision(args.db_revision)
            return
        if args.update:
            updater = AutoUpdater()
            updater.update_payloads()
            update_info = updater.check_for_updates()
            if update_info.get("update_available"):
                print(f"\n✅ Update check complete. New version: {update_info['latest_version']}")
            return
        if args.headless and args.target:
            print(f"\n[*] Starting headless scan for {args.target}")
            run_migrations()
            with db_conn() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO scans (target, status, user_id)
                    VALUES (?, ?, ?)
                    """,
                    (args.target, "RUNNING", "cli-user"),
                )
                scan_id = cursor.lastrowid
            tools = ["nmap", "nuclei", "supply_chain", "blockchain", "gamification"]
            if args.deep:
                tools.extend(["zeroday", "ai_prediction", "cloud_audit", "api_scan"])
            if args.autoexploit:
                tools.extend(["autoexploit"])
            try:
                from monolith.tasks import run_scan
                task = run_scan.delay(args.target, scan_id, True, tools, "cli-user")
                if hasattr(task, "id"):
                    print(f"[*] Scan enqueued with task id: {task.id} (scan id: {scan_id})")
                else:
                    print(f"[*] Scan executed synchronously (scan id: {scan_id})")
            except Exception:
                run_worker(args.target, scan_id, True, tools, "cli-user")
            print("[*] Check web interface for results")
            print("[*] Use: python3 monolith.py (without --headless) to access web interface")
            return
        if args.publish_merkle:
            try:
                import monolith.blockchain as mchain
                scan_id = args.publish_merkle
                run_migrations()
                with db_conn() as conn:
                    rows = conn.execute(
                        "SELECT id, evidence_hash FROM blockchain_evidence WHERE scan_id = ?",
                        (scan_id,),
                    ).fetchall()
                if not rows:
                    print("[!] No evidence found for scan", scan_id)
                    return
                leaves = [(str(r[0]) + ":" + (r[1] or "")).encode("utf-8") for r in rows]
                pk = os.getenv("WEB3_PRIVATE_KEY")
                if not pk:
                    print("[!] Set WEB3_PRIVATE_KEY env var to publish")
                    return
                tx = mchain.publish_merkle_root(leaves, pk)
                print("[+] Published merkle root tx:", tx)
            except Exception as e:
                print("[!] Merkle publish error:", e)
            return
        if args.threathunter:
            print("\n[*] Starting Threat Hunter...")
            hunter = ThreatHunter()
            hunter.start()
            return
        print("\n" + "=" * 70)
        print("🧱 MONOLITH v68 ULTIMATE - ALL-IN-ONE PENETRATION TESTING PLATFORM")
        print("=" * 70)
        print("Version: v68.0 Ultimate")
        print("Features: AI Prediction | Supply Chain | Zero-Day Research | Blockchain | Gamification")
        print("          Cloud Security | API Security | Auto-Update | AutoExploit | Threat Hunter")
        print(f"Database: {DB_NAME}")
        print("Web Interface: http://127.0.0.1:5000")
        print(f"Login: {ADMIN_USER} / {ADMIN_PASS}")
        print(f"Analyst: {ANALYST_USER} / {ANALYST_PASS}")
        print(f"LHOST: {LHOST} | LPORT: {LPORT}")
        print("=" * 70)
        updater = AutoUpdater()
        update_info = updater.check_for_updates()
        if update_info.get("update_available"):
            print(f"\n⚠️  UPDATE AVAILABLE: {update_info['latest_version']}")
            print(f"   {update_info['release_notes']}")
            print("   Run with --update flag to update payloads")
        print('[DEBUG] check_tools çağrılıyor...')
        tools_ok = check_tools()
        print('[DEBUG] check_tools tamamlandı')
        if not tools_ok:
            print("\n⚠️  Some features may not work properly due to missing tools.")
            print("   Consider installing missing tools for full functionality.")
        print("\n🚀 Starting MONOLITH...")
        print("\n" + "=" * 70)
        print('[DEBUG] os.makedirs çağrılıyor...')
        os.makedirs("/tmp/monolith", exist_ok=True)
        print('[DEBUG] os.makedirs tamamlandı')
        print("[DEBUG] run_migrations çağrılıyor...")
        run_migrations()
        print("[DEBUG] run_migrations tamamlandı")
        print("[DEBUG] create_app çağrılıyor...")
        app = create_app(run_migrations_on_start=False)
        print("[DEBUG] create_app tamamlandı")
        print("[DEBUG] app.run başlatılıyor...")
        try:
            print("[DEBUG] app.run() ile başlatılıyor...")
            app.run(
                host="0.0.0.0",
                port=8080,
                debug=True,
                use_reloader=False
            )
            print("[DEBUG] run sonrası")
        except KeyboardInterrupt:
            print("\n\n👋 MONOLITH shutdown complete. Stay secure!")
        except Exception as e:
            print(f"\n❌ Error starting MONOLITH: {e}")
            sys.exit(1)
        print('[DEBUG] <main> TRY SONU')
    except Exception as exc:
        print('[EXCEPTION] Ana try/except bloğu yakaladı:')
        traceback.print_exc()



if __name__ == "__main__":
    main()
