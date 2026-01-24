"""
Evasion Testing Suite
=====================
Static YARA scanning and behavioral analysis for evasion validation

Features:
- YARA rule scanning for payload detection
- Behavioral pattern detection
- AV/EDR signature testing
- Entropy analysis
- String pattern detection
- API call pattern analysis

⚠️ YASAL UYARI: Bu modül sadece yetkili penetrasyon testleri içindir.
"""

from __future__ import annotations
import os
import re
import math
import struct
import hashlib
import logging
import subprocess
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from enum import Enum, auto
from collections import Counter

logger = logging.getLogger("evasion_review")


# ============================================================
# ENUMS & CONSTANTS
# ============================================================

class DetectionLevel(Enum):
    """Detection risk level"""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TestCategory(Enum):
    """Test categories"""
    YARA = "yara"
    STRINGS = "strings"
    ENTROPY = "entropy"
    BEHAVIOR = "behavior"
    SIGNATURE = "signature"
    API_PATTERN = "api_pattern"
    SHELLCODE = "shellcode"


# Common suspicious strings
SUSPICIOUS_STRINGS = [
    # Process injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtCreateThreadEx", "RtlCreateUserThread",
    "QueueUserAPC", "NtQueueApcThread",
    "SetThreadContext", "NtSetContextThread",
    
    # Memory
    "HeapCreate", "RtlAllocateHeap",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "NtMapViewOfSection", "NtUnmapViewOfSection",
    
    # Evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "GetTickCount64",
    "Sleep", "NtDelayExecution", "WaitForSingleObject",
    
    # Credential access
    "MiniDumpWriteDump", "sekurlsa", "lsass",
    "mimikatz", "kerberos", "logonpasswords",
    "wdigest", "credman", "SAMKeyDerivation",
    
    # Persistence
    "RegSetValueEx", "RegCreateKeyEx",
    "WScript.Shell", "CreateService", "StartService",
    "SchTasksCreate", "ScheduledTask",
    
    # Network
    "WinHttpOpen", "InternetOpen", "URLDownloadToFile",
    "WSAStartup", "socket", "connect",
    "HttpOpenRequest", "WinHttpSendRequest",
    
    # Execution
    "ShellExecute", "WinExec", "CreateProcess",
    "cmd.exe", "powershell", "rundll32",
    
    # AMSI/ETW Bypass indicators
    "AmsiScanBuffer", "AmsiInitialize",
    "EtwEventWrite", "NtTraceEvent",
    "amsi.dll", "clr.dll",
]

# API patterns indicating malicious behavior
MALICIOUS_API_PATTERNS = [
    # Classic injection
    ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"],
    ["NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"],
    
    # APC injection
    ["OpenThread", "QueueUserAPC", "ResumeThread"],
    ["NtOpenThread", "NtQueueApcThread", "NtAlertResumeThread"],
    
    # Section mapping
    ["NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection"],
    
    # Credential dumping
    ["OpenProcess", "MiniDumpWriteDump"],
    ["LsaEnumerateLogonSessions", "LsaGetLogonSessionData"],
    
    # Defense evasion
    ["GetProcAddress", "LoadLibrary", "VirtualProtect"],
    ["NtQuerySystemInformation", "IsDebuggerPresent"],
]

# Entropy thresholds
ENTROPY_THRESHOLDS = {
    'low': 4.0,
    'normal': 6.0,
    'packed': 7.2,
    'encrypted': 7.8
}


# ============================================================
# DATACLASSES
# ============================================================

@dataclass
class YARAMatch:
    """YARA rule match"""
    rule_name: str
    rule_source: str
    strings_matched: List[str] = field(default_factory=list)
    offset: int = 0
    description: str = ""
    severity: str = "medium"


@dataclass
class StringMatch:
    """Suspicious string match"""
    string: str
    offset: int
    context: str
    category: str


@dataclass
class EntropyResult:
    """Entropy analysis result"""
    overall_entropy: float
    section_entropy: Dict[str, float] = field(default_factory=dict)
    high_entropy_sections: List[str] = field(default_factory=list)
    is_packed: bool = False
    is_encrypted: bool = False


@dataclass
class BehaviorMatch:
    """Behavioral pattern match"""
    pattern_name: str
    apis_matched: List[str]
    risk_level: DetectionLevel
    description: str
    mitigation: str = ""


@dataclass
class EvasionReport:
    """Complete evasion analysis report"""
    scan_id: str
    target_file: str
    scan_time: str
    
    # Detection level
    overall_risk: DetectionLevel = DetectionLevel.CLEAN
    
    # Results
    yara_matches: List[YARAMatch] = field(default_factory=list)
    string_matches: List[StringMatch] = field(default_factory=list)
    entropy_result: Optional[EntropyResult] = None
    behavior_matches: List[BehaviorMatch] = field(default_factory=list)
    api_patterns_found: List[Dict] = field(default_factory=list)
    
    # Scores
    yara_score: int = 0
    string_score: int = 0
    entropy_score: int = 0
    behavior_score: int = 0
    total_score: int = 0
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'scan_id': self.scan_id,
            'target_file': self.target_file,
            'scan_time': self.scan_time,
            'overall_risk': self.overall_risk.value,
            'yara_matches': len(self.yara_matches),
            'string_matches': len(self.string_matches),
            'behavior_matches': len(self.behavior_matches),
            'total_score': self.total_score,
            'recommendations': self.recommendations,
        }


# ============================================================
# YARA SCANNER
# ============================================================

class YARAScanner:
    """
    YARA Rule Scanner
    
    Scans payloads against YARA rules to detect known patterns.
    """
    
    # Built-in YARA rules for common detection
    BUILTIN_RULES = '''
rule suspicious_shellcode {
    meta:
        description = "Detects common shellcode patterns"
        severity = "high"
    strings:
        $mz = "MZ"
        $pe = "PE"
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        $call_pop = { E8 00 00 00 00 5? }
        $xor_decoder = { 31 ?? 83 ?? ?? 75 ?? }
        $stack_pivot = { 94 C3 }
        $jmp_esp = { FF E4 }
        $call_esp = { FF D4 }
        $push_ret = { 68 ?? ?? ?? ?? C3 }
    condition:
        any of them
}

rule process_injection_strings {
    meta:
        description = "Process injection related strings"
        severity = "high"
    strings:
        $s1 = "VirtualAllocEx" ascii wide
        $s2 = "WriteProcessMemory" ascii wide
        $s3 = "CreateRemoteThread" ascii wide
        $s4 = "NtCreateThreadEx" ascii wide
        $s5 = "QueueUserAPC" ascii wide
        $s6 = "RtlCreateUserThread" ascii wide
    condition:
        2 of them
}

rule credential_theft_strings {
    meta:
        description = "Credential theft related strings"
        severity = "critical"
    strings:
        $s1 = "sekurlsa" ascii wide nocase
        $s2 = "logonpasswords" ascii wide nocase
        $s3 = "mimikatz" ascii wide nocase
        $s4 = "wdigest" ascii wide nocase
        $s5 = "lsass" ascii wide nocase
        $s6 = "MiniDumpWriteDump" ascii wide
    condition:
        any of them
}

rule amsi_bypass_strings {
    meta:
        description = "AMSI bypass related strings"
        severity = "high"
    strings:
        $s1 = "AmsiScanBuffer" ascii wide
        $s2 = "AmsiInitialize" ascii wide
        $s3 = "amsi.dll" ascii wide nocase
        $s4 = "AmsiContext" ascii wide
        $s5 = "AmsiOpenSession" ascii wide
    condition:
        2 of them
}

rule etw_bypass_strings {
    meta:
        description = "ETW bypass related strings"
        severity = "high"
    strings:
        $s1 = "EtwEventWrite" ascii wide
        $s2 = "NtTraceEvent" ascii wide
        $s3 = "EtwpEventWrite" ascii wide
        $s4 = "NtTraceControl" ascii wide
    condition:
        any of them
}

rule c2_framework_strings {
    meta:
        description = "C2 framework indicators"
        severity = "critical"
    strings:
        $cobalt1 = "beacon" ascii wide nocase
        $cobalt2 = "%COMSPEC%" ascii wide
        $cobalt3 = "ReflectiveLoader" ascii wide
        $sliver1 = "sliver" ascii wide nocase
        $sliver2 = "implant" ascii wide nocase
        $meta1 = "meterpreter" ascii wide nocase
        $meta2 = "metsrv" ascii wide
    condition:
        any of them
}

rule high_entropy_section {
    meta:
        description = "High entropy section (possible encryption/packing)"
        severity = "medium"
    condition:
        math.entropy(0, filesize) > 7.2
}

rule suspicious_pe_characteristics {
    meta:
        description = "Suspicious PE characteristics"
        severity = "medium"
    strings:
        $mz = "MZ" at 0
    condition:
        $mz and (
            pe.characteristics & 0x2000 or  // DLL
            pe.number_of_sections > 8 or
            pe.entry_point > pe.sections[pe.number_of_sections - 1].raw_data_offset + pe.sections[pe.number_of_sections - 1].raw_data_size
        )
}
'''
    
    def __init__(self, custom_rules_path: str = None):
        self.custom_rules_path = custom_rules_path
        self.rules = None
        self._compile_rules()
    
    def _compile_rules(self):
        """Compile YARA rules"""
        try:
            import yara
            
            # Compile built-in rules
            self.rules = yara.compile(source=self.BUILTIN_RULES)
            
            # Add custom rules if provided
            if self.custom_rules_path and os.path.exists(self.custom_rules_path):
                custom_rules = yara.compile(filepath=self.custom_rules_path)
                # Note: YARA doesn't support merging, would need to combine sources
                
        except ImportError:
            logger.warning("YARA module not installed, using fallback scanner")
            self.rules = None
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            self.rules = None
    
    def scan_file(self, file_path: str) -> List[YARAMatch]:
        """Scan file with YARA rules"""
        matches = []
        
        if self.rules:
            try:
                import yara
                yara_matches = self.rules.match(file_path)
                
                for match in yara_matches:
                    yara_match = YARAMatch(
                        rule_name=match.rule,
                        rule_source="builtin",
                        strings_matched=[str(s) for s in match.strings],
                        description=match.meta.get('description', ''),
                        severity=match.meta.get('severity', 'medium')
                    )
                    matches.append(yara_match)
                    
            except Exception as e:
                logger.error(f"YARA scan failed: {e}")
        else:
            # Fallback: use command line yara
            matches = self._fallback_yara_scan(file_path)
        
        return matches
    
    def scan_bytes(self, data: bytes) -> List[YARAMatch]:
        """Scan bytes with YARA rules"""
        matches = []
        
        if self.rules:
            try:
                import yara
                yara_matches = self.rules.match(data=data)
                
                for match in yara_matches:
                    yara_match = YARAMatch(
                        rule_name=match.rule,
                        rule_source="builtin",
                        strings_matched=[str(s) for s in match.strings],
                        description=match.meta.get('description', ''),
                        severity=match.meta.get('severity', 'medium')
                    )
                    matches.append(yara_match)
                    
            except Exception as e:
                logger.error(f"YARA scan failed: {e}")
        
        return matches
    
    def _fallback_yara_scan(self, file_path: str) -> List[YARAMatch]:
        """Fallback YARA scan using command line"""
        matches = []
        
        # Save rules to temp file
        rules_file = "/tmp/yara_rules.yar"
        with open(rules_file, 'w') as f:
            f.write(self.BUILTIN_RULES)
        
        try:
            result = subprocess.run(
                ["yara", "-s", rules_file, file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse output
            for line in result.stdout.split('\n'):
                if line and not line.startswith('0x'):
                    parts = line.split()
                    if parts:
                        matches.append(YARAMatch(
                            rule_name=parts[0],
                            rule_source="builtin"
                        ))
                        
        except Exception as e:
            logger.warning(f"Fallback YARA scan failed: {e}")
        
        return matches


# ============================================================
# STRING SCANNER
# ============================================================

class StringScanner:
    """
    Suspicious String Scanner
    
    Detects known malicious strings and patterns.
    """
    
    def __init__(self, custom_strings: List[str] = None):
        self.suspicious_strings = SUSPICIOUS_STRINGS.copy()
        if custom_strings:
            self.suspicious_strings.extend(custom_strings)
    
    def scan_file(self, file_path: str) -> List[StringMatch]:
        """Scan file for suspicious strings"""
        matches = []
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        return self.scan_bytes(data)
    
    def scan_bytes(self, data: bytes) -> List[StringMatch]:
        """Scan bytes for suspicious strings"""
        matches = []
        
        # Convert to string for searching (both ASCII and Unicode)
        ascii_data = data.decode('ascii', errors='ignore')
        unicode_data = data.decode('utf-16-le', errors='ignore')
        
        for suspicious in self.suspicious_strings:
            # Check ASCII
            for match in re.finditer(re.escape(suspicious), ascii_data, re.IGNORECASE):
                matches.append(StringMatch(
                    string=suspicious,
                    offset=match.start(),
                    context=ascii_data[max(0, match.start()-20):match.end()+20],
                    category=self._categorize_string(suspicious)
                ))
            
            # Check Unicode
            for match in re.finditer(re.escape(suspicious), unicode_data, re.IGNORECASE):
                # Don't add duplicates
                if not any(m.string == suspicious and abs(m.offset - match.start()*2) < 10 for m in matches):
                    matches.append(StringMatch(
                        string=suspicious + " (unicode)",
                        offset=match.start() * 2,
                        context=unicode_data[max(0, match.start()-20):match.end()+20],
                        category=self._categorize_string(suspicious)
                    ))
        
        return matches
    
    def _categorize_string(self, string: str) -> str:
        """Categorize suspicious string"""
        string_lower = string.lower()
        
        if any(x in string_lower for x in ['virtualallocex', 'writeprocessmemory', 'createremotethread', 'ntcreatethread']):
            return "process_injection"
        elif any(x in string_lower for x in ['mimikatz', 'sekurlsa', 'lsass', 'wdigest']):
            return "credential_theft"
        elif any(x in string_lower for x in ['amsi', 'etw']):
            return "defense_evasion"
        elif any(x in string_lower for x in ['regsetvalue', 'createservice', 'schtask']):
            return "persistence"
        elif any(x in string_lower for x in ['winhttp', 'internet', 'socket', 'wsastartup']):
            return "network"
        elif any(x in string_lower for x in ['shellexecute', 'createprocess', 'cmd.exe', 'powershell']):
            return "execution"
        else:
            return "generic"


# ============================================================
# ENTROPY ANALYZER
# ============================================================

class EntropyAnalyzer:
    """
    Entropy Analyzer
    
    Calculates entropy to detect encryption/packing.
    """
    
    def analyze_file(self, file_path: str) -> EntropyResult:
        """Analyze file entropy"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        return self.analyze_bytes(data)
    
    def analyze_bytes(self, data: bytes, section_size: int = 4096) -> EntropyResult:
        """Analyze bytes entropy"""
        overall = self._calculate_entropy(data)
        
        # Calculate section entropy
        sections = {}
        high_entropy = []
        
        for i in range(0, len(data), section_size):
            section_data = data[i:i+section_size]
            section_name = f"0x{i:08x}"
            section_entropy = self._calculate_entropy(section_data)
            sections[section_name] = section_entropy
            
            if section_entropy > ENTROPY_THRESHOLDS['packed']:
                high_entropy.append(section_name)
        
        return EntropyResult(
            overall_entropy=overall,
            section_entropy=sections,
            high_entropy_sections=high_entropy,
            is_packed=overall > ENTROPY_THRESHOLDS['packed'],
            is_encrypted=overall > ENTROPY_THRESHOLDS['encrypted']
        )
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        # Count byte frequency
        freq = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy


# ============================================================
# BEHAVIORAL ANALYZER
# ============================================================

class BehavioralAnalyzer:
    """
    Behavioral Pattern Analyzer
    
    Detects malicious API call patterns and behaviors.
    """
    
    def __init__(self):
        self.api_patterns = MALICIOUS_API_PATTERNS
    
    def analyze_strings(self, strings: List[str]) -> List[BehaviorMatch]:
        """Analyze extracted strings for behavioral patterns"""
        matches = []
        strings_set = set(s.lower() for s in strings)
        
        # Check for injection patterns
        for pattern in self.api_patterns:
            matched_apis = []
            for api in pattern:
                if api.lower() in strings_set:
                    matched_apis.append(api)
            
            if len(matched_apis) >= 2:  # At least 2 APIs from pattern
                behavior = self._identify_behavior(matched_apis)
                matches.append(BehaviorMatch(
                    pattern_name=behavior['name'],
                    apis_matched=matched_apis,
                    risk_level=behavior['risk'],
                    description=behavior['description'],
                    mitigation=behavior['mitigation']
                ))
        
        return matches
    
    def _identify_behavior(self, apis: List[str]) -> Dict:
        """Identify behavior based on matched APIs"""
        apis_lower = [a.lower() for a in apis]
        
        if 'virtualallocex' in apis_lower and 'createremotethread' in apis_lower:
            return {
                'name': 'Classic Process Injection',
                'risk': DetectionLevel.CRITICAL,
                'description': 'VirtualAllocEx + WriteProcessMemory + CreateRemoteThread pattern',
                'mitigation': 'Use direct syscalls or indirect injection methods'
            }
        
        if 'queueuserapc' in apis_lower:
            return {
                'name': 'APC Injection',
                'risk': DetectionLevel.HIGH,
                'description': 'APC queue injection pattern',
                'mitigation': 'Use NtQueueApcThread direct syscall'
            }
        
        if 'ntcreatesection' in apis_lower:
            return {
                'name': 'Section Mapping Injection',
                'risk': DetectionLevel.MEDIUM,
                'description': 'Process hollowing via section mapping',
                'mitigation': 'Randomize section permissions timing'
            }
        
        if 'minidumpwritedump' in apis_lower:
            return {
                'name': 'LSASS Dump',
                'risk': DetectionLevel.CRITICAL,
                'description': 'Credential dumping via MiniDumpWriteDump',
                'mitigation': 'Use direct LSASS memory reading or SSP'
            }
        
        return {
            'name': 'Suspicious API Pattern',
            'risk': DetectionLevel.MEDIUM,
            'description': f'Matched APIs: {", ".join(apis)}',
            'mitigation': 'Review and consider indirect calling'
        }


# ============================================================
# FULL EVASION TESTER
# ============================================================

class EvasionTester:
    """
    Complete Evasion Testing Suite
    
    Combines all analysis methods for comprehensive testing.
    """
    
    def __init__(self, scan_id: int = 0):
        self.scan_id = scan_id
        self.yara_scanner = YARAScanner()
        self.string_scanner = StringScanner()
        self.entropy_analyzer = EntropyAnalyzer()
        self.behavior_analyzer = BehavioralAnalyzer()
    
    def test_file(self, file_path: str) -> EvasionReport:
        """Run complete evasion test on file"""
        report = EvasionReport(
            scan_id=f"scan_{self.scan_id}",
            target_file=file_path,
            scan_time=datetime.now().isoformat()
        )
        
        logger.info(f"[EVASION] Testing file: {file_path}")
        
        # YARA scan
        yara_matches = self.yara_scanner.scan_file(file_path)
        report.yara_matches = yara_matches
        report.yara_score = len(yara_matches) * 25
        
        # String scan
        string_matches = self.string_scanner.scan_file(file_path)
        report.string_matches = string_matches
        report.string_score = len(string_matches) * 10
        
        # Entropy analysis
        entropy_result = self.entropy_analyzer.analyze_file(file_path)
        report.entropy_result = entropy_result
        report.entropy_score = 30 if entropy_result.is_encrypted else (15 if entropy_result.is_packed else 0)
        
        # Behavioral analysis
        extracted_strings = [m.string for m in string_matches]
        behavior_matches = self.behavior_analyzer.analyze_strings(extracted_strings)
        report.behavior_matches = behavior_matches
        report.behavior_score = sum(
            50 if b.risk_level == DetectionLevel.CRITICAL else
            30 if b.risk_level == DetectionLevel.HIGH else
            15 for b in behavior_matches
        )
        
        # Calculate total score
        report.total_score = (
            report.yara_score + 
            report.string_score + 
            report.entropy_score + 
            report.behavior_score
        )
        
        # Determine overall risk
        report.overall_risk = self._calculate_risk_level(report.total_score)
        
        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)
        
        logger.info(f"[EVASION] Risk: {report.overall_risk.value}, Score: {report.total_score}")
        
        return report
    
    def test_bytes(self, data: bytes, name: str = "payload") -> EvasionReport:
        """Run complete evasion test on bytes"""
        report = EvasionReport(
            scan_id=f"scan_{self.scan_id}",
            target_file=name,
            scan_time=datetime.now().isoformat()
        )
        
        # YARA scan
        yara_matches = self.yara_scanner.scan_bytes(data)
        report.yara_matches = yara_matches
        report.yara_score = len(yara_matches) * 25
        
        # String scan
        string_matches = self.string_scanner.scan_bytes(data)
        report.string_matches = string_matches
        report.string_score = len(string_matches) * 10
        
        # Entropy analysis
        entropy_result = self.entropy_analyzer.analyze_bytes(data)
        report.entropy_result = entropy_result
        report.entropy_score = 30 if entropy_result.is_encrypted else (15 if entropy_result.is_packed else 0)
        
        # Behavioral analysis
        extracted_strings = [m.string for m in string_matches]
        behavior_matches = self.behavior_analyzer.analyze_strings(extracted_strings)
        report.behavior_matches = behavior_matches
        report.behavior_score = sum(
            50 if b.risk_level == DetectionLevel.CRITICAL else
            30 if b.risk_level == DetectionLevel.HIGH else
            15 for b in behavior_matches
        )
        
        report.total_score = (
            report.yara_score + 
            report.string_score + 
            report.entropy_score + 
            report.behavior_score
        )
        
        report.overall_risk = self._calculate_risk_level(report.total_score)
        report.recommendations = self._generate_recommendations(report)
        
        return report
    
    def test_code_pattern(self, code: str, language: str = "python") -> EvasionReport:
        """Test source code for detection patterns"""
        report = EvasionReport(
            scan_id=f"scan_{self.scan_id}",
            target_file=f"code.{language}",
            scan_time=datetime.now().isoformat()
        )
        
        # Check for suspicious patterns in code
        code_patterns = [
            (r'ctypes\.windll|kernel32|ntdll', 'WinAPI Access', 20),
            (r'VirtualAlloc|VirtualProtect', 'Memory Manipulation', 30),
            (r'CreateRemoteThread|NtCreateThread', 'Thread Creation', 40),
            (r'WriteProcessMemory|ReadProcessMemory', 'Process Memory', 35),
            (r'base64\.b64decode|exec\(|eval\(', 'Dynamic Execution', 25),
            (r'subprocess|os\.system|os\.popen', 'Command Execution', 20),
            (r'socket|urllib|requests', 'Network Access', 15),
            (r'AmsiScanBuffer|EtwEventWrite', 'Security Bypass', 50),
        ]
        
        total = 0
        for pattern, name, score in code_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                report.string_matches.append(StringMatch(
                    string=name,
                    offset=0,
                    context=pattern,
                    category='code_pattern'
                ))
                total += score
        
        report.string_score = total
        report.total_score = total
        report.overall_risk = self._calculate_risk_level(total)
        report.recommendations = self._generate_code_recommendations(report)
        
        return report
    
    def _calculate_risk_level(self, score: int) -> DetectionLevel:
        """Calculate risk level from score"""
        if score == 0:
            return DetectionLevel.CLEAN
        elif score < 30:
            return DetectionLevel.LOW
        elif score < 60:
            return DetectionLevel.MEDIUM
        elif score < 100:
            return DetectionLevel.HIGH
        else:
            return DetectionLevel.CRITICAL
    
    def _generate_recommendations(self, report: EvasionReport) -> List[str]:
        """Generate evasion recommendations"""
        recommendations = []
        
        # Based on YARA matches
        for match in report.yara_matches:
            if 'shellcode' in match.rule_name:
                recommendations.append("🔴 Shellcode patterns detected - use polymorphic encoding")
            if 'injection' in match.rule_name:
                recommendations.append("🔴 Injection strings detected - use string obfuscation")
            if 'credential' in match.rule_name:
                recommendations.append("🔴 Credential theft signatures - modify tool signatures")
        
        # Based on string matches
        categories = set(m.category for m in report.string_matches)
        if 'process_injection' in categories:
            recommendations.append("⚠️ Use indirect syscalls instead of API calls")
        if 'credential_theft' in categories:
            recommendations.append("⚠️ Encrypt/obfuscate tool-specific strings")
        if 'defense_evasion' in categories:
            recommendations.append("⚠️ Implement string hashing for AMSI/ETW bypass")
        
        # Based on entropy
        if report.entropy_result:
            if not report.entropy_result.is_encrypted:
                recommendations.append("💡 Consider encrypting payload sections")
            if report.entropy_result.overall_entropy < 4.0:
                recommendations.append("💡 Add entropy to avoid statistical analysis")
        
        # Based on behaviors
        for behavior in report.behavior_matches:
            if behavior.mitigation:
                recommendations.append(f"📋 {behavior.pattern_name}: {behavior.mitigation}")
        
        if not recommendations:
            recommendations.append("✅ No major detection issues found")
        
        return recommendations
    
    def _generate_code_recommendations(self, report: EvasionReport) -> List[str]:
        """Generate code-specific recommendations"""
        recommendations = []
        
        for match in report.string_matches:
            if 'WinAPI' in match.string:
                recommendations.append("Use dynamic API resolution with GetProcAddress")
            if 'Memory' in match.string:
                recommendations.append("Consider indirect syscalls for memory operations")
            if 'Dynamic Execution' in match.string:
                recommendations.append("Obfuscate dynamic code execution patterns")
            if 'Security Bypass' in match.string:
                recommendations.append("Use runtime string deobfuscation for security APIs")
        
        return recommendations
    
    def generate_report_markdown(self, report: EvasionReport) -> str:
        """Generate markdown report"""
        md = f"""# Evasion Analysis Report

**Scan ID:** {report.scan_id}
**Target:** {report.target_file}
**Time:** {report.scan_time}

## Summary

| Metric | Score |
|--------|-------|
| Overall Risk | **{report.overall_risk.value.upper()}** |
| Total Score | {report.total_score} |
| YARA Matches | {len(report.yara_matches)} |
| String Matches | {len(report.string_matches)} |
| Behavior Patterns | {len(report.behavior_matches)} |

## YARA Matches

"""
        for match in report.yara_matches:
            md += f"- **{match.rule_name}** ({match.severity}): {match.description}\n"
        
        md += "\n## Suspicious Strings\n\n"
        for match in report.string_matches[:20]:
            md += f"- `{match.string}` at 0x{match.offset:08x} [{match.category}]\n"
        
        if report.entropy_result:
            md += f"""
## Entropy Analysis

- Overall Entropy: {report.entropy_result.overall_entropy:.2f}
- Is Packed: {report.entropy_result.is_packed}
- Is Encrypted: {report.entropy_result.is_encrypted}
- High Entropy Sections: {len(report.entropy_result.high_entropy_sections)}
"""
        
        md += "\n## Behavioral Patterns\n\n"
        for behavior in report.behavior_matches:
            md += f"- **{behavior.pattern_name}** ({behavior.risk_level.value})\n"
            md += f"  - APIs: {', '.join(behavior.apis_matched)}\n"
            md += f"  - Mitigation: {behavior.mitigation}\n"
        
        md += "\n## Recommendations\n\n"
        for rec in report.recommendations:
            md += f"- {rec}\n"
        
        return md


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Enums
    'DetectionLevel',
    'TestCategory',
    
    # Dataclasses
    'YARAMatch',
    'StringMatch',
    'EntropyResult',
    'BehaviorMatch',
    'EvasionReport',
    
    # Classes
    'YARAScanner',
    'StringScanner',
    'EntropyAnalyzer',
    'BehavioralAnalyzer',
    'EvasionTester',
]
