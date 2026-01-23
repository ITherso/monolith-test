"""
AI-Guided Lateral Movement
Integrates LLM for intelligent "next best jump" suggestions during lateral movement
Analyzes network topology, credentials, and defenses to optimize attack paths
"""

import json
import os
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from cybermodules.helpers import log_to_intel

# Try to import LLM engine
try:
    from cybermodules.llm_engine import LLMEngine
    HAS_LLM = True
except ImportError:
    HAS_LLM = False


@dataclass
class HostIntel:
    """Intelligence gathered about a host"""
    hostname: str
    ip: str
    os_type: str = "windows"
    compromised: bool = False
    creds_dumped: bool = False
    beacon_deployed: bool = False
    services: List[str] = None
    open_ports: List[int] = None
    users: List[str] = None
    groups: List[str] = None
    installed_software: List[str] = None
    av_product: str = ""
    domain_joined: bool = True
    is_dc: bool = False
    is_admin_workstation: bool = False
    notes: str = ""
    
    def __post_init__(self):
        if self.services is None:
            self.services = []
        if self.open_ports is None:
            self.open_ports = []
        if self.users is None:
            self.users = []
        if self.groups is None:
            self.groups = []
        if self.installed_software is None:
            self.installed_software = []


@dataclass
class CredentialIntel:
    """Intelligence about a credential"""
    username: str
    domain: str = ""
    cred_type: str = "password"  # password, ntlm_hash, kerberos
    source_host: str = ""
    cracked: bool = False
    tested_hosts: List[str] = None
    successful_hosts: List[str] = None
    is_domain_admin: bool = False
    is_local_admin: bool = False
    
    def __post_init__(self):
        if self.tested_hosts is None:
            self.tested_hosts = []
        if self.successful_hosts is None:
            self.successful_hosts = []


@dataclass
class JumpSuggestion:
    """AI-generated jump suggestion"""
    target: str
    method: str
    credentials: str
    confidence: float
    reasoning: str
    risk_level: str  # low, medium, high
    expected_value: str  # low, medium, high, critical
    prerequisites: List[str] = None
    
    def __post_init__(self):
        if self.prerequisites is None:
            self.prerequisites = []


class AILateralGuide:
    """
    AI-powered lateral movement guidance
    Analyzes the network state and suggests optimal next moves
    """
    
    def __init__(self, scan_id: int = 0, api_key: str = None):
        self.scan_id = scan_id
        self.api_key = api_key or os.environ.get('OPENAI_API_KEY', '')
        
        # Intelligence storage
        self.hosts: Dict[str, HostIntel] = {}
        self.credentials: Dict[str, CredentialIntel] = {}
        self.movement_history: List[Dict] = []
        
        # LLM Engine
        self.llm_engine = None
        if HAS_LLM and self.api_key:
            try:
                self.llm_engine = LLMEngine()
            except Exception:
                pass
    
    def add_host_intel(self, host: HostIntel):
        """Add or update host intelligence"""
        self.hosts[host.hostname] = host
        self._log(f"Added host intel: {host.hostname}")
    
    def add_credential_intel(self, cred: CredentialIntel):
        """Add or update credential intelligence"""
        key = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
        self.credentials[key] = cred
        self._log(f"Added credential intel: {key}")
    
    def record_movement(self, source: str, target: str, method: str, 
                       credential: str, success: bool, output: str = ""):
        """Record a lateral movement attempt"""
        self.movement_history.append({
            'timestamp': datetime.now().isoformat(),
            'source': source,
            'target': target,
            'method': method,
            'credential': credential,
            'success': success,
            'output': output[:500]  # Truncate output
        })
        
        # Update host state if successful
        if success and target in self.hosts:
            self.hosts[target].compromised = True
    
    def get_next_best_jump(self, current_host: str = None) -> List[JumpSuggestion]:
        """
        Get AI-suggested next best lateral movement targets
        Returns list of suggestions ordered by priority
        """
        
        # Build context for AI
        context = self._build_analysis_context(current_host)
        
        # If no LLM available, use rule-based suggestions
        if not self.llm_engine:
            return self._rule_based_suggestions(current_host)
        
        # Use LLM for intelligent suggestions
        try:
            prompt = self._build_suggestion_prompt(context)
            response = self._query_llm(prompt)
            suggestions = self._parse_suggestions(response)
            return suggestions
        except Exception as e:
            self._log(f"LLM suggestion failed: {e}, falling back to rules")
            return self._rule_based_suggestions(current_host)
    
    def analyze_defenses(self, target: str) -> Dict[str, Any]:
        """Analyze defenses on a target host"""
        if target not in self.hosts:
            return {'error': 'Host not in intel database'}
        
        host = self.hosts[target]
        
        analysis = {
            'host': target,
            'av_detected': bool(host.av_product),
            'av_product': host.av_product,
            'recommended_evasion': [],
            'risk_factors': [],
            'suggested_approach': ''
        }
        
        # AV-specific recommendations
        av_evasion_map = {
            'defender': ['amsi_bypass', 'etw_patching', 'unhook_ntdll'],
            'crowdstrike': ['direct_syscalls', 'sleep_obfuscation', 'process_hollowing'],
            'sentinelone': ['sleep_obfuscation', 'thread_execution_hijacking'],
            'carbonblack': ['process_hollowing', 'dll_unhooking']
        }
        
        if host.av_product:
            av_lower = host.av_product.lower()
            for av_name, techniques in av_evasion_map.items():
                if av_name in av_lower:
                    analysis['recommended_evasion'].extend(techniques)
                    break
        
        # Risk factors
        if host.is_dc:
            analysis['risk_factors'].append('Domain Controller - high monitoring')
        if 'admin' in target.lower():
            analysis['risk_factors'].append('Admin workstation - likely monitored')
        if host.av_product:
            analysis['risk_factors'].append(f'AV present: {host.av_product}')
        
        return analysis
    
    def suggest_attack_path(self, start: str, goal: str) -> List[Dict]:
        """
        Suggest optimal attack path from start to goal
        Uses graph analysis and AI for path optimization
        """
        
        if not self.llm_engine:
            return self._simple_path(start, goal)
        
        context = {
            'start': start,
            'goal': goal,
            'hosts': {h: self._host_to_dict(intel) for h, intel in self.hosts.items()},
            'credentials': {c: self._cred_to_dict(intel) for c, intel in self.credentials.items()},
            'history': self.movement_history[-10:]  # Last 10 movements
        }
        
        prompt = f"""
Analyze this network state and suggest the optimal lateral movement path:

START: {start}
GOAL: {goal}

KNOWN HOSTS:
{json.dumps(context['hosts'], indent=2)}

AVAILABLE CREDENTIALS:
{json.dumps({k: {{**v, 'password': '[REDACTED]'}} for k, v in context['credentials'].items()}, indent=2)}

MOVEMENT HISTORY:
{json.dumps(context['history'], indent=2)}

Suggest the optimal path considering:
1. Stealth (avoid detection)
2. Credential reuse across hosts
3. High-value intermediate targets
4. Defense evasion requirements

Return as JSON array of steps with: target, method, credential, reasoning
"""
        
        try:
            response = self._query_llm(prompt)
            return json.loads(response)
        except Exception:
            return self._simple_path(start, goal)
    
    def _build_analysis_context(self, current_host: str = None) -> Dict:
        """Build context for AI analysis"""
        
        # Categorize hosts
        compromised = [h for h, i in self.hosts.items() if i.compromised]
        uncompromised = [h for h, i in self.hosts.items() if not i.compromised]
        high_value = [h for h, i in self.hosts.items() if i.is_dc or i.is_admin_workstation]
        
        # Credential analysis
        domain_admin_creds = [c for c, i in self.credentials.items() if i.is_domain_admin]
        tested_creds = [(c, len(i.tested_hosts)) for c, i in self.credentials.items()]
        
        return {
            'current_host': current_host,
            'compromised_hosts': compromised,
            'uncompromised_hosts': uncompromised,
            'high_value_targets': high_value,
            'domain_admin_creds': domain_admin_creds,
            'total_hosts': len(self.hosts),
            'total_creds': len(self.credentials),
            'movement_count': len(self.movement_history)
        }
    
    def _build_suggestion_prompt(self, context: Dict) -> str:
        """Build prompt for next jump suggestion"""
        
        return f"""
You are an expert penetration tester analyzing a network for lateral movement.

CURRENT STATE:
- Current position: {context['current_host'] or 'Initial foothold'}
- Compromised hosts: {context['compromised_hosts']}
- Uncompromised targets: {context['uncompromised_hosts']}
- High-value targets: {context['high_value_targets']}
- Domain admin credentials available: {len(context['domain_admin_creds']) > 0}
- Total movements so far: {context['movement_count']}

HOST DETAILS:
{json.dumps({h: self._host_to_dict(i) for h, i in list(self.hosts.items())[:10]}, indent=2)}

CREDENTIAL DETAILS:
{json.dumps({c: {{**self._cred_to_dict(i), 'tested_hosts': i.tested_hosts}} for c, i in list(self.credentials.items())[:5]}, indent=2)}

Based on this state, suggest the next 3 best lateral movement targets.
For each suggestion, provide:
1. Target host
2. Recommended method (wmiexec, psexec, smbexec, dcomexec)
3. Which credential to use
4. Confidence score (0-1)
5. Reasoning
6. Risk level (low/medium/high)
7. Expected value (low/medium/high/critical)

Prioritize:
- Untested credential/host combinations
- High-value targets (DCs, admin workstations)
- Stealth (prefer wmiexec over psexec when possible)
- Credential expansion (hosts that may have new credentials)

Return as JSON array.
"""
    
    def _query_llm(self, prompt: str) -> str:
        """Query the LLM engine"""
        if self.llm_engine:
            return self.llm_engine.generate(prompt)
        
        # Fallback: Use direct OpenAI API if available
        if self.api_key:
            import openai
            openai.api_key = self.api_key
            
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert penetration testing AI assistant."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            return response.choices[0].message.content
        
        raise Exception("No LLM available")
    
    def _parse_suggestions(self, response: str) -> List[JumpSuggestion]:
        """Parse LLM response into JumpSuggestion objects"""
        suggestions = []
        
        try:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                
                for item in data:
                    suggestions.append(JumpSuggestion(
                        target=item.get('target', ''),
                        method=item.get('method', 'wmiexec'),
                        credentials=item.get('credential', ''),
                        confidence=float(item.get('confidence', 0.5)),
                        reasoning=item.get('reasoning', ''),
                        risk_level=item.get('risk_level', 'medium'),
                        expected_value=item.get('expected_value', 'medium'),
                        prerequisites=item.get('prerequisites', [])
                    ))
        except Exception as e:
            self._log(f"Failed to parse suggestions: {e}")
        
        return suggestions
    
    def _rule_based_suggestions(self, current_host: str = None) -> List[JumpSuggestion]:
        """Generate suggestions using rule-based logic (no AI)"""
        suggestions = []
        
        # Priority 1: Domain Controllers (if we have domain admin creds)
        domain_admin_creds = [c for c, i in self.credentials.items() if i.is_domain_admin]
        dcs = [h for h, i in self.hosts.items() if i.is_dc and not i.compromised]
        
        if domain_admin_creds and dcs:
            for dc in dcs[:2]:
                suggestions.append(JumpSuggestion(
                    target=dc,
                    method='wmiexec',
                    credentials=domain_admin_creds[0],
                    confidence=0.85,
                    reasoning='Domain Controller with domain admin credentials',
                    risk_level='high',
                    expected_value='critical'
                ))
        
        # Priority 2: Admin workstations (for credential harvesting)
        admin_ws = [h for h, i in self.hosts.items() 
                   if i.is_admin_workstation and not i.compromised]
        
        for ws in admin_ws[:2]:
            best_cred = self._find_best_credential_for_host(ws)
            if best_cred:
                suggestions.append(JumpSuggestion(
                    target=ws,
                    method='wmiexec',
                    credentials=best_cred,
                    confidence=0.7,
                    reasoning='Admin workstation - likely has cached credentials',
                    risk_level='medium',
                    expected_value='high'
                ))
        
        # Priority 3: Any uncompromised host with untested credentials
        for hostname, host in self.hosts.items():
            if host.compromised:
                continue
            
            for cred_name, cred in self.credentials.items():
                if hostname not in cred.tested_hosts:
                    suggestions.append(JumpSuggestion(
                        target=hostname,
                        method='wmiexec',
                        credentials=cred_name,
                        confidence=0.5,
                        reasoning='Untested credential/host combination',
                        risk_level='low',
                        expected_value='medium'
                    ))
                    break
            
            if len(suggestions) >= 5:
                break
        
        # Sort by confidence
        suggestions.sort(key=lambda x: x.confidence, reverse=True)
        return suggestions[:5]
    
    def _find_best_credential_for_host(self, hostname: str) -> Optional[str]:
        """Find the best credential to use for a host"""
        
        # Prefer credentials that have worked on similar hosts
        for cred_name, cred in self.credentials.items():
            if cred.is_domain_admin:
                return cred_name
        
        # Fall back to any credential
        if self.credentials:
            return list(self.credentials.keys())[0]
        
        return None
    
    def _simple_path(self, start: str, goal: str) -> List[Dict]:
        """Generate a simple path without AI"""
        return [
            {'target': start, 'method': 'initial', 'credential': '', 'reasoning': 'Starting point'},
            {'target': goal, 'method': 'wmiexec', 'credential': 'domain_admin', 'reasoning': 'Direct path to goal'}
        ]
    
    def _host_to_dict(self, host: HostIntel) -> Dict:
        """Convert HostIntel to dict for JSON serialization"""
        return {
            'hostname': host.hostname,
            'ip': host.ip,
            'compromised': host.compromised,
            'is_dc': host.is_dc,
            'is_admin_ws': host.is_admin_workstation,
            'av': host.av_product,
            'services': host.services[:5] if host.services else []
        }
    
    def _cred_to_dict(self, cred: CredentialIntel) -> Dict:
        """Convert CredentialIntel to dict for JSON serialization"""
        return {
            'username': cred.username,
            'domain': cred.domain,
            'type': cred.cred_type,
            'is_domain_admin': cred.is_domain_admin,
            'successful_hosts': cred.successful_hosts
        }
    
    def _log(self, message: str):
        """Log to intel table"""
        log_to_intel(self.scan_id, "AI_LATERAL_GUIDE", message)
        print(f"[AI_LATERAL] {message}")
    
    def get_summary(self) -> Dict:
        """Get summary of current state"""
        return {
            'total_hosts': len(self.hosts),
            'compromised_hosts': sum(1 for h in self.hosts.values() if h.compromised),
            'total_credentials': len(self.credentials),
            'domain_admin_creds': sum(1 for c in self.credentials.values() if c.is_domain_admin),
            'total_movements': len(self.movement_history),
            'successful_movements': sum(1 for m in self.movement_history if m['success']),
            'dcs_compromised': sum(1 for h in self.hosts.values() if h.is_dc and h.compromised)
        }
