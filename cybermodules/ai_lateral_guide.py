"""
AI-Guided Lateral Movement
Integrates LLM for intelligent "next best jump" suggestions during lateral movement
Analyzes network topology, credentials, and defenses to optimize attack paths
Includes evasion profile scoring for detection risk assessment
"""

import json
import os
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from cybermodules.helpers import log_to_intel

# Import evasion profile metrics
try:
    from cybermodules.lateral_evasion import (
        EvasionProfile, ProfileMetrics, PROFILE_METRICS, get_profile_metrics
    )
    HAS_EVASION_METRICS = True
except ImportError:
    HAS_EVASION_METRICS = False
    EvasionProfile = None

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
    """AI-generated jump suggestion with evasion scoring"""
    target: str
    method: str
    credentials: str
    confidence: float
    reasoning: str
    risk_level: str  # low, medium, high
    expected_value: str  # low, medium, high, critical
    prerequisites: List[str] = None
    # Evasion profile scoring
    recommended_profile: str = "stealth"  # none, default, stealth, paranoid, aggressive
    detection_risk: float = 0.5  # 0.0 - 1.0
    speed_impact: str = "moderate"  # fast, moderate, slow, very_slow
    evasion_notes: List[str] = None
    
    def __post_init__(self):
        if self.prerequisites is None:
            self.prerequisites = []
        if self.evasion_notes is None:
            self.evasion_notes = []


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
        """Analyze defenses on a target host and recommend evasion profile"""
        if target not in self.hosts:
            return {'error': 'Host not in intel database'}
        
        host = self.hosts[target]
        
        analysis = {
            'host': target,
            'av_detected': bool(host.av_product),
            'av_product': host.av_product,
            'recommended_evasion': [],
            'risk_factors': [],
            'suggested_approach': '',
            # Evasion profile scoring
            'recommended_profile': 'stealth',
            'profile_metrics': None,
            'detection_risk_by_profile': {}
        }
        
        # AV-specific recommendations and profile scoring
        av_evasion_map = {
            'defender': {
                'techniques': ['amsi_bypass', 'etw_patching', 'unhook_ntdll'],
                'min_profile': 'default',
                'recommended_profile': 'stealth'
            },
            'crowdstrike': {
                'techniques': ['direct_syscalls', 'sleep_obfuscation', 'process_hollowing', 'srdi'],
                'min_profile': 'stealth',
                'recommended_profile': 'paranoid'
            },
            'sentinelone': {
                'techniques': ['sleep_obfuscation', 'thread_execution_hijacking', 'entropy_jitter'],
                'min_profile': 'stealth',
                'recommended_profile': 'paranoid'
            },
            'carbonblack': {
                'techniques': ['process_hollowing', 'dll_unhooking', 'doppelganging'],
                'min_profile': 'stealth',
                'recommended_profile': 'stealth'
            },
            'elastic': {
                'techniques': ['sleep_obfuscation', 'process_hollowing'],
                'min_profile': 'stealth',
                'recommended_profile': 'paranoid'
            }
        }
        
        if host.av_product:
            av_lower = host.av_product.lower()
            for av_name, av_config in av_evasion_map.items():
                if av_name in av_lower:
                    analysis['recommended_evasion'].extend(av_config['techniques'])
                    analysis['recommended_profile'] = av_config['recommended_profile']
                    break
        
        # Risk factors affect profile recommendation
        risk_score = 0
        if host.is_dc:
            analysis['risk_factors'].append('Domain Controller - high monitoring')
            risk_score += 2
        if 'admin' in target.lower():
            analysis['risk_factors'].append('Admin workstation - likely monitored')
            risk_score += 1
        if host.av_product:
            analysis['risk_factors'].append(f'AV present: {host.av_product}')
            risk_score += 1
        
        # Adjust profile based on risk score
        if risk_score >= 3:
            analysis['recommended_profile'] = 'paranoid'
        elif risk_score >= 2:
            analysis['recommended_profile'] = 'stealth'
        
        # Get detection risk for each profile
        analysis['detection_risk_by_profile'] = self.get_evasion_profile_scoring(target)
        
        # Add profile metrics if available
        if HAS_EVASION_METRICS:
            try:
                profile_enum = EvasionProfile(analysis['recommended_profile'])
                metrics = get_profile_metrics(profile_enum)
                analysis['profile_metrics'] = {
                    'detection_risk': metrics.detection_risk,
                    'speed_multiplier': metrics.speed_multiplier,
                    'stealth_score': metrics.stealth_score,
                    'summary': metrics.get_summary()
                }
            except Exception:
                pass
        
        return analysis
    
    def get_evasion_profile_scoring(self, target: str) -> Dict[str, Dict]:
        """
        Get detection risk scoring for all evasion profiles against a target
        Returns metrics like 'Paranoid modda detection riski %80 azalır ama 5x yavaşlar'
        """
        if target not in self.hosts:
            return {}
        
        host = self.hosts[target]
        scoring = {}
        
        # Base detection risk based on AV/EDR
        base_risk = 0.5  # 50% baseline
        
        if host.av_product:
            av_lower = host.av_product.lower()
            if 'crowdstrike' in av_lower or 'sentinelone' in av_lower:
                base_risk = 0.85  # Advanced EDR = high baseline risk
            elif 'defender' in av_lower:
                base_risk = 0.60  # Defender = moderate risk
            elif 'carbonblack' in av_lower:
                base_risk = 0.75  # CB = moderately high
        
        if host.is_dc:
            base_risk = min(base_risk + 0.15, 0.95)  # DCs have higher monitoring
        
        # Profile-specific scoring
        profiles = [
            ('none', 1.0, 1.0, "Evasion yok - anında tespit"),
            ('default', 0.7, 1.2, "Temel AMSI bypass - hızlı ama riskli"),
            ('stealth', 0.4, 2.0, "Orta düzey gizlilik - dengeli"),
            ('paranoid', 0.2, 5.0, "Maksimum gizlilik - çok yavaş"),
            ('aggressive', 0.55, 1.5, "Hızlı saldırı - orta risk"),
        ]
        
        for profile_name, risk_modifier, speed_mult, description in profiles:
            actual_risk = base_risk * risk_modifier
            detection_reduction = int((1 - risk_modifier) * 100)
            
            scoring[profile_name] = {
                'detection_risk': round(actual_risk, 2),
                'detection_risk_percent': f"{int(actual_risk * 100)}%",
                'detection_reduction': f"{detection_reduction}% azalma",
                'speed_multiplier': speed_mult,
                'speed_impact': f"{speed_mult}x yavaş" if speed_mult > 1 else "baseline",
                'description': description,
                'summary': f"{profile_name.upper()}: {detection_reduction}% risk azalması, {speed_mult}x yavaşlama"
            }
        
        return scoring
    
    def recommend_evasion_for_jump(self, target: str, time_critical: bool = False) -> Tuple[str, Dict]:
        """
        Recommend optimal evasion profile for a specific jump
        
        Args:
            target: Target hostname
            time_critical: If True, prefer faster profiles
        
        Returns:
            Tuple of (profile_name, profile_details)
        """
        scoring = self.get_evasion_profile_scoring(target)
        
        if not scoring:
            return ('stealth', {'reason': 'Default recommendation - no intel'})
        
        if time_critical:
            # Prefer aggressive or default for speed
            if scoring.get('aggressive', {}).get('detection_risk', 1.0) < 0.7:
                return ('aggressive', {
                    **scoring['aggressive'],
                    'reason': 'Time-critical: aggressive profile seçildi, kabul edilebilir risk'
                })
            return ('default', {
                **scoring.get('default', {}),
                'reason': 'Time-critical: default profile, hız öncelikli'
            })
        
        # Normal operation: balance risk and speed
        host = self.hosts.get(target)
        
        # High-value targets get paranoid
        if host and (host.is_dc or host.is_admin_workstation):
            return ('paranoid', {
                **scoring.get('paranoid', {}),
                'reason': f'Yüksek değerli hedef ({target}): paranoid profil önerilir'
            })
        
        # EDR environments get paranoid
        if host and host.av_product:
            av_lower = host.av_product.lower()
            if 'crowdstrike' in av_lower or 'sentinelone' in av_lower:
                return ('paranoid', {
                    **scoring.get('paranoid', {}),
                    'reason': f'Gelişmiş EDR tespit edildi ({host.av_product}): paranoid profil şart'
                })
        
        # Default: stealth
        return ('stealth', {
            **scoring.get('stealth', {}),
            'reason': 'Standart hedef: stealth profil dengeli seçim'
        })

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
        """Generate suggestions using rule-based logic with evasion scoring"""
        suggestions = []
        
        # Priority 1: Domain Controllers (if we have domain admin creds)
        domain_admin_creds = [c for c, i in self.credentials.items() if i.is_domain_admin]
        dcs = [h for h, i in self.hosts.items() if i.is_dc and not i.compromised]
        
        if domain_admin_creds and dcs:
            for dc in dcs[:2]:
                # Get evasion recommendation for DC
                profile, profile_info = self.recommend_evasion_for_jump(dc)
                
                suggestions.append(JumpSuggestion(
                    target=dc,
                    method='wmiexec',
                    credentials=domain_admin_creds[0],
                    confidence=0.85,
                    reasoning='Domain Controller with domain admin credentials',
                    risk_level='high',
                    expected_value='critical',
                    # Evasion scoring
                    recommended_profile=profile,
                    detection_risk=profile_info.get('detection_risk', 0.3),
                    speed_impact='very_slow' if profile == 'paranoid' else 'slow',
                    evasion_notes=[
                        f"Önerilen profil: {profile.upper()}",
                        profile_info.get('reason', ''),
                        f"Tespit riski: {profile_info.get('detection_risk_percent', '30%')}",
                        "DC için maksimum gizlilik önerilir"
                    ]
                ))
        
        # Priority 2: Admin workstations (for credential harvesting)
        admin_ws = [h for h, i in self.hosts.items() 
                   if i.is_admin_workstation and not i.compromised]
        
        for ws in admin_ws[:2]:
            best_cred = self._find_best_credential_for_host(ws)
            if best_cred:
                profile, profile_info = self.recommend_evasion_for_jump(ws)
                
                suggestions.append(JumpSuggestion(
                    target=ws,
                    method='wmiexec',
                    credentials=best_cred,
                    confidence=0.7,
                    reasoning='Admin workstation - likely has cached credentials',
                    risk_level='medium',
                    expected_value='high',
                    recommended_profile=profile,
                    detection_risk=profile_info.get('detection_risk', 0.4),
                    speed_impact='slow' if profile in ['paranoid', 'stealth'] else 'moderate',
                    evasion_notes=[
                        f"Önerilen profil: {profile.upper()}",
                        "Admin WS - credential harvesting potansiyeli yüksek"
                    ]
                ))
        
        # Priority 3: Any uncompromised host with untested credentials
        for hostname, host in self.hosts.items():
            if host.compromised:
                continue
            
            for cred_name, cred in self.credentials.items():
                if hostname not in cred.tested_hosts:
                    profile, profile_info = self.recommend_evasion_for_jump(hostname)
                    
                    suggestions.append(JumpSuggestion(
                        target=hostname,
                        method='wmiexec',
                        credentials=cred_name,
                        confidence=0.5,
                        reasoning='Untested credential/host combination',
                        risk_level='low',
                        expected_value='medium',
                        recommended_profile=profile,
                        detection_risk=profile_info.get('detection_risk', 0.5),
                        speed_impact='moderate',
                        evasion_notes=[f"Önerilen profil: {profile.upper()}"]
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
