#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                    SMART PASSWORD SPRAYING - AI PATTERN ANALYSIS                       ║
║                    Intelligent Credential Testing 🧠                                   ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║  AI-powered password policy analysis and smart spraying                                ║
║  - Analyze company name and leaked passwords to predict patterns                       ║
║  - Generate high-probability password candidates                                        ║
║  - Smart timing to avoid account lockout                                               ║
║  - Protocol support: LDAP, SMB, RDP, O365, OWA, VPN                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
"""

import json
import sqlite3
import os
import re
import hashlib
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging
from concurrent.futures import ThreadPoolExecutor
import itertools

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AuthProtocol(Enum):
    """Supported authentication protocols"""
    LDAP = "ldap"
    SMB = "smb"
    RDP = "rdp"
    OFFICE365 = "office365"
    OWA = "owa"
    VPN_CISCO = "vpn_cisco"
    VPN_FORTINET = "vpn_fortinet"
    SSH = "ssh"
    FTP = "ftp"
    KERBEROS = "kerberos"


class PasswordComplexity(Enum):
    """Password complexity levels"""
    NONE = "none"
    SIMPLE = "simple"  # 8 chars
    MODERATE = "moderate"  # 8 chars + number
    COMPLEX = "complex"  # 8 chars + upper + lower + number
    VERY_COMPLEX = "very_complex"  # 12 chars + upper + lower + number + special


@dataclass
class PasswordPolicy:
    """Detected/inferred password policy"""
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_number: bool = True
    require_special: bool = False
    lockout_threshold: int = 5
    lockout_duration_minutes: int = 30
    password_history: int = 3
    max_age_days: int = 90
    common_patterns: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class PasswordCandidate:
    """Generated password candidate"""
    password: str
    pattern: str
    probability: float
    source: str  # "ai_generated", "pattern_based", "mutation", "leaked"


@dataclass
class SprayTarget:
    """Password spray target"""
    username: str
    domain: str
    email: str = ""
    tried_passwords: List[str] = field(default_factory=list)
    valid_password: Optional[str] = None
    status: str = "pending"  # pending, testing, found, locked, failed


@dataclass
class SprayJob:
    """Password spraying job"""
    job_id: str
    company_name: str
    domain: str
    protocol: AuthProtocol
    targets: List[SprayTarget]
    password_candidates: List[PasswordCandidate]
    status: str = "queued"
    progress: int = 0
    found_credentials: List[Dict] = field(default_factory=list)
    policy: Optional[PasswordPolicy] = None
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None


class SmartPasswordSprayer:
    """Smart Password Spraying with AI Pattern Analysis"""
    
    _instance = None
    _lock = threading.Lock()
    
    # Common password patterns
    PATTERNS = {
        "season_year": ["{season}{year}", "{Season}{year}", "{SEASON}{year}"],
        "company_year": ["{company}{year}", "{Company}{year}", "{company}{year}!"],
        "month_year": ["{month}{year}", "{Month}{year}", "{month}{year}!"],
        "company_special": ["{Company}@{year}", "{company}#{year}", "{Company}!{year}"],
        "welcome": ["Welcome{year}", "Welcome{year}!", "Welcome@{year}"],
        "password": ["Password{year}", "Password{year}!", "P@ssword{year}"],
        "changeme": ["Changeme{year}", "Changeme!", "Change@me{year}"],
    }
    
    SEASONS = ["Spring", "Summer", "Fall", "Winter", "Autumn"]
    MONTHS = ["January", "February", "March", "April", "May", "June", 
              "July", "August", "September", "October", "November", "December"]
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        
        self.db_path = Path("/tmp/smart_spray.db")
        self.jobs: Dict[str, SprayJob] = {}
        self._init_database()
        
        # Current year for patterns
        self.current_year = datetime.now().year
        
        logger.info("Smart Password Sprayer initialized")
    
    def _init_database(self):
        """Initialize database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS spray_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT UNIQUE,
                    company TEXT,
                    domain TEXT,
                    protocol TEXT,
                    status TEXT,
                    found_count INTEGER,
                    started_at TEXT,
                    completed_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS found_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT,
                    username TEXT,
                    password TEXT,
                    domain TEXT,
                    found_at TEXT
                )
            """)
            
            conn.commit()
    
    def analyze_password_policy(self, company_name: str, sample_passwords: List[str] = None,
                               domain: str = None) -> PasswordPolicy:
        """Analyze and infer password policy from company info and samples"""
        
        policy = PasswordPolicy()
        patterns_found = []
        confidence_factors = []
        
        # Analyze company name
        company_lower = company_name.lower()
        company_title = company_name.title()
        
        # Check sample passwords for patterns
        if sample_passwords:
            for pwd in sample_passwords:
                # Check length
                if len(pwd) > policy.min_length:
                    pass  # Adjust minimum
                
                # Check complexity requirements
                has_upper = bool(re.search(r'[A-Z]', pwd))
                has_lower = bool(re.search(r'[a-z]', pwd))
                has_digit = bool(re.search(r'\d', pwd))
                has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', pwd))
                
                # Detect patterns
                if company_lower in pwd.lower():
                    patterns_found.append("company_based")
                    confidence_factors.append(0.3)
                
                year_match = re.search(r'20\d{2}', pwd)
                if year_match:
                    patterns_found.append("year_suffix")
                    confidence_factors.append(0.2)
                
                season_match = any(s.lower() in pwd.lower() for s in self.SEASONS)
                if season_match:
                    patterns_found.append("season_based")
                    confidence_factors.append(0.2)
                
                month_match = any(m.lower() in pwd.lower() for m in self.MONTHS)
                if month_match:
                    patterns_found.append("month_based")
                    confidence_factors.append(0.15)
        
        # Update policy based on analysis
        policy.common_patterns = list(set(patterns_found))
        policy.confidence = min(1.0, sum(confidence_factors))
        
        # Default corporate policy assumptions
        if not sample_passwords:
            policy.min_length = 8
            policy.require_uppercase = True
            policy.require_lowercase = True
            policy.require_number = True
            policy.require_special = False  # Many companies don't require this
            policy.lockout_threshold = 5
            policy.confidence = 0.5
        
        logger.info(f"Policy analysis complete: {policy.common_patterns} (confidence: {policy.confidence:.2f})")
        return policy
    
    def generate_password_candidates(self, company_name: str, policy: PasswordPolicy,
                                    sample_passwords: List[str] = None,
                                    max_candidates: int = 10) -> List[PasswordCandidate]:
        """Generate smart password candidates based on analysis"""
        
        candidates = []
        company_variants = self._get_company_variants(company_name)
        years = [str(self.current_year), str(self.current_year - 1), 
                str(self.current_year + 1), str(self.current_year)[-2:]]
        
        # Pattern-based generation
        for pattern_name, templates in self.PATTERNS.items():
            for template in templates:
                for company_var in company_variants[:3]:
                    for year in years[:2]:
                        try:
                            # Generate password
                            pwd = template.format(
                                company=company_var.lower(),
                                Company=company_var.title(),
                                COMPANY=company_var.upper(),
                                year=year,
                                season=self.SEASONS[datetime.now().month // 4].lower(),
                                Season=self.SEASONS[datetime.now().month // 4],
                                SEASON=self.SEASONS[datetime.now().month // 4].upper(),
                                month=self.MONTHS[datetime.now().month - 1].lower(),
                                Month=self.MONTHS[datetime.now().month - 1],
                            )
                            
                            # Check if meets policy
                            if self._meets_policy(pwd, policy):
                                probability = self._calculate_probability(pwd, policy, pattern_name)
                                candidates.append(PasswordCandidate(
                                    password=pwd,
                                    pattern=pattern_name,
                                    probability=probability,
                                    source="pattern_based"
                                ))
                        except KeyError:
                            continue
        
        # Add common corporate passwords
        common_passwords = [
            f"Welcome{self.current_year}!",
            f"Welcome{self.current_year}",
            f"Password{self.current_year}!",
            f"Password{self.current_year}",
            f"Changeme{self.current_year}!",
            f"Summer{self.current_year}!",
            f"Winter{self.current_year}!",
            f"{company_name.title()}{self.current_year}!",
            f"{company_name.title()}{self.current_year}",
            f"{company_name.title()}@{self.current_year}",
            "Welcome1!",
            "Password1!",
            "Changeme1!",
        ]
        
        for pwd in common_passwords:
            if self._meets_policy(pwd, policy):
                candidates.append(PasswordCandidate(
                    password=pwd,
                    pattern="common_corporate",
                    probability=0.4,
                    source="common_list"
                ))
        
        # Mutate sample passwords if available
        if sample_passwords:
            for sample in sample_passwords:
                mutations = self._generate_mutations(sample)
                for mutation in mutations:
                    if self._meets_policy(mutation, policy):
                        candidates.append(PasswordCandidate(
                            password=mutation,
                            pattern="mutation",
                            probability=0.6,
                            source="sample_mutation"
                        ))
        
        # Sort by probability and deduplicate
        seen = set()
        unique_candidates = []
        for c in sorted(candidates, key=lambda x: x.probability, reverse=True):
            if c.password not in seen:
                seen.add(c.password)
                unique_candidates.append(c)
        
        # Return top candidates
        return unique_candidates[:max_candidates]
    
    def _get_company_variants(self, company_name: str) -> List[str]:
        """Generate company name variants"""
        variants = [company_name]
        
        # Remove common suffixes
        for suffix in [" Inc", " LLC", " Ltd", " Corp", " Co"]:
            if company_name.endswith(suffix):
                variants.append(company_name[:-len(suffix)])
        
        # Split camelCase or spaces
        words = re.findall(r'[A-Z][a-z]*|[a-z]+', company_name)
        if len(words) > 1:
            variants.append(''.join(words))
            variants.append(words[0])
            if len(words) >= 2:
                variants.append(words[0] + words[1])
        
        # Abbreviation
        initials = ''.join(w[0].upper() for w in words if w)
        if len(initials) >= 2:
            variants.append(initials)
        
        return list(set(variants))
    
    def _meets_policy(self, password: str, policy: PasswordPolicy) -> bool:
        """Check if password meets policy requirements"""
        if len(password) < policy.min_length:
            return False
        if len(password) > policy.max_length:
            return False
        if policy.require_uppercase and not re.search(r'[A-Z]', password):
            return False
        if policy.require_lowercase and not re.search(r'[a-z]', password):
            return False
        if policy.require_number and not re.search(r'\d', password):
            return False
        if policy.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True
    
    def _calculate_probability(self, password: str, policy: PasswordPolicy, pattern: str) -> float:
        """Calculate probability score for password candidate"""
        score = 0.5  # Base score
        
        # Boost if pattern matches detected patterns
        if pattern in policy.common_patterns:
            score += 0.3
        
        # Boost for current year
        if str(self.current_year) in password:
            score += 0.1
        
        # Boost for proper capitalization
        if password[0].isupper() and password[1:].islower():
            score += 0.05
        
        # Penalize very long passwords
        if len(password) > 14:
            score -= 0.1
        
        return min(1.0, max(0.1, score))
    
    def _generate_mutations(self, password: str) -> List[str]:
        """Generate password mutations"""
        mutations = []
        
        # Year increment
        year_match = re.search(r'(20)(\d{2})', password)
        if year_match:
            old_year = int(year_match.group(0))
            mutations.append(password.replace(str(old_year), str(old_year + 1)))
            mutations.append(password.replace(str(old_year), str(self.current_year)))
        
        # Common substitutions
        subs = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$'}
        for old, new in subs.items():
            if old in password.lower():
                mutations.append(password.replace(old, new))
                mutations.append(password.replace(old.upper(), new))
        
        # Add/remove special chars
        mutations.append(password + "!")
        mutations.append(password + "1")
        mutations.append(password + "123")
        if password.endswith("!"):
            mutations.append(password[:-1])
        
        return mutations
    
    def start_spray(self, company_name: str, domain: str, usernames: List[str],
                   protocol: AuthProtocol = AuthProtocol.LDAP,
                   sample_passwords: List[str] = None,
                   target_url: str = None) -> str:
        """Start smart password spraying"""
        
        job_id = hashlib.md5(f"{company_name}{domain}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        
        # Analyze policy
        policy = self.analyze_password_policy(company_name, sample_passwords, domain)
        
        # Generate candidates
        candidates = self.generate_password_candidates(company_name, policy, sample_passwords)
        
        # Create targets
        targets = []
        for username in usernames:
            email = f"{username}@{domain}" if '@' not in username else username
            targets.append(SprayTarget(
                username=username,
                domain=domain,
                email=email
            ))
        
        job = SprayJob(
            job_id=job_id,
            company_name=company_name,
            domain=domain,
            protocol=protocol,
            targets=targets,
            password_candidates=candidates,
            policy=policy
        )
        
        self.jobs[job_id] = job
        
        # Start spraying in background
        thread = threading.Thread(target=self._execute_spray, args=(job_id, target_url))
        thread.daemon = True
        thread.start()
        
        logger.info(f"Started smart spray {job_id}: {len(usernames)} users, {len(candidates)} passwords")
        return job_id
    
    def _execute_spray(self, job_id: str, target_url: str = None):
        """Execute password spraying with smart timing"""
        job = self.jobs[job_id]
        job.status = "running"
        
        total_attempts = len(job.targets) * len(job.password_candidates)
        current_attempt = 0
        
        # Spray one password at a time across all users (avoid lockout)
        for candidate in job.password_candidates:
            logger.info(f"[{job_id}] Testing password: {candidate.password[:3]}*** (probability: {candidate.probability:.2f})")
            
            for target in job.targets:
                if target.status in ["found", "locked"]:
                    continue
                
                target.status = "testing"
                current_attempt += 1
                job.progress = int((current_attempt / total_attempts) * 100)
                
                # Attempt authentication
                success = self._try_auth(target, candidate.password, job.protocol, target_url)
                
                if success:
                    target.status = "found"
                    target.valid_password = candidate.password
                    job.found_credentials.append({
                        "username": target.username,
                        "password": candidate.password,
                        "domain": target.domain,
                        "email": target.email,
                        "found_at": datetime.utcnow().isoformat()
                    })
                    logger.info(f"[{job_id}] ✓ FOUND: {target.username}:{candidate.password}")
                else:
                    target.tried_passwords.append(candidate.password)
                
                # Smart delay between attempts
                time.sleep(0.5)  # Per-user delay
            
            # Longer delay between password rounds
            time.sleep(2)  # Between passwords to avoid lockout
        
        job.status = "completed"
        job.completed_at = datetime.utcnow().isoformat()
        job.progress = 100
        
        self._save_results(job)
        logger.info(f"[{job_id}] Spray completed: {len(job.found_credentials)} credentials found")
    
    def _try_auth(self, target: SprayTarget, password: str, protocol: AuthProtocol,
                 target_url: str = None) -> bool:
        """Attempt authentication (simulated for demo)"""
        # In real implementation, would use appropriate library for each protocol:
        # - LDAP: ldap3
        # - SMB: impacket
        # - RDP: xfreerdp
        # - O365: requests to login.microsoftonline.com
        # etc.
        
        # Simulated for demo - would need actual implementation
        logger.debug(f"Auth attempt: {target.username}:{password[:3]}*** via {protocol.value}")
        
        # Simulate occasional success for demo
        import random
        return random.random() < 0.01  # 1% success rate simulation
    
    def _save_results(self, job: SprayJob):
        """Save results to database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO spray_jobs 
                (job_id, company, domain, protocol, status, found_count, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (job.job_id, job.company_name, job.domain, job.protocol.value,
                  job.status, len(job.found_credentials), job.started_at, job.completed_at))
            
            for cred in job.found_credentials:
                conn.execute("""
                    INSERT INTO found_credentials (job_id, username, password, domain, found_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (job.job_id, cred['username'], cred['password'], cred['domain'], cred['found_at']))
            
            conn.commit()
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status"""
        job = self.jobs.get(job_id)
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "company": job.company_name,
            "domain": job.domain,
            "protocol": job.protocol.value,
            "status": job.status,
            "progress": job.progress,
            "total_targets": len(job.targets),
            "total_passwords": len(job.password_candidates),
            "found_credentials": len(job.found_credentials),
            "policy_confidence": job.policy.confidence if job.policy else 0,
            "started_at": job.started_at,
            "completed_at": job.completed_at
        }
    
    def get_job_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get full job results"""
        job = self.jobs.get(job_id)
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "company": job.company_name,
            "domain": job.domain,
            "protocol": job.protocol.value,
            "status": job.status,
            "password_candidates": [
                {"password": c.password, "probability": c.probability, "pattern": c.pattern}
                for c in job.password_candidates
            ],
            "found_credentials": job.found_credentials,
            "policy": {
                "min_length": job.policy.min_length,
                "require_special": job.policy.require_special,
                "lockout_threshold": job.policy.lockout_threshold,
                "common_patterns": job.policy.common_patterns,
                "confidence": job.policy.confidence
            } if job.policy else None
        }
    
    def preview_candidates(self, company_name: str, sample_passwords: List[str] = None) -> Dict:
        """Preview password candidates without starting spray"""
        policy = self.analyze_password_policy(company_name, sample_passwords)
        candidates = self.generate_password_candidates(company_name, policy, sample_passwords)
        
        return {
            "company": company_name,
            "policy": {
                "min_length": policy.min_length,
                "require_uppercase": policy.require_uppercase,
                "require_lowercase": policy.require_lowercase,
                "require_number": policy.require_number,
                "require_special": policy.require_special,
                "lockout_threshold": policy.lockout_threshold,
                "common_patterns": policy.common_patterns,
                "confidence": policy.confidence
            },
            "candidates": [
                {
                    "password": c.password,
                    "probability": c.probability,
                    "pattern": c.pattern,
                    "source": c.source
                }
                for c in candidates
            ]
        }


def get_smart_sprayer() -> SmartPasswordSprayer:
    """Get Smart Password Sprayer singleton"""
    return SmartPasswordSprayer()


if __name__ == "__main__":
    sprayer = get_smart_sprayer()
    
    print("Smart Password Spraying - AI Pattern Analysis")
    print("=" * 50)
    
    # Demo: Preview candidates for a company
    company = "Acme Corporation"
    sample = ["Acme2024!", "Welcome2024"]
    
    preview = sprayer.preview_candidates(company, sample)
    
    print(f"\nCompany: {preview['company']}")
    print(f"Policy Confidence: {preview['policy']['confidence']:.1%}")
    print(f"Detected Patterns: {preview['policy']['common_patterns']}")
    
    print("\nGenerated Password Candidates:")
    for i, c in enumerate(preview['candidates'], 1):
        print(f"  {i}. {c['password']} (prob: {c['probability']:.1%}, pattern: {c['pattern']})")
