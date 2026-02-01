#!/usr/bin/env python3
"""
Advanced Target Management System
==================================
CSV import, target grouping, OSINT integration, domain analysis

Author: CyberGhost Pro Team
"""

import csv
import json
import sqlite3
import secrets
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import requests


class TargetRiskLevel(Enum):
    """Target risk assessment"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Target:
    """Phishing target"""
    target_id: str
    email: str
    first_name: str = ""
    last_name: str = ""
    company: str = ""
    department: str = ""
    position: str = ""
    phone: str = ""
    
    # Enrichment data
    linkedin_url: str = ""
    twitter_handle: str = ""
    last_active: Optional[datetime] = None
    
    # Risk assessment
    risk_level: TargetRiskLevel = TargetRiskLevel.MEDIUM
    security_aware: bool = False
    mfa_enabled: bool = False
    
    # Grouping
    group_ids: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    # Campaign history
    campaigns_sent: int = 0
    campaigns_opened: int = 0
    campaigns_clicked: int = 0
    
    # Metadata
    notes: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class TargetGroup:
    """Target group/segment"""
    group_id: str
    name: str
    description: str = ""
    filter_criteria: Dict[str, Any] = field(default_factory=dict)
    target_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)


class TargetManager:
    """Advanced target management system"""
    
    def __init__(self, db_path: str = "/tmp/phishing_targets.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Targets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                target_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                first_name TEXT,
                last_name TEXT,
                company TEXT,
                department TEXT,
                position TEXT,
                phone TEXT,
                enrichment JSON,
                risk_level TEXT,
                group_ids JSON,
                tags JSON,
                campaign_stats JSON,
                notes TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        # Target groups table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS target_groups (
                group_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                filter_criteria JSON,
                target_count INTEGER,
                created_at TEXT
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_email ON targets(email)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_company ON targets(company)")
        
        conn.commit()
        conn.close()
    
    def add_target(self, target: Target) -> Dict[str, Any]:
        """Add new target"""
        if not target.target_id:
            target.target_id = self._generate_target_id()
        
        # Validate email
        if not self._validate_email(target.email):
            return {"success": False, "error": "Invalid email address"}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            enrichment = {
                "linkedin_url": target.linkedin_url,
                "twitter_handle": target.twitter_handle,
                "last_active": target.last_active.isoformat() if target.last_active else None,
                "security_aware": target.security_aware,
                "mfa_enabled": target.mfa_enabled
            }
            
            campaign_stats = {
                "campaigns_sent": target.campaigns_sent,
                "campaigns_opened": target.campaigns_opened,
                "campaigns_clicked": target.campaigns_clicked
            }
            
            cursor.execute("""
                INSERT INTO targets (target_id, email, first_name, last_name, company, department, position, phone, enrichment, risk_level, group_ids, tags, campaign_stats, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target.target_id,
                target.email.lower(),
                target.first_name,
                target.last_name,
                target.company,
                target.department,
                target.position,
                target.phone,
                json.dumps(enrichment),
                target.risk_level.value,
                json.dumps(target.group_ids),
                json.dumps(target.tags),
                json.dumps(campaign_stats),
                target.notes,
                target.created_at.isoformat(),
                target.updated_at.isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "target_id": target.target_id,
                "message": f"Target {target.email} added successfully"
            }
        
        except sqlite3.IntegrityError:
            conn.close()
            return {"success": False, "error": f"Target {target.email} already exists"}
    
    def import_from_csv(self, csv_file_path: str, mapping: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Import targets from CSV file"""
        if mapping is None:
            mapping = {
                "email": "email",
                "first_name": "first_name",
                "last_name": "last_name",
                "company": "company",
                "department": "department",
                "position": "position"
            }
        
        imported = 0
        errors = []
        
        try:
            with open(csv_file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    try:
                        target = Target(
                            target_id="",
                            email=row.get(mapping.get("email", "email"), ""),
                            first_name=row.get(mapping.get("first_name", "first_name"), ""),
                            last_name=row.get(mapping.get("last_name", "last_name"), ""),
                            company=row.get(mapping.get("company", "company"), ""),
                            department=row.get(mapping.get("department", "department"), ""),
                            position=row.get(mapping.get("position", "position"), "")
                        )
                        
                        result = self.add_target(target)
                        if result["success"]:
                            imported += 1
                        else:
                            errors.append(f"{target.email}: {result['error']}")
                    
                    except Exception as e:
                        errors.append(f"Row error: {str(e)}")
            
            return {
                "success": True,
                "imported": imported,
                "errors": errors,
                "message": f"Imported {imported} targets successfully"
            }
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def create_group(self, group: TargetGroup) -> Dict[str, Any]:
        """Create target group"""
        if not group.group_id:
            group.group_id = self._generate_group_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO target_groups (group_id, name, description, filter_criteria, target_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            group.group_id,
            group.name,
            group.description,
            json.dumps(group.filter_criteria),
            group.target_count,
            group.created_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "group_id": group.group_id,
            "message": f"Group '{group.name}' created successfully"
        }
    
    def assign_to_group(self, target_ids: List[str], group_id: str) -> Dict[str, Any]:
        """Assign targets to group"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        updated = 0
        for target_id in target_ids:
            cursor.execute("SELECT group_ids FROM targets WHERE target_id = ?", (target_id,))
            row = cursor.fetchone()
            
            if row:
                group_ids = json.loads(row[0])
                if group_id not in group_ids:
                    group_ids.append(group_id)
                    cursor.execute("UPDATE targets SET group_ids = ?, updated_at = ? WHERE target_id = ?",
                                 (json.dumps(group_ids), datetime.now().isoformat(), target_id))
                    updated += 1
        
        conn.commit()
        conn.close()
        
        # Update group target count
        self._update_group_count(group_id)
        
        return {
            "success": True,
            "assigned": updated,
            "message": f"Assigned {updated} targets to group"
        }
    
    def get_targets_by_group(self, group_id: str) -> List[Target]:
        """Get all targets in a group"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM targets")
        rows = cursor.fetchall()
        conn.close()
        
        targets = []
        for row in rows:
            group_ids = json.loads(row[10])
            if group_id in group_ids:
                targets.append(self._row_to_target(row))
        
        return targets
    
    def search_targets(self, query: str, field: str = "email") -> List[Target]:
        """Search targets by field"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if field == "email":
            cursor.execute("SELECT * FROM targets WHERE email LIKE ?", (f"%{query}%",))
        elif field == "company":
            cursor.execute("SELECT * FROM targets WHERE company LIKE ?", (f"%{query}%",))
        elif field == "name":
            cursor.execute("SELECT * FROM targets WHERE first_name LIKE ? OR last_name LIKE ?", (f"%{query}%", f"%{query}%"))
        else:
            cursor.execute("SELECT * FROM targets")
        
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_target(row) for row in rows]
    
    def enrich_target_from_linkedin(self, target_id: str) -> Dict[str, Any]:
        """Enrich target data from LinkedIn (placeholder)"""
        # This would integrate with LinkedIn API or scraping
        # For now, just a placeholder
        
        return {
            "success": True,
            "target_id": target_id,
            "enrichment": {
                "linkedin_url": "https://linkedin.com/in/example",
                "position": "Senior Engineer",
                "company": "Tech Corp",
                "connections": 500
            },
            "message": "Target enriched from LinkedIn"
        }
    
    def analyze_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Analyze domain reputation"""
        # Extract domain from email if full email provided
        if '@' in domain:
            domain = domain.split('@')[1]
        
        analysis = {
            "domain": domain,
            "exists": False,
            "mx_records": [],
            "spf_record": None,
            "dmarc_record": None,
            "reputation_score": 0,
            "risk_level": "unknown"
        }
        
        # Simple DNS checks (would integrate with real DNS lookups)
        try:
            # Placeholder for actual DNS queries
            analysis["exists"] = True
            analysis["reputation_score"] = 75
            analysis["risk_level"] = "medium"
        except:
            pass
        
        return analysis
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get target statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM targets")
        total_targets = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM target_groups")
        total_groups = cursor.fetchone()[0]
        
        cursor.execute("SELECT company, COUNT(*) FROM targets WHERE company != '' GROUP BY company ORDER BY COUNT(*) DESC LIMIT 10")
        top_companies = [{"company": row[0], "count": row[1]} for row in cursor.fetchall()]
        
        cursor.execute("SELECT department, COUNT(*) FROM targets WHERE department != '' GROUP BY department ORDER BY COUNT(*) DESC LIMIT 10")
        top_departments = [{"department": row[0], "count": row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "total_targets": total_targets,
            "total_groups": total_groups,
            "top_companies": top_companies,
            "top_departments": top_departments
        }
    
    def _row_to_target(self, row: Tuple) -> Target:
        """Convert database row to Target object"""
        enrichment = json.loads(row[8])
        campaign_stats = json.loads(row[12])
        
        return Target(
            target_id=row[0],
            email=row[1],
            first_name=row[2],
            last_name=row[3],
            company=row[4],
            department=row[5],
            position=row[6],
            phone=row[7],
            linkedin_url=enrichment.get("linkedin_url", ""),
            twitter_handle=enrichment.get("twitter_handle", ""),
            last_active=datetime.fromisoformat(enrichment["last_active"]) if enrichment.get("last_active") else None,
            risk_level=TargetRiskLevel(row[9]),
            security_aware=enrichment.get("security_aware", False),
            mfa_enabled=enrichment.get("mfa_enabled", False),
            group_ids=json.loads(row[10]),
            tags=json.loads(row[11]),
            campaigns_sent=campaign_stats.get("campaigns_sent", 0),
            campaigns_opened=campaign_stats.get("campaigns_opened", 0),
            campaigns_clicked=campaign_stats.get("campaigns_clicked", 0),
            notes=row[13],
            created_at=datetime.fromisoformat(row[14]),
            updated_at=datetime.fromisoformat(row[15])
        )
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _update_group_count(self, group_id: str):
        """Update target count for group"""
        targets = self.get_targets_by_group(group_id)
        count = len(targets)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE target_groups SET target_count = ? WHERE group_id = ?", (count, group_id))
        conn.commit()
        conn.close()
    
    def _generate_target_id(self) -> str:
        """Generate unique target ID"""
        return f"tgt_{secrets.token_hex(8)}"
    
    def _generate_group_id(self) -> str:
        """Generate unique group ID"""
        return f"grp_{secrets.token_hex(8)}"


# Singleton
_target_manager = None

def get_target_manager() -> TargetManager:
    """Get target manager singleton"""
    global _target_manager
    if _target_manager is None:
        _target_manager = TargetManager()
    return _target_manager
