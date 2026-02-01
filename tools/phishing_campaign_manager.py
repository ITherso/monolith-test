#!/usr/bin/env python3
"""
Professional Phishing Campaign Manager
======================================
Advanced campaign management with scheduling, A/B testing, multi-stage campaigns

Author: CyberGhost Pro Team
"""

import json
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
import time


class CampaignStatus(Enum):
    """Campaign status"""
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class CampaignStage(Enum):
    """Multi-stage campaign stages"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_CONTACT = "initial_contact"
    TRUST_BUILDING = "trust_building"
    CREDENTIAL_HARVEST = "credential_harvest"
    PERSISTENCE = "persistence"


@dataclass
class CampaignConfig:
    """Campaign configuration"""
    campaign_id: str
    name: str
    description: str
    status: CampaignStatus = CampaignStatus.DRAFT
    
    # Scheduling
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    send_interval_minutes: int = 5  # Interval between emails
    business_hours_only: bool = True
    timezone: str = "UTC"
    
    # A/B Testing
    ab_testing_enabled: bool = False
    ab_variants: List[Dict] = field(default_factory=list)
    
    # Multi-stage
    multi_stage_enabled: bool = False
    stages: List[Dict] = field(default_factory=list)
    stage_delay_hours: int = 24
    
    # Advanced
    rate_limit_per_hour: int = 100
    auto_pause_on_detection: bool = True
    rotation_enabled: bool = True
    
    # Targeting
    target_group_ids: List[str] = field(default_factory=list)
    total_targets: int = 0
    
    # Results
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_harvested: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class ABTestVariant:
    """A/B test variant"""
    variant_id: str
    name: str
    subject_line: str
    sender_name: str
    sender_email: str
    template_id: str
    weight: float = 0.5  # Traffic split
    
    # Results
    sent_count: int = 0
    opened_count: int = 0
    clicked_count: int = 0
    harvested_count: int = 0
    
    @property
    def open_rate(self) -> float:
        return (self.opened_count / self.sent_count * 100) if self.sent_count > 0 else 0.0
    
    @property
    def click_rate(self) -> float:
        return (self.clicked_count / self.sent_count * 100) if self.sent_count > 0 else 0.0
    
    @property
    def harvest_rate(self) -> float:
        return (self.harvested_count / self.sent_count * 100) if self.sent_count > 0 else 0.0


@dataclass
class CampaignStageConfig:
    """Multi-stage campaign configuration"""
    stage_id: str
    stage_type: CampaignStage
    stage_order: int
    template_id: str
    subject_line: str
    delay_hours: int
    
    # Conditional progression
    auto_progress: bool = True
    progress_condition: str = "time_based"  # time_based, click_based, open_based
    progress_threshold: float = 0.0
    
    # Results
    targets_reached: int = 0
    targets_progressed: int = 0


class PhishingCampaignManager:
    """Professional phishing campaign manager"""
    
    def __init__(self, db_path: str = "/tmp/phishing_campaigns.db"):
        self.db_path = db_path
        self._init_database()
        self.active_campaigns = {}
        self.scheduler_thread = None
        self.scheduler_running = False
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Campaigns table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                status TEXT,
                config JSON,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        # Campaign events
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaign_events (
                event_id TEXT PRIMARY KEY,
                campaign_id TEXT,
                event_type TEXT,
                target_email TEXT,
                variant_id TEXT,
                stage_id TEXT,
                timestamp TEXT,
                metadata JSON,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
            )
        """)
        
        # A/B test results
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ab_test_results (
                result_id TEXT PRIMARY KEY,
                campaign_id TEXT,
                variant_id TEXT,
                metric TEXT,
                value REAL,
                timestamp TEXT,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def create_campaign(self, config: CampaignConfig) -> Dict[str, Any]:
        """Create new phishing campaign"""
        if not config.campaign_id:
            config.campaign_id = self._generate_campaign_id()
        
        config.created_at = datetime.now()
        config.updated_at = datetime.now()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO campaigns (campaign_id, name, description, status, config, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            config.campaign_id,
            config.name,
            config.description,
            config.status.value,
            json.dumps(asdict(config), default=str),
            config.created_at.isoformat(),
            config.updated_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "campaign_id": config.campaign_id,
            "message": f"Campaign '{config.name}' created successfully"
        }
    
    def schedule_campaign(self, campaign_id: str, start_time: datetime, end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """Schedule campaign for future execution"""
        config = self.get_campaign(campaign_id)
        if not config:
            return {"success": False, "error": "Campaign not found"}
        
        config.start_time = start_time
        config.end_time = end_time
        config.status = CampaignStatus.SCHEDULED
        config.updated_at = datetime.now()
        
        self._update_campaign(config)
        
        # Start scheduler if not running
        if not self.scheduler_running:
            self.start_scheduler()
        
        return {
            "success": True,
            "campaign_id": campaign_id,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat() if end_time else None,
            "message": "Campaign scheduled successfully"
        }
    
    def create_ab_test(self, campaign_id: str, variants: List[ABTestVariant]) -> Dict[str, Any]:
        """Create A/B test for campaign"""
        config = self.get_campaign(campaign_id)
        if not config:
            return {"success": False, "error": "Campaign not found"}
        
        # Validate weights sum to 1.0
        total_weight = sum(v.weight for v in variants)
        if abs(total_weight - 1.0) > 0.01:
            return {"success": False, "error": f"Variant weights must sum to 1.0 (current: {total_weight})"}
        
        config.ab_testing_enabled = True
        config.ab_variants = [asdict(v) for v in variants]
        config.updated_at = datetime.now()
        
        self._update_campaign(config)
        
        return {
            "success": True,
            "campaign_id": campaign_id,
            "variants_count": len(variants),
            "message": "A/B test configured successfully"
        }
    
    def create_multistage_campaign(self, campaign_id: str, stages: List[CampaignStageConfig]) -> Dict[str, Any]:
        """Create multi-stage campaign"""
        config = self.get_campaign(campaign_id)
        if not config:
            return {"success": False, "error": "Campaign not found"}
        
        # Sort stages by order
        sorted_stages = sorted(stages, key=lambda s: s.stage_order)
        
        config.multi_stage_enabled = True
        config.stages = [asdict(s) for s in sorted_stages]
        config.updated_at = datetime.now()
        
        self._update_campaign(config)
        
        return {
            "success": True,
            "campaign_id": campaign_id,
            "stages_count": len(stages),
            "message": "Multi-stage campaign configured successfully"
        }
    
    def start_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """Start campaign immediately"""
        config = self.get_campaign(campaign_id)
        if not config:
            return {"success": False, "error": "Campaign not found"}
        
        if config.status == CampaignStatus.RUNNING:
            return {"success": False, "error": "Campaign already running"}
        
        config.status = CampaignStatus.RUNNING
        config.start_time = datetime.now()
        config.updated_at = datetime.now()
        
        self._update_campaign(config)
        self.active_campaigns[campaign_id] = config
        
        # Start execution thread
        thread = threading.Thread(target=self._execute_campaign, args=(campaign_id,))
        thread.daemon = True
        thread.start()
        
        return {
            "success": True,
            "campaign_id": campaign_id,
            "status": "running",
            "message": "Campaign started successfully"
        }
    
    def pause_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """Pause running campaign"""
        config = self.get_campaign(campaign_id)
        if not config:
            return {"success": False, "error": "Campaign not found"}
        
        config.status = CampaignStatus.PAUSED
        config.updated_at = datetime.now()
        
        self._update_campaign(config)
        
        if campaign_id in self.active_campaigns:
            del self.active_campaigns[campaign_id]
        
        return {
            "success": True,
            "campaign_id": campaign_id,
            "status": "paused",
            "message": "Campaign paused successfully"
        }
    
    def stop_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """Stop and complete campaign"""
        config = self.get_campaign(campaign_id)
        if not config:
            return {"success": False, "error": "Campaign not found"}
        
        config.status = CampaignStatus.COMPLETED
        config.end_time = datetime.now()
        config.updated_at = datetime.now()
        
        self._update_campaign(config)
        
        if campaign_id in self.active_campaigns:
            del self.active_campaigns[campaign_id]
        
        return {
            "success": True,
            "campaign_id": campaign_id,
            "status": "completed",
            "message": "Campaign stopped successfully"
        }
    
    def get_campaign(self, campaign_id: str) -> Optional[CampaignConfig]:
        """Get campaign configuration"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT config FROM campaigns WHERE campaign_id = ?", (campaign_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            config_dict = json.loads(row[0])
            # Convert string dates back to datetime
            if config_dict.get('start_time'):
                config_dict['start_time'] = datetime.fromisoformat(config_dict['start_time'])
            if config_dict.get('end_time'):
                config_dict['end_time'] = datetime.fromisoformat(config_dict['end_time'])
            config_dict['created_at'] = datetime.fromisoformat(config_dict['created_at'])
            config_dict['updated_at'] = datetime.fromisoformat(config_dict['updated_at'])
            config_dict['status'] = CampaignStatus(config_dict['status'])
            
            return CampaignConfig(**config_dict)
        
        return None
    
    def list_campaigns(self, status: Optional[CampaignStatus] = None) -> List[Dict[str, Any]]:
        """List all campaigns"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute("SELECT campaign_id, name, status, created_at FROM campaigns WHERE status = ?", (status.value,))
        else:
            cursor.execute("SELECT campaign_id, name, status, created_at FROM campaigns")
        
        rows = cursor.fetchall()
        conn.close()
        
        campaigns = []
        for row in rows:
            campaigns.append({
                "campaign_id": row[0],
                "name": row[1],
                "status": row[2],
                "created_at": row[3]
            })
        
        return campaigns
    
    def get_campaign_stats(self, campaign_id: str) -> Dict[str, Any]:
        """Get campaign statistics"""
        config = self.get_campaign(campaign_id)
        if not config:
            return {"success": False, "error": "Campaign not found"}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get event counts
        cursor.execute("""
            SELECT event_type, COUNT(*) 
            FROM campaign_events 
            WHERE campaign_id = ? 
            GROUP BY event_type
        """, (campaign_id,))
        
        events = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        stats = {
            "campaign_id": campaign_id,
            "campaign_name": config.name,
            "status": config.status.value,
            "total_targets": config.total_targets,
            "emails_sent": events.get("email_sent", 0),
            "emails_opened": events.get("email_opened", 0),
            "links_clicked": events.get("link_clicked", 0),
            "credentials_harvested": events.get("credential_harvested", 0),
            "open_rate": 0.0,
            "click_rate": 0.0,
            "harvest_rate": 0.0
        }
        
        if stats["emails_sent"] > 0:
            stats["open_rate"] = (stats["emails_opened"] / stats["emails_sent"]) * 100
            stats["click_rate"] = (stats["links_clicked"] / stats["emails_sent"]) * 100
            stats["harvest_rate"] = (stats["credentials_harvested"] / stats["emails_sent"]) * 100
        
        return stats
    
    def get_ab_test_results(self, campaign_id: str) -> Dict[str, Any]:
        """Get A/B test results"""
        config = self.get_campaign(campaign_id)
        if not config or not config.ab_testing_enabled:
            return {"success": False, "error": "A/B testing not enabled for this campaign"}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        results = {}
        for variant_dict in config.ab_variants:
            variant_id = variant_dict['variant_id']
            
            cursor.execute("""
                SELECT event_type, COUNT(*) 
                FROM campaign_events 
                WHERE campaign_id = ? AND variant_id = ?
                GROUP BY event_type
            """, (campaign_id, variant_id))
            
            events = {row[0]: row[1] for row in cursor.fetchall()}
            
            sent = events.get("email_sent", 0)
            opened = events.get("email_opened", 0)
            clicked = events.get("link_clicked", 0)
            harvested = events.get("credential_harvested", 0)
            
            results[variant_id] = {
                "variant_name": variant_dict['name'],
                "sent": sent,
                "opened": opened,
                "clicked": clicked,
                "harvested": harvested,
                "open_rate": (opened / sent * 100) if sent > 0 else 0.0,
                "click_rate": (clicked / sent * 100) if sent > 0 else 0.0,
                "harvest_rate": (harvested / sent * 100) if sent > 0 else 0.0
            }
        
        conn.close()
        
        # Determine winner
        winner = max(results.items(), key=lambda x: x[1]['harvest_rate'])
        
        return {
            "success": True,
            "campaign_id": campaign_id,
            "variants": results,
            "winner": {
                "variant_id": winner[0],
                "harvest_rate": winner[1]['harvest_rate']
            }
        }
    
    def log_event(self, campaign_id: str, event_type: str, target_email: str, 
                  variant_id: Optional[str] = None, stage_id: Optional[str] = None,
                  metadata: Optional[Dict] = None) -> None:
        """Log campaign event"""
        event_id = secrets.token_hex(16)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO campaign_events (event_id, campaign_id, event_type, target_email, variant_id, stage_id, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            campaign_id,
            event_type,
            target_email,
            variant_id,
            stage_id,
            datetime.now().isoformat(),
            json.dumps(metadata) if metadata else None
        ))
        
        conn.commit()
        conn.close()
    
    def start_scheduler(self):
        """Start campaign scheduler thread"""
        if self.scheduler_running:
            return
        
        self.scheduler_running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop)
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
    
    def stop_scheduler(self):
        """Stop campaign scheduler"""
        self.scheduler_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
    
    def _scheduler_loop(self):
        """Scheduler main loop"""
        while self.scheduler_running:
            # Check for scheduled campaigns
            campaigns = self.list_campaigns(status=CampaignStatus.SCHEDULED)
            
            for campaign_info in campaigns:
                config = self.get_campaign(campaign_info['campaign_id'])
                if config and config.start_time and datetime.now() >= config.start_time:
                    self.start_campaign(config.campaign_id)
            
            time.sleep(60)  # Check every minute
    
    def _execute_campaign(self, campaign_id: str):
        """Execute campaign (placeholder for actual email sending)"""
        # This would integrate with SMTP manager and template engine
        # For now, just a placeholder
        pass
    
    def _update_campaign(self, config: CampaignConfig):
        """Update campaign in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE campaigns 
            SET status = ?, config = ?, updated_at = ?
            WHERE campaign_id = ?
        """, (
            config.status.value,
            json.dumps(asdict(config), default=str),
            config.updated_at.isoformat(),
            config.campaign_id
        ))
        
        conn.commit()
        conn.close()
    
    def _generate_campaign_id(self) -> str:
        """Generate unique campaign ID"""
        return f"camp_{secrets.token_hex(8)}"


# Singleton instance
_campaign_manager = None

def get_campaign_manager() -> PhishingCampaignManager:
    """Get campaign manager singleton"""
    global _campaign_manager
    if _campaign_manager is None:
        _campaign_manager = PhishingCampaignManager()
    return _campaign_manager
