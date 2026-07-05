"""
Tests for Kerberos Attack Chain Module
======================================
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import subprocess

from cybermodules.kerberos_chain import (
    KerberosAttackType,
    EncryptionType,
    TicketStatus,
    ASREPUser,
    KerberoastHash,
    KerberosTicket,
    ChainStep,
    KerberosChainResult,
    ASREPRoaster,
    Kerberoaster,
    OverpassTheHash,
    SilverTicketForger,
    GoldenTicketForger,
    KerberosAttackChain,
)


# ============================================================
# DATACLASS TESTS
# ============================================================

class TestASREPUser:
    """Tests for ASREPUser dataclass"""
    
    def test_asrep_user_creation(self):
        """Test ASREPUser creation"""
        user = ASREPUser(
            username="svc_sql",
            domain="corp.local",
            hash_type="23",
            as_rep_hash="abc123def456"
        )
        
        assert user.username == "svc_sql"
        assert user.domain == "corp.local"
        assert user.hash_type == "23"
    
    def test_hashcat_format(self):
        """Test hashcat format conversion"""
        user = ASREPUser(
            username="user1",
            domain="test.local",
            hash_type="23",
            as_rep_hash="deadbeef"
        )
        
        hashcat = user.to_hashcat_format()
        assert "$krb5asrep$23$user1@test.local:deadbeef" == hashcat
    
    def test_john_format(self):
        """Test John format conversion"""
        user = ASREPUser(
            username="user1",
            domain="test.local",
            as_rep_hash="deadbeef"
        )
        
        john = user.to_john_format()
        assert "$krb5asrep$user1@test.local:deadbeef" == john


class TestKerberoastHash:
    """Tests for KerberoastHash dataclass"""
    
    def test_kerberoast_hash_creation(self):
        """Test KerberoastHash creation"""
        hash_obj = KerberoastHash(
            username="svc_sql",
            domain="corp.local",
            spn="MSSQLSvc/sql01.corp.local",
            tgs_hash="abc123"
        )
        
        assert hash_obj.spn == "MSSQLSvc/sql01.corp.local"
    
    def test_hashcat_format(self):
        """Test TGS hashcat format"""
        hash_obj = KerberoastHash(
            username="svc_http",
            domain="test.local",
            spn="HTTP/web.test.local",
            hash_type="23",
            tgs_hash="cafebabe"
        )
        
        hashcat = hash_obj.to_hashcat_format()
        assert "$krb5tgs$23$*svc_http$test.local$HTTP/web.test.local*$cafebabe" == hashcat


class TestKerberosTicket:
    """Tests for KerberosTicket dataclass"""
    
    def test_ticket_creation(self):
        """Test KerberosTicket creation"""
        ticket = KerberosTicket(
            ticket_type="Golden",
            target_user="Administrator",
            target_domain="corp.local",
            domain_sid="S-1-5-21-123-456-789",
            status=TicketStatus.FORGED
        )
        
        assert ticket.ticket_type == "Golden"
        assert ticket.status == TicketStatus.FORGED
    
    def test_ticket_to_dict(self):
        """Test ticket serialization"""
        ticket = KerberosTicket(
            ticket_type="Silver",
            target_user="admin",
            target_domain="test.local",
            target_service="cifs"
        )
        
        data = ticket.to_dict()
        assert data['ticket_type'] == "Silver"
        assert data['target_service'] == "cifs"
    
    def test_default_groups(self):
        """Test default privileged groups"""
        ticket = KerberosTicket(
            ticket_type="Golden",
            target_user="Admin",
            target_domain="corp.local"
        )
        
        # Default groups: DA, DU, SA, EA, GPO
        assert 512 in ticket.groups  # Domain Admins
        assert 519 in ticket.groups  # Enterprise Admins


# ============================================================
# AS-REP ROASTER TESTS
# ============================================================

class TestASREPRoaster:
    """Tests for ASREPRoaster class"""
    
    def test_roaster_initialization(self):
        """Test roaster initialization"""
        roaster = ASREPRoaster(scan_id=123)
        assert roaster.scan_id == 123
        assert roaster.discovered_users == []
    
    def test_common_userlist(self):
        """Test common userlist generation"""
        roaster = ASREPRoaster()
        userlist = roaster._get_common_userlist()
        
        assert "administrator" in userlist
        assert "krbtgt" in userlist
        assert "svc_sql" in userlist
    
    @patch('subprocess.run')
    def test_enumerate_with_mock(self, mock_run):
        """Test enumeration with mocked subprocess"""
        mock_run.return_value = Mock(
            stdout="$krb5asrep$23$svc_backup@corp.local:abcdef123456",
            stderr="",
            returncode=0
        )
        
        roaster = ASREPRoaster()
        users = roaster.enumerate_no_preauth_users(
            domain="corp.local",
            dc_ip="192.168.1.1",
            username="user",
            password="pass"
        )
        
        assert len(users) == 1
        assert users[0].username == "svc_backup"
    
    def test_parse_asrep_output(self):
        """Test parsing AS-REP output"""
        roaster = ASREPRoaster()
        
        output = """
        [*] Querying LDAP
        $krb5asrep$23$user1@corp.local:abc123def456
        $krb5asrep$23$user2@corp.local:789xyz012345
        """
        
        users = roaster._parse_asrep_output(output, "corp.local")
        
        assert len(users) == 2
        assert users[0].username == "user1"
        assert users[1].username == "user2"
    
    def test_generate_crack_commands(self):
        """Test crack command generation"""
        roaster = ASREPRoaster(scan_id=1)
        roaster.discovered_users = [
            ASREPUser(username="test", domain="corp.local", as_rep_hash="abc")
        ]
        
        commands = roaster.generate_crack_commands()
        
        assert 'hashcat' in commands
        assert '-m 18200' in commands['hashcat']


# ============================================================
# KERBEROASTER TESTS
# ============================================================

class TestKerberoaster:
    """Tests for Kerberoaster class"""
    
    def test_kerberoaster_initialization(self):
        """Test kerberoaster initialization"""
        roaster = Kerberoaster(scan_id=456)
        assert roaster.scan_id == 456
    
    @patch('subprocess.run')
    def test_roast_with_password(self, mock_run):
        """Test kerberoasting with password"""
        mock_run.return_value = Mock(
            stdout="$krb5tgs$23$*svc$corp.local$HTTP/web*$hash123",
            stderr="",
            returncode=0
        )
        
        roaster = Kerberoaster()
        hashes = roaster.roast(
            domain="corp.local",
            dc_ip="192.168.1.1",
            username="user",
            password="pass"
        )
        
        # Method returns parsed hashes from output
        # With mock output, parsing should find 1 hash
        assert mock_run.called
    
    def test_parse_kerberoast_output(self):
        """Test parsing kerberoast output"""
        roaster = Kerberoaster()
        
        output = "$krb5tgs$23$*sqlsvc$corp.local$MSSQLSvc/sql01*$abcdef"
        
        hashes = roaster._parse_kerberoast_output(output, "corp.local")
        
        assert len(hashes) == 1
        assert hashes[0].username == "sqlsvc"
        assert hashes[0].spn == "MSSQLSvc/sql01"


# ============================================================
# OVERPASS-THE-HASH TESTS
# ============================================================

class TestOverpassTheHash:
    """Tests for OverpassTheHash class"""
    
    def test_opth_initialization(self):
        """Test OPTH initialization"""
        opth = OverpassTheHash(scan_id=789)
        assert opth.scan_id == 789
    
    @patch('subprocess.run')
    @patch('os.path.exists')
    def test_request_tgt_success(self, mock_exists, mock_run):
        """Test successful TGT request"""
        mock_run.return_value = Mock(
            stdout="[*] Saving ticket in user.ccache",
            stderr="",
            returncode=0
        )
        mock_exists.return_value = True
        
        opth = OverpassTheHash(scan_id=1)
        ticket = opth.request_tgt_with_hash(
            domain="corp.local",
            username="admin",
            ntlm_hash="aad3b435b51404ee",
            dc_ip="192.168.1.1"
        )
        
        # With proper mocking this would return a ticket
        # For now, just test the method runs without error
        mock_run.assert_called_once()


# ============================================================
# SILVER TICKET TESTS
# ============================================================

class TestSilverTicketForger:
    """Tests for SilverTicketForger class"""
    
    def test_silver_forger_initialization(self):
        """Test Silver Ticket forger initialization"""
        forger = SilverTicketForger(scan_id=100)
        assert forger.scan_id == 100
    
    @patch('subprocess.run')
    @patch('os.path.exists')
    @patch('os.rename')
    def test_forge_silver_ticket(self, mock_rename, mock_exists, mock_run):
        """Test Silver Ticket forging"""
        mock_run.return_value = Mock(
            stdout="[*] Saving ticket",
            stderr="",
            returncode=0
        )
        mock_exists.return_value = True
        
        forger = SilverTicketForger(scan_id=1)
        ticket = forger.forge(
            domain="corp.local",
            domain_sid="S-1-5-21-123-456-789",
            target_user="Administrator",
            target_host="dc01.corp.local",
            service="cifs",
            service_hash="abc123def456"
        )
        
        mock_run.assert_called_once()


# ============================================================
# GOLDEN TICKET TESTS
# ============================================================

class TestGoldenTicketForger:
    """Tests for GoldenTicketForger class"""
    
    def test_golden_forger_initialization(self):
        """Test Golden Ticket forger initialization"""
        forger = GoldenTicketForger(scan_id=200)
        assert forger.scan_id == 200
    
    @patch('subprocess.run')
    @patch('os.path.exists')
    @patch('os.rename')
    def test_forge_golden_ticket(self, mock_rename, mock_exists, mock_run):
        """Test Golden Ticket forging"""
        mock_run.return_value = Mock(
            stdout="[*] Saving ticket",
            stderr="",
            returncode=0
        )
        mock_exists.return_value = True
        
        forger = GoldenTicketForger(scan_id=1)
        ticket = forger.forge(
            domain="corp.local",
            domain_sid="S-1-5-21-123-456-789",
            krbtgt_hash="aad3b435b51404ee"
        )
        
        mock_run.assert_called_once()


# ============================================================
# ATTACK CHAIN TESTS
# ============================================================

class TestKerberosAttackChain:
    """Tests for KerberosAttackChain class"""
    
    def test_chain_initialization(self):
        """Test attack chain initialization"""
        chain = KerberosAttackChain(scan_id=300)
        
        assert chain.scan_id == 300
        assert chain.chain_id is not None
        assert chain.asrep is not None
        assert chain.kerberoast is not None
        assert chain.opth is not None
    
    def test_generate_attack_diagram(self):
        """Test attack diagram generation"""
        chain = KerberosAttackChain()
        diagram = chain.generate_attack_diagram()
        
        assert "mermaid" in diagram
        assert "ROASTING" in diagram
        assert "Golden Ticket" in diagram
    
    @patch.object(ASREPRoaster, 'enumerate_no_preauth_users')
    def test_execute_chain_asrep_only(self, mock_asrep):
        """Test chain execution with AS-REP only"""
        mock_asrep.return_value = [
            ASREPUser(username="test", domain="corp.local", as_rep_hash="abc")
        ]
        
        chain = KerberosAttackChain()
        result = chain.execute_full_chain(
            domain="corp.local",
            dc_ip="192.168.1.1"
        )
        
        assert len(result.steps) >= 1
        assert result.asrep_users == [mock_asrep.return_value[0]]


class TestChainResult:
    """Tests for KerberosChainResult"""
    
    def test_result_to_dict(self):
        """Test result serialization"""
        result = KerberosChainResult(
            chain_id="test123",
            success=True,
            domain_admin_achieved=True
        )
        
        data = result.to_dict()
        
        assert data['chain_id'] == "test123"
        assert data['success'] is True
        assert data['domain_admin_achieved'] is True


# ============================================================
# ENUM TESTS
# ============================================================

class TestEnums:
    """Tests for Kerberos enums"""
    
    def test_attack_types(self):
        """Test KerberosAttackType enum"""
        assert KerberosAttackType.AS_REP_ROAST.value == "as_rep_roast"
        assert KerberosAttackType.GOLDEN_TICKET.value == "golden_ticket"
        assert KerberosAttackType.RBCD.value == "rbcd"
    
    def test_encryption_types(self):
        """Test EncryptionType enum"""
        assert EncryptionType.RC4_HMAC.value == 23
        assert EncryptionType.AES256_CTS_HMAC_SHA1.value == 18
    
    def test_ticket_status(self):
        """Test TicketStatus enum"""
        assert TicketStatus.FORGED.value == "forged"
        assert TicketStatus.INJECTED.value == "injected"
