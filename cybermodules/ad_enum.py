from cyberapp.models.db import db_conn


try:
    from ldap3 import ALL, Connection, Server, NTLM, SASL, SIMPLE
    has_ldap = True
except Exception:
    has_ldap = False
    Server = None
    Connection = None
    ALL = None


class ActiveDirectoryEnum:
    def __init__(self, domain, scan_id, credentials=None):
        """
        domain: Target domain (örneğin: corp.local)
        scan_id: Database scan ID
        credentials: {'username': 'admin', 'password': 'pass123', 'domain': 'CORP'}
        """
        self.domain = domain
        self.scan_id = scan_id
        self.credentials = credentials
        self.users = []
        self.computers = []
        self.groups = []
        self.ous = []

    def log(self, data):
        """Intel tablosuna log yaz"""
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data, timestamp) VALUES (?, ?, ?, datetime('now'))",
                    (self.scan_id, "AD_ENUM", data),
                )
        except Exception as e:
            print(f"[AD_ENUM] Log error: {e}")

    def log_security_finding(self, severity, finding):
        """Güvenlik bulgusunu logla"""
        self.log(f"[{severity}] {finding}")

    def start(self):
        """Ana enumeration başlangıcı"""
        self.log(f"Starting AD enumeration on: {self.domain}")
        
        if not has_ldap:
            self.log_security_finding("HIGH", "ldap3 module not installed - enumeration aborted")
            return

        # 1. Anonymous bind dene
        self.enumerate_anonymous()

        # 2. Authenticated enumeration (credentials varsa)
        if self.credentials:
            self.enumerate_authenticated()
        else:
            self.log_security_finding("MEDIUM", "No credentials provided - limited enumeration performed")

        # 3. Admin users tara
        self.find_admin_users()

        # 4. OU ve Group yapısını çek
        self.enumerate_structure()

        # Özet rapor
        self.log(f"Enumeration complete: {len(self.users)} users, {len(self.computers)} computers, {len(self.groups)} groups found")

    def enumerate_anonymous(self):
        """Anonymous bind ile bilgi topla"""
        try:
            server = Server(self.domain, get_info=ALL)
            conn = Connection(server, auto_bind=True)
            
            self.log_security_finding("HIGH", f"Anonymous bind ALLOWED on {self.domain}")
            
            # Kullanıcıları çek
            self._get_users(conn)
            
            # Bilgisayarları çek
            self._get_computers(conn)
            
            # Grupları çek
            self._get_groups(conn)
            
            # OU'ları çek
            self._get_ous(conn)
            
            conn.unbind()
            
        except Exception as e:
            self.log(f"Anonymous bind failed: {str(e)}")

    def enumerate_authenticated(self):
        """Authenticated bind ile derinlemesine tarama"""
        if not self.credentials:
            return

        try:
            server = Server(self.domain, get_info=ALL)
            
            # NTLM authentication
            auth_type = NTLM if self.credentials.get('ntlm') else SIMPLE
            
            conn = Connection(
                server,
                user=f"{self.credentials.get('domain', '')}\\{self.credentials.get('username')}",
                password=self.credentials.get('password'),
                authentication=auth_type,
                auto_bind=True
            )
            
            self.log(f"Authenticated as: {self.credentials.get('username')}")
            
            # Domain admins grubunu bul
            self._get_domain_admins(conn)
            
            # Privileged users tara
            self._get_privileged_users(conn)
            
            # Service accounts tara
            self._get_service_accounts(conn)
            
            # Trust relationships
            self._get_trusts(conn)
            
            # Password policy çek
            self._get_password_policy(conn)
            
            # KRBTGT hesabını bul
            self._find_krbtgt(conn)
            
            conn.unbind()
            
        except Exception as e:
            self.log(f"Authenticated enumeration failed: {str(e)}")

    def _get_users(self, conn):
        """Tüm kullanıcıları çek"""
        try:
            base_dn = self._get_base_dn()
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=user)",
                attributes=['sAMAccountName', 'cn', 'memberOf', 'pwdLastSet', 
                           'lastLogon', 'logonCount', 'badPwdCount', 'adminCount',
                           'userPrincipalName', 'displayName', 'mail', 'title',
                           'department', 'objectSid', 'sIDHistory']
            )

            for entry in conn.entries:
                user_data = {
                    'username': getattr(entry, 'sAMAccountName', '').value or '',
                    'cn': getattr(entry, 'cn', '').value or '',
                    'memberOf': [g.value for g in getattr(entry, 'memberOf', [])],
                    'adminCount': getattr(entry, 'adminCount', {}).value or 0,
                    'displayName': getattr(entry, 'displayName', '').value or '',
                    'email': getattr(entry, 'mail', '').value or '',
                    'title': getattr(entry, 'title', '').value or '',
                    'department': getattr(entry, 'department', '').value or '',
                    'sid': getattr(entry, 'objectSid', '').value or '',
                    'pwdLastSet': getattr(entry, 'pwdLastSet', '').value or '',
                    'lastLogon': getattr(entry, 'lastLogon', '').value or '',
                    'badPwdCount': getattr(entry, 'badPwdCount', {}).value or 0,
                }
                self.users.append(user_data)
                
                # Admin bulguları
                if user_data['adminCount'] == 1:
                    self.log_security_finding("HIGH", f"Admin user found: {user_data['username']}")
                
                # Zayıf parola politikası göstergeleri
                if user_data['badPwdCount'] > 5:
                    self.log_security_finding("MEDIUM", f"User {user_data['username']} has {user_data['badPwdCount']} bad password attempts")

            self.log(f"Found {len(self.users)} users")
            
        except Exception as e:
            self.log(f"User enumeration error: {str(e)}")

    def _get_computers(self, conn):
        """Bilgisayarları çek"""
        try:
            base_dn = self._get_base_dn()
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=computer)",
                attributes=['sAMAccountName', 'operatingSystem', 'operatingSystemVersion',
                           'dNSHostName', 'whenCreated', 'lastLogon', 'objectSid']
            )

            for entry in conn.entries:
                comp_data = {
                    'name': getattr(entry, 'sAMAccountName', '').value or '',
                    'hostname': getattr(entry, 'dNSHostName', '').value or '',
                    'os': getattr(entry, 'operatingSystem', '').value or '',
                    'os_version': getattr(entry, 'operatingSystemVersion', '').value or '',
                    'created': getattr(entry, 'whenCreated', '').value or '',
                    'sid': getattr(entry, 'objectSid', '').value or '',
                }
                self.computers.append(comp_data)
                
                # Domain controllers
                if '$' in comp_data['name'] and 'DC$' not in comp_data['name']:
                    self.log_security_finding("INFO", f"Workstation: {comp_data['hostname']}")

            self.log(f"Found {len(self.computers)} computers")
            
        except Exception as e:
            self.log(f"Computer enumeration error: {str(e)}")

    def _get_groups(self, conn):
        """Grupları çek"""
        try:
            base_dn = self._get_base_dn()
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=group)",
                attributes=['sAMAccountName', 'cn', 'member', 'description', 'adminCount']
            )

            for entry in conn.entries:
                group_data = {
                    'name': getattr(entry, 'sAMAccountName', '').value or '',
                    'cn': getattr(entry, 'cn', '').value or '',
                    'members': [m.value for m in getattr(entry, 'member', [])],
                    'description': getattr(entry, 'description', '').value or '',
                    'adminCount': getattr(entry, 'adminCount', {}).value or 0,
                }
                self.groups.append(group_data)
                
                # Admin grupları
                if group_data['adminCount'] == 1 or 'admin' in group_data['name'].lower():
                    self.log_security_finding("HIGH", f"Admin group found: {group_data['name']} ({len(group_data['members'])} members)")

            self.log(f"Found {len(self.groups)} groups")
            
        except Exception as e:
            self.log(f"Group enumeration error: {str(e)}")

    def _get_ous(self, conn):
        """Organizational Unit'leri çek"""
        try:
            base_dn = self._get_base_dn()
            conn.search(
                search_base=base_dn,
                search_filter="(objectClass=organizationalUnit)",
                attributes=['ou', 'description', 'distinguishedName']
            )

            for entry in conn.entries:
                ou_data = {
                    'name': getattr(entry, 'ou', '').value or '',
                    'description': getattr(entry, 'description', '').value or '',
                    'dn': getattr(entry, 'distinguishedName', '').value or '',
                }
                self.ous.append(ou_data)

            self.log(f"Found {len(self.ous)} OUs")
            
        except Exception as e:
            self.log(f"OU enumeration error: {str(e)}")

    def _get_domain_admins(self, conn):
        """Domain Admins grubunu çek"""
        try:
            base_dn = self._get_base_dn()
            conn.search(
                search_base=base_dn,
                search_filter="(sAMAccountName=Domain Admins)",
                attributes=['member', 'sAMAccountName']
            )

            if conn.entries:
                da_group = conn.entries[0]
                members = [m.value for m in getattr(da_group, 'member', [])]
                self.log_security_finding("CRITICAL", f"Domain Admins has {len(members)} members")
                
                for member in members[:10]:  # İlk 10 üyeyi logla
                    self.log(f"  DA Member: {member}")

        except Exception as e:
            self.log(f"Domain Admins query failed: {str(e)}")

    def _get_privileged_users(self, conn):
        """Privileged kullanıcıları tara"""
        privileged_groups = [
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Server Operators",
            "Print Operators",
            "Backup Operators",
            "Replicator",
            "Cryptographic Operators",
        ]
        
        for group in privileged_groups:
            try:
                base_dn = self._get_base_dn()
                conn.search(
                    search_base=base_dn,
                    search_filter=f"(sAMAccountName={group})",
                    attributes=['member', 'sAMAccountName']
                )
                
                if conn.entries:
                    members = [m.value for m in getattr(conn.entries[0], 'member', [])]
                    if members:
                        self.log_security_finding("HIGH", f"Group {group}: {len(members)} privileged users")
                        
            except Exception:
                pass

    def _get_service_accounts(self, conn):
        """Service account'ları tara"""
        try:
            base_dn = self._get_base_dn()
            conn.search(
                search_base=base_dn,
                search_filter="(&(objectClass=user)(servicePrincipalName=*))",
                attributes=['sAMAccountName', 'servicePrincipalName']
            )

            for entry in conn.entries:
                spns = [s.value for s in getattr(entry, 'servicePrincipalName', [])]
                for spn in spns[:3]:  # İlk 3 SPN'i logla
                    self.log_security_finding("MEDIUM", f"Service Account: {entry.sAMAccountName.value} - {spn}")

        except Exception as e:
            self.log(f"Service account query failed: {str(e)}")

    def _get_trusts(self, conn):
        """Trust relationship'leri çek"""
        try:
            base_dn = self._get_base_dn()
            conn.search(
                search_base=f"CN=System,{base_dn}",
                search_filter="(objectClass=trustedDomain)",
                attributes=['trustPartner', 'trustDirection', 'trustType', 'cn']
            )

            for entry in conn.entries:
                trust_partner = getattr(entry, 'trustPartner', '').value or 'Unknown'
                trust_dir = getattr(entry, 'trustDirection', '').value or 0
                trust_type = getattr(entry, 'trustType', '').value or 0
                
                dir_str = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(trust_dir, "Unknown")
                type_str = {1: "Windows NT", 2: "Active Directory", 3: "Kerberos", 4: "Forest"}.get(trust_type, "Unknown")
                
                self.log_security_finding("HIGH", f"Trust: {trust_partner} (Direction: {dir_str}, Type: {type_str})")

        except Exception as e:
            self.log(f"Trust query failed: {str(e)}")

    def _get_password_policy(self, conn):
        """Password policy çek"""
        try:
            base_dn = self._get_base_dn()
            conn.search(
                search_base=f"CN=Password Settings Container,CN=System,{base_dn}",
                search_filter="(objectClass=msDS-PasswordSettings)",
                attributes=['name', 'msDS-MinimumPasswordLength', 'msDS-PasswordComplexityEnabled',
                           'msDS-PasswordHistoryLength', 'msDS-LockoutThreshold', 'msDS-LockoutObservationWindow']
            )

            for entry in conn.entries:
                min_len = getattr(entry, 'msDS-MinimumPasswordLength', {}).value or 0
                complexity = getattr(entry, 'msDS-PasswordComplexityEnabled', {}).value or False
                history = getattr(entry, 'msDS-PasswordHistoryLength', {}).value or 0
                
                self.log_security_finding("MEDIUM", f"Password Policy: MinLen={min_len}, Complexity={complexity}, History={history}")

        except Exception as e:
            self.log(f"Password policy query failed: {str(e)}")

    def _find_krbtgt(self, conn):
        """KRBTGT hesabını bul"""
        try:
            base_dn = self._get_base_dn()
            conn.search(
                search_base=base_dn,
                search_filter="(sAMAccountName=krbtgt)",
                attributes=['sAMAccountName', 'pwdLastSet', 'badPwdCount', 'memberOf']
            )

            if conn.entries:
                krbtgt = conn.entries[0]
                pwd_last_set = getattr(krbtgt, 'pwdLastSet', '').value or 'Unknown'
                self.log_security_finding("CRITICAL", f"KRBTGT account found - Last password set: {pwd_last_set}")

        except Exception as e:
            self.log(f"KRBTGT query failed: {str(e)}")

    def find_admin_users(self):
        """Admin haklarına sahip kullanıcıları tara"""
        admin_keywords = ['admin', 'administrator', 'root', 'svc_', 'service', 'sql', 'oracle', 'db_']
        
        for user in self.users:
            username = user['username'].lower()
            is_admin = False
            
            for keyword in admin_keywords:
                if keyword in username:
                    is_admin = True
                    break
            
            if is_admin:
                self.log_security_finding("HIGH", f"Potential admin account: {user['username']}")

    def enumerate_structure(self):
        """OU ve delegation yapısını çek"""
        try:
            server = Server(self.domain, get_info=ALL)
            conn = Connection(server, auto_bind=True)
            
            base_dn = self._get_base_dn()
            
            # GPO'ları çek
            conn.search(
                search_base=f"CN=Policies,CN=System,{base_dn}",
                search_filter="(objectClass=groupPolicyContainer)",
                attributes=['displayName', 'cn', 'gPCFileSysPath']
            )
            
            gpo_count = len(conn.entries)
            if gpo_count > 0:
                self.log_security_finding("INFO", f"Found {gpo_count} Group Policies")
                
                for entry in conn.entries[:5]:
                    gpo_name = getattr(entry, 'displayName', '').value or getattr(entry, 'cn', '').value
                    self.log(f"  GPO: {gpo_name}")
            
            conn.unbind()
            
        except Exception as e:
            self.log(f"Structure enumeration failed: {str(e)}")

    def _get_base_dn(self):
        """Base DN'i domain'den çıkart"""
        if '.' in self.domain:
            parts = self.domain.split('.')
            return ','.join([f"DC={p}" for p in parts])
        return f"DC={self.domain},DC=local"

    def export_users_for_hashdump(self):
        """Hashdump için user listesini export et"""
        return [u['username'] for u in self.users]

    def get_high_value_targets(self):
        """High value target'ları döndür"""
        targets = []
        
        # Admin hesaplar
        for user in self.users:
            if user['adminCount'] == 1:
                targets.append({'type': 'admin_user', 'username': user['username'], 'data': user})
        
        # Service accounts
        for user in self.users:
            if any(svc in user['username'].lower() for svc in ['svc_', 'service', 'sql', 'oracle']):
                targets.append({'type': 'service_account', 'username': user['username'], 'data': user})
        
        return targets