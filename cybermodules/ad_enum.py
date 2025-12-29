from cyberapp.models.db import db_conn

try:
    from ldap3 import ALL, Connection, Server
    has_ldap = True
except Exception:
    has_ldap = False
    Server = None
    Connection = None
    ALL = None


class ActiveDirectoryEnum:
    def __init__(self, domain, scan_id):
        self.domain = domain
        self.scan_id = scan_id

    def log(self, data):
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                    (self.scan_id, "AD_ENUM", data),
                )
        except Exception:
            pass

    def start(self):
        if not has_ldap:
            self.log("ldap3 module not installed")
            return

        try:
            server = Server(self.domain, get_info=ALL)
            self.log(f"Connected to AD: {self.domain}")

            try:
                conn = Connection(server, auto_bind=True)
                self.log("Anonymous bind SUCCESS - Information disclosure possible!")

                conn.search(
                    search_base=f"DC={self.domain.split('.')[0]},DC={self.domain.split('.')[1] if '.' in self.domain else 'local'}",
                    search_filter="(objectClass=user)",
                    attributes=['sAMAccountName', 'cn', 'memberOf'],
                )

                users = [entry.sAMAccountName.value for entry in conn.entries if hasattr(entry, 'sAMAccountName')]
                self.log(f"Found {len(users)} users via anonymous bind")

                conn.unbind()
            except Exception as e:
                self.log(f"Anonymous bind failed: {str(e)}")

        except Exception as e:
            self.log(f"AD Connection error: {str(e)}")
