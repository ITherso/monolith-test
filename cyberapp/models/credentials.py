"""
Credential Storage Module
Handles hash dumps and cracked password storage
"""

from cyberapp.models.db import db_conn


class CredentialStore:
    """Credential veritabanı işlemleri"""
    
    @staticmethod
    def save_hash_dump(scan_id, hostname, hash_type, username, nthash, lmhash):
        """Hash dump sonucunu veritabanına kaydet"""
        try:
            with db_conn() as conn:
                conn.execute(
                    """INSERT INTO hash_dumps 
                    (scan_id, hostname, hash_type, username, nthash, lmhash, dumped_at) 
                    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
                    (scan_id, hostname, hash_type, username, nthash, lmhash)
                )
                conn.commit()
                return True
        except Exception as e:
            print(f"[CREDSTORE] Error saving hash dump: {e}")
            return False
    
    @staticmethod
    def save_cracked_password(scan_id, username, password, hash_source):
        """Cracked password'i veritabanına kaydet"""
        try:
            with db_conn() as conn:
                conn.execute(
                    """INSERT INTO cracked_credentials 
                    (scan_id, username, password, hash_source, cracked_at) 
                    VALUES (?, ?, ?, ?, datetime('now'))""",
                    (scan_id, username, password, hash_source)
                )
                conn.commit()
                return True
        except Exception as e:
            print(f"[CREDSTORE] Error saving cracked password: {e}")
            return False
    
    @staticmethod
    def get_hash_dumps(scan_id):
        """Scan'e ait tüm hashleri getir"""
        with db_conn() as conn:
            return conn.execute(
                """SELECT hostname, hash_type, username, nthash, lmhash 
                FROM hash_dumps WHERE scan_id = ?""",
                (scan_id,)
            ).fetchall()
    
    @staticmethod
    def get_cracked_credentials(scan_id):
        """Scan'e ait tüm cracked credential'ları getir"""
        with db_conn() as conn:
            return conn.execute(
                """SELECT username, password, hash_source, cracked_at 
                FROM cracked_credentials WHERE scan_id = ?""",
                (scan_id,)
            ).fetchall()
    
    @staticmethod
    def get_cracked_for_intel(scan_id):
        """Intel tablosu için formatlanmış credential verisi"""
        with db_conn() as conn:
            return conn.execute(
                """SELECT username, password, hash_source FROM cracked_credentials 
                WHERE scan_id = ?""",
                (scan_id,)
            ).fetchall()
    
    @staticmethod
    def credential_exists(scan_id, username, hash_source):
        """Credential daha önce kaydedilmiş mi kontrol et"""
        with db_conn() as conn:
            result = conn.execute(
                """SELECT id FROM cracked_credentials 
                WHERE scan_id = ? AND username = ? AND hash_source = ?""",
                (scan_id, username, hash_source)
            ).fetchone()
            return result is not None