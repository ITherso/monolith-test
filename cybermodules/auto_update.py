import urllib

from cyberapp.models.db import db_conn
from cyberapp.release_updates import CURRENT_VERSION, LATEST_RELEASE_URL, check_release_updates


class AutoUpdater:
    def __init__(self):
        self.version = CURRENT_VERSION
        self.update_url = LATEST_RELEASE_URL

    def check_for_updates(self):
        """Read release metadata only; no software download or installation."""
        return check_release_updates(self.version)

    def update_payloads(self):
        """Payload database güncelleme"""
        try:
            print("\n📥 Updating payload databases...")

            payload_sources = [
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
            ]

            for url in payload_sources:
                try:
                    req = urllib.request.Request(url)
                    response = urllib.request.urlopen(req, timeout=30)
                    content = response.read().decode('utf-8')

                    payloads = [line.strip() for line in content.split('\n') if line.strip()]

                    with db_conn() as conn:
                        conn.execute(
                            """
                            CREATE TABLE IF NOT EXISTS payloads (
                                id INTEGER PRIMARY KEY,
                                type TEXT,
                                payload TEXT,
                                source TEXT,
                                added_date TEXT DEFAULT CURRENT_TIMESTAMP
                            )
                            """
                        )
                        for payload in payloads:
                            payload_type = 'SQLi' if 'sql' in url.lower() else 'XSS' if 'xss' in url.lower() else 'DIR'
                            conn.execute(
                                """
                                INSERT OR IGNORE INTO payloads (type, payload, source)
                                VALUES (?, ?, ?)
                                """,
                                (payload_type, payload, url),
                            )

                    print(f"✓ Updated payloads from {url.split('/')[-1]}")

                except Exception as e:
                    print(f"✗ Failed to update from {url}: {e}")

            print("✅ Payload update completed")

        except Exception as e:
            print(f"Payload update error: {e}")
