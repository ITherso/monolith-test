import json
import urllib

from cyberapp.models.db import db_conn


class AutoUpdater:
    def __init__(self):
        self.version = "v68.0"
        self.update_url = "https://api.github.com/repos/your-repo/monolith/releases/latest"

    def check_for_updates(self):
        """Güncelleme kontrolü"""
        try:
            req = urllib.request.Request(
                self.update_url,
                headers={'User-Agent': 'Monolith-Scanner'},
            )
            response = urllib.request.urlopen(req, timeout=10)
            data = json.loads(response.read())

            latest_version = data['tag_name']

            if latest_version != self.version:
                print(f"\n⚠️  NEW VERSION AVAILABLE: {latest_version}")
                print(f"   Current: {self.version}")
                print(f"   Release Notes: {data['html_url']}")

                return {
                    'update_available': True,
                    'latest_version': latest_version,
                    'release_notes': data['body'][:200] if data['body'] else "No release notes",
                    'download_url': data['assets'][0]['browser_download_url'] if data['assets'] else None,
                }

            return {'update_available': False}

        except Exception as e:
            print(f"Update check failed: {e}")
            return {'update_available': False, 'error': str(e)}

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
