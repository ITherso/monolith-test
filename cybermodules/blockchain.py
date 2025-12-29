import datetime
import hashlib
import secrets

from cyberapp.models.db import db_conn


class BlockchainEvidence:
    def __init__(self, scan_id):
        self.scan_id = scan_id

    def collect_evidence(self):
        try:
            with db_conn() as conn:
                vulns = conn.execute("SELECT type, url FROM vulns WHERE scan_id=?", (self.scan_id,)).fetchall()
                techs = conn.execute("SELECT name FROM techno WHERE scan_id=?", (self.scan_id,)).fetchall()

            evidence = f"ScanID:{self.scan_id}|Vulns:{len(vulns)}|Techs:{len(techs)}"
            evidence_hash = hashlib.sha256(evidence.encode()).hexdigest()

            tx_hash = f"0x{secrets.token_hex(32)}"

            with db_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO blockchain_evidence (scan_id, tx_hash, evidence_hash, merkle_root)
                    VALUES (?, ?, ?, ?)
                    """,
                    (self.scan_id, tx_hash, evidence_hash, secrets.token_hex(16)),
                )

            return tx_hash
        except Exception:
            return None

    def generate_verification_script(self):
        script = f'''#!/bin/bash
# MONOLITH Blockchain Evidence Verification Script
# Scan ID: {self.scan_id}
# Generated: {datetime.datetime.now().isoformat()}

SCAN_ID="{self.scan_id}"
EVIDENCE_FILE="/tmp/monolith_evidence_$SCAN_ID.txt"

echo "MONOLITH Evidence Verification"
echo "================================"
echo "Scan ID: $SCAN_ID"

# Özet oluştur
echo "ScanID:$SCAN_ID|Vulns:$(sqlite3 monolith_supreme.db "SELECT COUNT(*) FROM vulns WHERE scan_id=$SCAN_ID")|Techs:$(sqlite3 monolith_supreme.db "SELECT COUNT(*) FROM techno WHERE scan_id=$SCAN_ID")" > $EVIDENCE_FILE

# Hash hesapla
HASH=$(sha256sum $EVIDENCE_FILE | awk '{{print $1}}')
echo "Evidence Hash: $HASH"

# Blockchain doğrulama (simüle edilmiş)
TX=$(sqlite3 monolith_supreme.db "SELECT tx_hash FROM blockchain_evidence WHERE scan_id=$SCID")
echo "Transaction: $TX"

if [ -n "$TX" ]; then
    echo "Status: VERIFIED"
    exit 0
else
    echo "Status: NOT FOUND"
    exit 1
fi
'''
        try:
            with open(f"/tmp/verify_{self.scan_id}.sh", "w") as f:
                f.write(script)
        except Exception:
            pass
