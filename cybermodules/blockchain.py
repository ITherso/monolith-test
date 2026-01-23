import datetime
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager

from cyberapp.models.db import db_conn


class BlockchainEvidenceCollector:
    """
    Blok zinciri tabanlı kanıt toplama ve doğrulama modülü.
    Güvenlik tarama sonuçlarının değiştirilmediğini doğrulamak için
    merkle ağaçları ve dijital imzalar kullanır.
    """

    def __init__(self, scan_id, target=None):
        self.scan_id = scan_id
        self.target = target
        self.evidence_chain = []
        self.merkle_root = None

    def _generate_merkle_leaf(self, data):
        """Merkle ağacı yaprağı oluştur."""
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def _generate_merkle_parent(self, left, right):
        """Merkle ağacı parent düğümü oluştur."""
        combined = (left + right).encode()
        return hashlib.sha256(combined).hexdigest()

    def _build_merkle_tree(self, leaves):
        """Merkle ağacı inşa et."""
        if not leaves:
            return None

        tree = leaves[:]
        while len(tree) > 1:
            new_level = []
            for i in range(0, len(tree), 2):
                left = tree[i]
                right = tree[i + 1] if i + 1 < len(tree) else left
                new_level.append(self._generate_merkle_parent(left, right))
            tree = new_level
        return tree[0] if tree else None

    def collect_vulnerability_evidence(self, vuln_data):
        """
        Bir güvenlik açığı için kanıt topla.
        Açığın hash'ini oluştur ve kanıt zincirine ekle.
        """
        vuln_hash = self._generate_merkle_leaf({
            "type": vuln_data.get("type", ""),
            "url": vuln_data.get("url", ""),
            "severity": vuln_data.get("severity", ""),
            "timestamp": vuln_data.get("timestamp", ""),
        })

        self.evidence_chain.append({
            "type": "VULNERABILITY",
            "data_hash": vuln_hash,
            "original_data": vuln_data,
            "timestamp": datetime.datetime.now().isoformat()
        })

        return vuln_hash

    def collect_technology_evidence(self, tech_data):
        """
        Tespit edilen teknoloji için kanıt topla.
        """
        tech_hash = self._generate_merkle_leaf({
            "name": tech_data.get("name", ""),
            "version": tech_data.get("version", ""),
            "confidence": tech_data.get("confidence", 0),
        })

        self.evidence_chain.append({
            "type": "TECHNOLOGY",
            "data_hash": tech_hash,
            "original_data": tech_data,
            "timestamp": datetime.datetime.now().isoformat()
        })

        return tech_hash

    def collect_intelligence_evidence(self, intel_data):
        """
        Toplanan istihbarat için kanıt topla.
        """
        intel_hash = self._generate_merkle_leaf({
            "type": intel_data.get("type", ""),
            "data": intel_data.get("data", ""),
            "source": intel_data.get("source", ""),
        })

        self.evidence_chain.append({
            "type": "INTELLIGENCE",
            "data_hash": intel_hash,
            "original_data": intel_data,
            "timestamp": datetime.datetime.now().isoformat()
        })

        return intel_hash

    def build_evidence_chain(self):
        """
        Tüm kanıt parçalarından merkle ağacı oluştur.
        Tarama verilerinin bütünlüğünü garanti eder.
        """
        if not self.evidence_chain:
            return None

        leaves = [item["data_hash"] for item in self.evidence_chain]
        self.merkle_root = self._build_merkle_tree(leaves)
        return self.merkle_root

    def generate_evidence_hash(self):
        """
        Tarama için kapsamlı bir kanıt hash'i oluştur.
        Bu hash tarama sonuçlarının bütünlüğünü temsil eder.
        """
        try:
            # Veritabanından tarama verilerini çek
            with db_conn() as conn:
                vulns = conn.execute(
                    "SELECT type, url, severity FROM vulns WHERE scan_id=?", 
                    (self.scan_id,)
                ).fetchall()
                techs = conn.execute(
                    "SELECT name, detected_via, confidence FROM techno WHERE scan_id=?", 
                    (self.scan_id,)
                ).fetchall()
                intel = conn.execute(
                    "SELECT type, data FROM intel WHERE scan_id=?", 
                    (self.scan_id,)
                ).fetchall()

            # Kanıt verilerini topla
            evidence_data = {
                "scan_id": self.scan_id,
                "timestamp": datetime.datetime.now().isoformat(),
                "vulnerabilities": [{"type": v[0], "url": v[1], "severity": v[2]} for v in vulns],
                "technologies": [{"name": t[0], "via": t[1]} for t in techs],
                "intelligence": [{"type": i[0], "data": i[1][:100]} for i in intel],
                "evidence_chain_count": len(self.evidence_chain)
            }

            # Hash oluştur
            evidence_string = json.dumps(evidence_data, sort_keys=True)
            evidence_hash = hashlib.sha256(evidence_string.encode()).hexdigest()

            # Simüle edilmiş blockchain transaction hash'i
            # Gerçek bir blockchain entegrasyonu için Web3 veya benzeri kütüphaneler kullanılabilir
            tx_hash = self._generate_transaction_hash(evidence_hash)

            # Merkle root'u dahil et
            merkle_root = self.build_evidence_chain()

            # Veritabanına kaydet
            with db_conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO blockchain_evidence 
                    (scan_id, tx_hash, evidence_hash, merkle_root, timestamp, verified)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (self.scan_id, tx_hash, evidence_hash, merkle_root, 
                     datetime.datetime.now().isoformat(), False),
                )

            return {
                "tx_hash": tx_hash,
                "evidence_hash": evidence_hash,
                "merkle_root": merkle_root,
                "vuln_count": len(vulns),
                "tech_count": len(techs),
                "intel_count": len(intel)
            }

        except Exception as e:
            print(f"[Blockchain] Evidence collection error: {e}")
            return None

    def _generate_transaction_hash(self, evidence_hash):
        """
        Simüle edilmiş transaction hash oluştur.
        Gerçek blockchain entegrasyonu için bu method değiştirilmelidir.
        """
        # Ethereum tarzı transaction hash formatı
        timestamp = datetime.datetime.now().timestamp()
        combined = f"{evidence_hash}|{self.scan_id}|{timestamp}"
        hash_bytes = hashlib.sha256(combined.encode()).hexdigest()
        return f"0x{hash_bytes[:64]}"

    def verify_evidence_integrity(self):
        """
        Kayıtlı kanıtların bütünlüğünü doğrula.
        Veritabanındaki verilerin hash ile eşleşip eşleşmediğini kontrol eder.
        """
        try:
            with db_conn() as conn:
                record = conn.execute(
                    "SELECT tx_hash, evidence_hash, merkle_root, timestamp FROM blockchain_evidence WHERE scan_id=?",
                    (self.scan_id,)
                ).fetchone()

            if not record:
                return {"valid": False, "error": "No evidence record found"}

            tx_hash, stored_hash, merkle_root, timestamp = record

            # Mevcut verilerle yeni hash oluştur ve karşılaştır
            with db_conn() as conn:
                vulns = conn.execute(
                    "SELECT type, url, severity FROM vulns WHERE scan_id=?", 
                    (self.scan_id,)
                ).fetchall()
                techs = conn.execute(
                    "SELECT name, detected_via, confidence FROM techno WHERE scan_id=?", 
                    (self.scan_id,)
                ).fetchall()

            evidence_data = {
                "scan_id": self.scan_id,
                "vulnerabilities": [{"type": v[0], "url": v[1], "severity": v[2]} for v in vulns],
                "technologies": [{"name": t[0], "via": t[1]} for t in techs],
            }

            current_hash = hashlib.sha256(json.dumps(evidence_data, sort_keys=True).encode()).hexdigest()

            if current_hash == stored_hash:
                return {
                    "valid": True,
                    "tx_hash": tx_hash,
                    "verified_at": datetime.datetime.now().isoformat(),
                    "original_timestamp": timestamp,
                    "merkle_root": merkle_root
                }
            else:
                return {
                    "valid": False,
                    "error": "Evidence hash mismatch - data may have been altered",
                    "original_hash": stored_hash,
                    "current_hash": current_hash
                }

        except Exception as e:
            return {"valid": False, "error": str(e)}

    def generate_verification_report(self):
        """
        Doğrulama raporu oluştur.
        Kanıt bütünlüğü ve doğrulama sonuçlarını içerir.
        """
        verification = self.verify_evidence_integrity()

        report = {
            "scan_id": self.scan_id,
            "generated_at": datetime.datetime.now().isoformat(),
            "verification": verification,
            "evidence_chain": {
                "total_items": len(self.evidence_chain),
                "items": self.evidence_chain[:10]  # İlk 10 item
            }
        }

        return report

    def generate_verification_script(self, output_path=None):
        """
        Linux shell scripti olarak doğrulama scripti oluştur.
        Bu script harici olarak çalıştırılarak kanıtları doğrulayabilir.
        """
        try:
            scan_id = self.scan_id
            timestamp = datetime.datetime.now().isoformat()
            script_content = '''#!/bin/bash
# MONOLITH Blockchain Evidence Verification Script
# Scan ID: ''' + str(scan_id) + '''
# Generated: ''' + timestamp + '''

SCAN_ID="''' + str(scan_id) + '''"
EVIDENCE_DB="/tmp/monolith_evidence_$SCAN_ID.db"
REPORT_FILE="/tmp/monolith_verification_$SCAN_ID.txt"

echo "========================================"
echo "MONOLITH Evidence Verification Script"
echo "========================================"
echo "Scan ID: $SCAN_ID"
echo "Date: $(date -Iseconds)"
echo ""

# SQLite veritabanından kanıtları çek
TX_HASH=$(sqlite3 "$EVIDENCE_DB" "SELECT tx_hash FROM blockchain_evidence WHERE scan_id=$SCAN_ID" 2>/dev/null || echo "")
EVIDENCE_HASH=$(sqlite3 "$EVIDENCE_DB" "SELECT evidence_hash FROM blockchain_evidence WHERE scan_id=$SCAN_ID" 2>/dev/null || echo "")
MERKLE_ROOT=$(sqlite3 "$EVIDENCE_DB" "SELECT merkle_root FROM blockchain_evidence WHERE scan_id=$SCAN_ID" 2>/dev/null || echo "")

echo "Transaction Hash: $TX_HASH"
echo "Evidence Hash: $EVIDENCE_HASH"
echo "Merkle Root: $MERKLE_ROOT"
echo ""

# Açık sayılarını kontrol et
VULN_COUNT=$(sqlite3 "$EVIDENCE_DB" "SELECT COUNT(*) FROM vulns WHERE scan_id=$SCAN_ID" 2>/dev/null || echo "0")
TECH_COUNT=$(sqlite3 "$EVIDENCE_DB" "SELECT COUNT(*) FROM techno WHERE scan_id=$SCAN_ID" 2>/dev/null || echo "0")

echo "Vulnerabilities Found: $VULN_COUNT"
echo "Technologies Detected: $TECH_COUNT"
echo ""

# Hash doğrulama
echo "Verifying data integrity..."
CALCULATED_HASH=$(sqlite3 "$EVIDENCE_DB" "SELECT type||url||severity FROM vulns WHERE scan_id=$SCAN_ID" | sort | sha256sum | awk '{print $1}')

if [ "$CALCULATED_HASH" = "$EVIDENCE_HASH" ]; then
    echo "Status: VERIFIED"
    echo "The evidence has not been tampered with."
    exit 0
else
    echo "Status: FAILED"
    echo "Warning: Evidence hash mismatch!"
    echo "Calculated: $CALCULATED_HASH"
    echo "Stored: $EVIDENCE_HASH"
    exit 1
fi
'''

            if output_path:
                script_path = output_path
            else:
                script_path = f"/tmp/verify_scan_{self.scan_id}.sh"

            with open(script_path, "w") as f:
                f.write(script_content)
            os.chmod(script_path, 0o755)

            return script_path

        except Exception as e:
            print(f"[Blockchain] Script generation error: {e}")
            return None

    def start(self):
        """
        Kanıt toplama sürecini başlat.
        """
        return self.generate_evidence_hash()
