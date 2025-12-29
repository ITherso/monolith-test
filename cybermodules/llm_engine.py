class LLMEngine:
    def __init__(self, scan_id):
        self.scan_id = scan_id

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
