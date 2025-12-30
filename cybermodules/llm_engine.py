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