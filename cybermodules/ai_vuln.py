from cyberapp.models.db import db_conn


class AIVulnerabilityPredictor:
    def __init__(self, scan_id):
        self.scan_id = scan_id

    def predict_vulnerabilities(self):
        try:
            with db_conn() as conn:
                techs = [r[0] for r in conn.execute("SELECT name FROM techno WHERE scan_id=?", (self.scan_id,)).fetchall()]
                vulns = [r[0] for r in conn.execute("SELECT type FROM vulns WHERE scan_id=?", (self.scan_id,)).fetchall()]

            # Basit risk skoru hesaplama
            risk_score = 0.0
            recommendations = []

            # Teknoloji bazlı riskler
            if "WordPress" in techs:
                risk_score += 0.15
                recommendations.append("WordPress detected - check for vulnerable plugins")

            # Mevcut zafiyetler
            vuln_multipliers = {
                "SQL_INJECTION": 0.3,
                "RCE": 0.35,
                "XSS": 0.15,
                "Header Eksik": 0.1,
            }

            for vuln in vulns:
                for key, mult in vuln_multipliers.items():
                    if key in vuln:
                        risk_score += mult

            # Normalize et
            risk_score = min(risk_score, 1.0)

            # Risk seviyesi
            if risk_score >= 0.7:
                risk_level = "CRITICAL"
            elif risk_score >= 0.4:
                risk_level = "HIGH"
            elif risk_score >= 0.2:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            return risk_score, risk_level, len(recommendations)
        except Exception:
            return 0.0, "UNKNOWN", 0
