import os
import shutil

from cyberapp.models.db import db_conn


def find_tool(*candidates):
    for c in candidates:
        if not c:
            continue
        c_exp = os.path.expanduser(c)
        if shutil.which(c):
            return shutil.which(c)
        if os.path.exists(c_exp):
            return c_exp
    return None


TOOLS = {
    "Nmap": find_tool("nmap"),
    "Nikto": find_tool("nikto"),
    "SQLMap": find_tool("sqlmap"),
    "Whois": find_tool("whois"),
    "Gobuster": find_tool("gobuster"),
    "FFUF": find_tool("ffuf"),
    "Nuclei": find_tool("nuclei"),
    "Amass": find_tool("amass"),
    "SSLScan": find_tool("sslscan"),
    "WPScan": find_tool("wpscan"),
    "Arjun": find_tool("arjun"),
    "Dalfox": find_tool("dalfox"),
    "EyeWitness": find_tool("eyewitness"),
    "Metasploit": find_tool("msfconsole"),
    "Hydra": find_tool("hydra"),
    "Patator": find_tool("patator"),
    "CrackMapExec": find_tool("crackmapexec"),
    "Impacket": find_tool("GetNPUsers.py"),
    "Responder": find_tool("Responder.py"),
    "LinPEAS": "/opt/PEAS/linpeas.sh",
    "WinPEAS": "/opt/PEAS/winpeas.exe",
    "Trivy": find_tool("trivy"),
    "TruffleHog": find_tool("trufflehog"),
    "Gitleaks": find_tool("gitleaks"),
    "Semgrep": find_tool("semgrep"),
    "Bandit": find_tool("bandit"),
    "Safety": find_tool("safety"),
    "NpmAudit": find_tool("npm"),
    "PipAudit": find_tool("pip-audit"),
    "Syft": find_tool("syft"),
    "Grype": find_tool("grype"),
}


DIR_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
if os.path.exists("/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt"):
    DIR_WORDLIST = "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt"


class SupremeArsenalEngine:
    def __init__(self, target, scan_id, tools_selected):
        self.target = target
        self.domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        self.scan_id = scan_id
        self.tools = tools_selected

    def log_tool(self, tool, output):
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO tool_logs (scan_id, tool_name, output) VALUES (?, ?, ?)",
                    (self.scan_id, tool, output),
                )
        except Exception:
            pass

    def start(self):
        if "supply_chain" in self.tools:
            self.log_tool("SUPPLY_CHAIN_START", "Starting supply chain audit...")
            try:
                from cybermodules.supply_chain import SupplyChainAuditor  # type: ignore
            except Exception:
                self.log_tool("SUPPLY_CHAIN_ERROR", "SupplyChainAuditor not available")
            else:
                supply = SupplyChainAuditor(self.target, self.scan_id)
                supply.start()

        if "zeroday" in self.tools:
            self.log_tool("ZERODAY_START", "Starting zero-day research...")
            try:
                from cybermodules.zeroday import ZeroDayResearchEngine
            except Exception:
                self.log_tool("ZERODAY_ERROR", "ZeroDayResearchEngine not available")
            else:
                zeroday = ZeroDayResearchEngine(self.target, self.scan_id)
                zeroday.start()

        if "cloud_audit" in self.tools:
            self.log_tool("CLOUD_AUDIT_START", "Starting cloud security audit...")
            try:
                from cybermodules.cloud import CloudSecurityAuditor
            except Exception:
                self.log_tool("CLOUD_AUDIT_ERROR", "CloudSecurityAuditor not available")
            else:
                cloud = CloudSecurityAuditor(self.target, self.scan_id)
                cloud.start()

        if "api_scan" in self.tools:
            self.log_tool("API_SCAN_START", "Starting API security scan...")
            try:
                from cybermodules.api_scanner import APISecurityScanner
            except Exception:
                self.log_tool("API_SCAN_ERROR", "APISecurityScanner not available")
            else:
                api = APISecurityScanner(self.target, self.scan_id)
                api.start()

        if "blockchain" in self.tools:
            self.log_tool("BLOCKCHAIN_START", "Starting blockchain evidence collection...")
            try:
                from cybermodules.blockchain import BlockchainEvidence
            except Exception:
                self.log_tool("BLOCKCHAIN_ERROR", "BlockchainEvidence not available")
            else:
                blockchain = BlockchainEvidence(self.scan_id)
                blockchain.collect_evidence()
                blockchain.generate_verification_script()

        if "gamification" in self.tools:
            self.log_tool("GAMIFICATION_START", "Starting gamification engine...")
            try:
                from cybermodules.gamification import GamificationEngine
            except Exception:
                self.log_tool("GAMIFICATION_ERROR", "GamificationEngine not available")
            else:
                game = GamificationEngine(self.scan_id)
                score, level, achievements, badges = game.calculate_score()
                game.generate_certificate()
                game.create_ctf_challenge()

                leaderboard_pos = game.get_leaderboard_position()
                self.log_tool(
                    "GAMIFICATION_RESULT",
                    f"Score: {score} | Level: {level} | Achievements: {len(achievements)} | "
                    f"Badges: {len(badges)} | Leaderboard: #{leaderboard_pos}",
                )

        self.run_standard_tools()

    def run_standard_tools(self):
        if "nmap" in self.tools and TOOLS["Nmap"]:
            try:
                from monolith.tasks import run_nmap

                task = run_nmap.delay(self.target, args=["-sV", "-sC", "-O", "-T4"])
                if hasattr(task, 'id'):
                    self.log_tool("Nmap", f"Enqueued Nmap task id={task.id}")
                else:
                    out = task
                    try:
                        with open(out, 'r') as f:
                            txt = f.read()
                        self.log_tool("Nmap", txt[:5000])
                        for line in txt.split('\n'):
                            if 'open' in line and 'tcp' in line:
                                port_info = line.strip()
                                self.log_tool("NMAP_PORTS", f"Open port: {port_info}")
                    except Exception as e:
                        self.log_tool("Nmap", f"Error reading nmap output: {str(e)}")
            except Exception as e:
                self.log_tool("Nmap", f"Error: {str(e)}")

        if "nuclei" in self.tools and TOOLS["Nuclei"]:
            try:
                from monolith.tasks import run_nuclei

                task = run_nuclei.delay(self.target)
                if hasattr(task, 'id'):
                    self.log_tool("Nuclei", f"Enqueued Nuclei task id={task.id}")
                else:
                    out = task
                    try:
                        with open(out, 'r') as f:
                            txt = f.read()
                        self.log_tool("Nuclei", txt[:5000])
                        critical_count = txt.count('[critical]')
                        high_count = txt.count('[high]')
                        if critical_count > 0 or high_count > 0:
                            self.log_tool(
                                "NUCLEI_ALERT",
                                f"Critical: {critical_count}, High: {high_count} vulnerabilities found",
                            )
                    except Exception as e:
                        self.log_tool("Nuclei", f"Error reading nuclei output: {str(e)}")
            except Exception as e:
                self.log_tool("Nuclei", f"Error: {str(e)}")

        if "gobuster" in self.tools and TOOLS["Gobuster"]:
            try:
                from monolith.tasks import run_gobuster

                task = run_gobuster.delay(self.target, wordlist=DIR_WORDLIST)
                if hasattr(task, 'id'):
                    self.log_tool("Gobuster", f"Enqueued Gobuster task id={task.id}")
                else:
                    out = task
                    try:
                        with open(out, 'r') as f:
                            txt = f.read()
                        self.log_tool("Gobuster", txt[:2000])
                        found_dirs = []
                        for line in txt.split('\n'):
                            if ('Status: 200' in line) or ('Status: 301' in line) or ('Status: 302' in line):
                                found_dirs.append(line.strip())

                        if found_dirs:
                            self.log_tool("GOBUSTER_DIRS", f"Found {len(found_dirs)} accessible directories")
                    except Exception as e:
                        self.log_tool("Gobuster", f"Error reading gobuster output: {str(e)}")
            except Exception as e:
                self.log_tool("Gobuster", f"Error: {str(e)}")
