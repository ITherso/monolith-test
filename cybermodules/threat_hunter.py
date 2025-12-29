# --- THREAT HUNTER MODULE ---
import time


class ThreatHunter:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.running = False

    def start(self):
        self.running = True
        print(f"[ThreatHunter] Monitoring started on {self.interface}")
        while self.running:
            time.sleep(5)

    def stop(self):
        self.running = False
        print("[ThreatHunter] Monitoring stopped")
