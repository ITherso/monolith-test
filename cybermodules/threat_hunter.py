"""Passive analysis of an explicitly supplied JSONL security-event log."""

import os
import threading

from cyberapp.passive_monitor import PassiveEventMonitor


class ThreatHunter:
    def __init__(
        self, interface="eth0", event_log=None, on_finding=None, poll_interval=1.0
    ):
        self.interface = interface
        self.running = False
        self.event_log = event_log or os.getenv("MONOLITH_EVENT_LOG")
        self.on_finding = on_finding
        self.poll_interval = max(float(poll_interval), 0.1)
        self.findings = []
        self.monitor = PassiveEventMonitor(self.event_log) if self.event_log else None
        self._stop = threading.Event()

    def poll_once(self):
        if self.monitor is None:
            raise RuntimeError(
                "Configure a local JSONL event log; packet capture is not implemented"
            )
        findings = self.monitor.poll_once()
        self.findings.extend(findings)
        self.findings = self.findings[-1000:]
        for finding in findings:
            if self.on_finding:
                self.on_finding(finding)
        return findings

    def start(self):
        self._stop.clear()
        try:
            self.poll_once()  # Validate the supplied source before claiming activity.
            self.running = not self._stop.is_set()
            while self.running and not self._stop.wait(self.poll_interval):
                self.poll_once()
        finally:
            self.running = False

    def stop(self):
        self.running = False
        self._stop.set()
