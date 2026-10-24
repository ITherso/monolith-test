"""Read-only JSONL event analysis; no process, network, or system modifications."""

import json
import os
import stat
from pathlib import Path

MAX_RECORD_BYTES = 1_048_576
MAX_POLL_BYTES = 4 * MAX_RECORD_BYTES
MAX_POLL_RECORDS = 1000


class PassiveEventMonitor:
    """Consume a supplied event log and flag events for human review.

    This does not collect OS events, capture packets, or establish compromise.
    A separate trusted producer must provide JSON objects, one per line.
    """

    def __init__(self, source: str | Path):
        if str(source).startswith(("\\\\", "//")):
            raise ValueError("A local event-log path is required")
        self.source = Path(source)
        self.offset = 0
        self.events_processed = 0
        self.invalid_records = 0
        self._file_id = None
        self._discarding_oversized = False
        self.has_more = False

    @staticmethod
    def analyze(event: dict) -> list[dict]:
        findings = []
        process = (
            str(event.get("process_name", "")).replace("\\", "/").split("/")[-1].lower()
        )
        if process in {"calc.exe", "calculator.exe", "calculatorapp.exe"} and event.get(
            "network_destination"
        ):
            findings.append(
                {
                    "kind": "calculator_network_activity",
                    "severity": "high",
                    "summary": "Calculator network activity was recorded; review the source event.",
                }
            )
        if event.get("action") == "persistence_created":
            findings.append(
                {
                    "kind": "persistence_entry_recorded",
                    "severity": "medium",
                    "summary": "A persistence entry was recorded; verify whether it was expected.",
                }
            )
        if (
            event.get("action") == "security_configuration_changed"
            and event.get("setting") == "real_time_protection"
            and event.get("enabled") is False
        ):
            findings.append(
                {
                    "kind": "protection_disabled_recorded",
                    "severity": "high",
                    "summary": "The event log reports that real-time protection was disabled.",
                }
            )
        for finding in findings:
            finding["timestamp"] = str(event.get("timestamp", ""))
            finding["evidence_type"] = "supplied_log_event"
            finding["compromise_confirmed"] = False
        return findings

    def poll_once(self) -> list[dict]:
        source = self.source.resolve(strict=True)
        if str(source).startswith(("\\\\", "//")):
            raise ValueError("A local event-log path is required")
        if not stat.S_ISREG(source.stat().st_mode):
            raise ValueError("The event log must be a regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        findings = []
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("The event log must be a regular file")
            identity = (opened.st_dev, opened.st_ino)
            if identity != self._file_id or opened.st_size < self.offset:
                self.offset = 0
                self._file_id = identity
                self._discarding_oversized = False
            stream.seek(self.offset)
            bytes_read = 0
            records_read = 0
            while records_read < MAX_POLL_RECORDS:
                remaining = MAX_POLL_BYTES - bytes_read
                if self._discarding_oversized:
                    if remaining <= 0:
                        break
                    raw = stream.readline(min(MAX_RECORD_BYTES + 1, remaining))
                    if not raw:
                        break
                    bytes_read += len(raw)
                    self.offset = stream.tell()
                    if raw.endswith(b"\n"):
                        self._discarding_oversized = False
                        records_read += 1
                    continue
                # Reserve enough budget for a complete maximum-sized record.
                if remaining < MAX_RECORD_BYTES + 1:
                    break
                start = stream.tell()
                raw = stream.readline(MAX_RECORD_BYTES + 1)
                if not raw:
                    break
                bytes_read += len(raw)
                if len(raw) > MAX_RECORD_BYTES:
                    self.invalid_records += 1
                    self.offset = stream.tell()
                    self._discarding_oversized = not raw.endswith(b"\n")
                    records_read += 1
                    continue
                if not raw.endswith(b"\n"):
                    # JSONL records commit only at a newline, even if valid JSON.
                    stream.seek(start)
                    break
                records_read += 1
                try:
                    event = json.loads(raw.decode("utf-8"))
                    if not isinstance(event, dict):
                        raise ValueError("An event must be a JSON object")
                except (ValueError, UnicodeDecodeError, RecursionError):
                    self.invalid_records += 1
                    self.offset = stream.tell()
                    continue
                self.events_processed += 1
                findings.extend(self.analyze(event))
                self.offset = stream.tell()
            self.has_more = self.offset < os.fstat(stream.fileno()).st_size
        return findings
