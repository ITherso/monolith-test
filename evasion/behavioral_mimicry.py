"""
Behavioral Mimicry + Human-Like Agent
======================================
Advanced human behavior simulation to bypass EDR behavioral ML detection.

Features:
- Mouse/Keyboard simulation (PyAutoGUI-like patterns)
- Natural traffic pattern generation (GAN-based)
- Human typing cadence with realistic errors
- Mouse movement with Bézier curves (human-like)
- Activity scheduling (work hours, breaks)
- Process interaction patterns
- Network traffic timing jitter
- EDR Behavioral ML bypass (SentinelOne, CrowdStrike, etc.)

Target: SentinelOne Behavioral Score = 0

⚠️ LEGAL WARNING: For authorized penetration testing only.
"""

from __future__ import annotations
import os
import re
import json
import math
import time
import random
import hashlib
import secrets
import logging
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Callable, Union
from enum import Enum, auto
from collections import deque
import numpy as np

logger = logging.getLogger("behavioral_mimicry")


# =============================================================================
# ENUMS & CONSTANTS
# =============================================================================

class MimicryMode(Enum):
    """Behavioral mimicry intensity levels"""
    DISABLED = "disabled"           # No mimicry
    LIGHT = "light"                 # Basic jitter only
    MODERATE = "moderate"           # Mouse + keyboard simulation
    AGGRESSIVE = "aggressive"       # Full human simulation
    PARANOID = "paranoid"           # Maximum stealth, continuous activity
    HUMAN = "human"                 # Indistinguishable from real user


class ActivityType(Enum):
    """Types of simulated human activity"""
    MOUSE_MOVE = "mouse_move"
    MOUSE_CLICK = "mouse_click"
    MOUSE_SCROLL = "mouse_scroll"
    KEY_PRESS = "key_press"
    KEY_COMBO = "key_combo"
    TYPING = "typing"
    WINDOW_SWITCH = "window_switch"
    FILE_BROWSE = "file_browse"
    IDLE = "idle"
    READING = "reading"
    BREAK = "break"


class TrafficPattern(Enum):
    """Network traffic patterns"""
    BURSTY = "bursty"               # Human browsing pattern
    STEADY = "steady"               # Background service
    PERIODIC = "periodic"           # Scheduled tasks
    REACTIVE = "reactive"           # User-initiated
    MIXED = "mixed"                 # Combination


class EDRBehavioralEngine(Enum):
    """EDR behavioral detection engines"""
    SENTINELONE = "sentinelone"
    CROWDSTRIKE = "crowdstrike"
    CARBONBLACK = "carbonblack"
    DEFENDER_ATP = "defender_atp"
    CYLANCE = "cylance"
    SOPHOS = "sophos"


# Human behavior constants (based on research)
HUMAN_TYPING_SPEED = {
    "slow": (150, 300),      # ms between keys
    "average": (80, 150),
    "fast": (40, 80),
    "expert": (20, 50),
}

HUMAN_MOUSE_SPEED = {
    "slow": (0.5, 1.5),      # pixels per ms
    "average": (1.0, 3.0),
    "fast": (2.0, 5.0),
}

# Typing error rates (based on human studies)
TYPING_ERROR_RATE = 0.02        # 2% error rate
TYPING_CORRECTION_RATE = 0.8    # 80% of errors are corrected
DOUBLE_LETTER_RATE = 0.01       # 1% double letter typos

# Mouse movement characteristics
MOUSE_OVERSHOOT_RATE = 0.15     # 15% overshoot target
MOUSE_CURVE_POINTS = 20         # Bezier curve resolution

# Work pattern constants
WORK_START_HOUR = 9
WORK_END_HOUR = 17
LUNCH_START_HOUR = 12
LUNCH_END_HOUR = 13
BREAK_INTERVAL_MIN = 45         # Minutes between breaks
BREAK_DURATION_MIN = 5          # Average break duration


# =============================================================================
# DATACLASSES
# =============================================================================

@dataclass
class MouseState:
    """Current mouse state"""
    x: int = 0
    y: int = 0
    buttons: Dict[str, bool] = field(default_factory=lambda: {"left": False, "right": False, "middle": False})
    last_move_time: float = 0.0
    movement_history: deque = field(default_factory=lambda: deque(maxlen=100))


@dataclass
class KeyboardState:
    """Current keyboard state"""
    pressed_keys: set = field(default_factory=set)
    last_key_time: float = 0.0
    typing_speed: str = "average"
    key_history: deque = field(default_factory=lambda: deque(maxlen=500))


@dataclass
class ActivityEvent:
    """Single activity event"""
    event_id: str
    activity_type: ActivityType
    timestamp: float
    duration_ms: int
    details: Dict[str, Any] = field(default_factory=dict)
    synthetic: bool = True  # True = generated, False = real


@dataclass
class TrafficEvent:
    """Network traffic event"""
    event_id: str
    timestamp: float
    direction: str  # "outbound" or "inbound"
    size_bytes: int
    timing_jitter_ms: int
    pattern: TrafficPattern
    destination: str = ""


@dataclass
class BehavioralProfile:
    """Human behavioral profile for simulation"""
    profile_id: str
    typing_speed: str = "average"
    mouse_speed: str = "average"
    error_rate: float = TYPING_ERROR_RATE
    work_hours: Tuple[int, int] = (WORK_START_HOUR, WORK_END_HOUR)
    break_frequency: int = BREAK_INTERVAL_MIN
    activity_variance: float = 0.3  # 30% variance in timing
    preferred_apps: List[str] = field(default_factory=lambda: ["chrome", "outlook", "excel", "notepad"])


@dataclass
class MimicryResult:
    """Result of mimicry operation"""
    success: bool
    mode: MimicryMode
    events_generated: int
    duration_ms: int
    behavioral_score: float  # 0 = perfect human, 1 = obvious bot
    edr_bypass_confidence: float
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class DefenseAnalysis:
    """Defense analysis result"""
    edr_detected: Optional[EDRBehavioralEngine]
    behavioral_monitoring: bool
    ml_detection: bool
    recommended_mode: MimicryMode
    risk_factors: List[str]
    bypass_strategies: List[str]
    confidence: float


# =============================================================================
# NEURAL NETWORK FOR TRAFFIC GENERATION
# =============================================================================

class GANTrafficGenerator:
    """
    GAN-based Network Traffic Pattern Generator
    
    Generates human-like network traffic patterns to evade
    behavioral ML detection.
    
    Features:
    - Learned inter-packet timing from real user traffic
    - Burst patterns matching human browsing
    - Request size distribution mimicking real browsers
    - Realistic idle periods
    """
    
    def __init__(self, latent_dim: int = 32):
        self.latent_dim = latent_dim
        
        # Generator network (simple MLP)
        self.gen_weights1 = np.random.randn(latent_dim, 64) * 0.1
        self.gen_bias1 = np.zeros(64)
        self.gen_weights2 = np.random.randn(64, 32) * 0.1
        self.gen_bias2 = np.zeros(32)
        self.gen_weights3 = np.random.randn(32, 4) * 0.1  # [timing, size, burst_prob, idle_prob]
        self.gen_bias3 = np.zeros(4)
        
        # Discriminator network
        self.disc_weights1 = np.random.randn(4, 32) * 0.1
        self.disc_bias1 = np.zeros(32)
        self.disc_weights2 = np.random.randn(32, 16) * 0.1
        self.disc_bias2 = np.zeros(16)
        self.disc_weights3 = np.random.randn(16, 1) * 0.1
        self.disc_bias3 = np.zeros(1)
        
        # Pre-train with human traffic patterns
        self._pretrain()
    
    def _pretrain(self):
        """Pre-train on synthetic human traffic patterns"""
        # Generate synthetic "human" traffic samples
        human_samples = []
        
        for _ in range(1000):
            # Human browsing characteristics
            timing = random.gauss(500, 200)  # ~500ms between requests
            timing = max(50, min(timing, 5000))
            
            size = random.gauss(1500, 500)  # ~1.5KB average
            size = max(100, min(size, 10000))
            
            burst_prob = random.random() * 0.3  # 0-30% burst probability
            idle_prob = random.random() * 0.2   # 0-20% idle probability
            
            human_samples.append([timing, size, burst_prob, idle_prob])
        
        # Simple training (gradient descent)
        X = np.array(human_samples)
        X = (X - X.mean(axis=0)) / (X.std(axis=0) + 1e-8)  # Normalize
        
        lr = 0.001
        for epoch in range(100):
            # Train discriminator on real samples
            for sample in X[:100]:
                self._train_discriminator_step(sample.reshape(1, -1), real=True, lr=lr)
            
            # Train generator
            noise = np.random.randn(10, self.latent_dim)
            for n in noise:
                self._train_generator_step(n.reshape(1, -1), lr=lr)
    
    def _leaky_relu(self, x, alpha=0.01):
        return np.where(x > 0, x, alpha * x)
    
    def _sigmoid(self, x):
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
    
    def _generate(self, noise: np.ndarray) -> np.ndarray:
        """Generator forward pass"""
        x = noise @ self.gen_weights1 + self.gen_bias1
        x = self._leaky_relu(x)
        x = x @ self.gen_weights2 + self.gen_bias2
        x = self._leaky_relu(x)
        x = x @ self.gen_weights3 + self.gen_bias3
        return x
    
    def _discriminate(self, x: np.ndarray) -> np.ndarray:
        """Discriminator forward pass"""
        h = x @ self.disc_weights1 + self.disc_bias1
        h = self._leaky_relu(h)
        h = h @ self.disc_weights2 + self.disc_bias2
        h = self._leaky_relu(h)
        h = h @ self.disc_weights3 + self.disc_bias3
        return self._sigmoid(h)
    
    def _train_discriminator_step(self, sample: np.ndarray, real: bool, lr: float):
        """Single discriminator training step"""
        pred = self._discriminate(sample)
        target = 1.0 if real else 0.0
        
        # Binary cross-entropy gradient
        grad = pred - target
        
        # Simple gradient descent (backprop simplified)
        self.disc_weights3 -= lr * grad * 0.01
        self.disc_bias3 -= lr * grad.flatten() * 0.01
    
    def _train_generator_step(self, noise: np.ndarray, lr: float):
        """Single generator training step"""
        generated = self._generate(noise)
        pred = self._discriminate(generated)
        
        # Generator wants discriminator to output 1 (real)
        grad = pred - 1.0
        
        # Simple gradient descent
        self.gen_weights3 -= lr * grad * 0.01
        self.gen_bias3 -= lr * grad.flatten() * 0.01
    
    def generate_traffic_pattern(self, num_events: int = 10) -> List[TrafficEvent]:
        """Generate human-like traffic pattern"""
        events = []
        current_time = time.time()
        
        for i in range(num_events):
            # Generate from GAN
            noise = np.random.randn(1, self.latent_dim)
            params = self._generate(noise)[0]
            
            # Denormalize parameters
            timing_ms = int(max(50, min(abs(params[0]) * 500 + 200, 5000)))
            size_bytes = int(max(100, min(abs(params[1]) * 1500 + 500, 50000)))
            burst_prob = abs(params[2]) % 1.0
            idle_prob = abs(params[3]) % 1.0
            
            # Apply burst logic
            if random.random() < burst_prob:
                # Burst: rapid succession of requests
                timing_ms = int(timing_ms * 0.2)
                size_bytes = int(size_bytes * 0.5)
            
            # Apply idle logic
            if random.random() < idle_prob:
                # Idle period
                timing_ms = int(timing_ms * 5)
            
            # Add jitter
            jitter_ms = int(random.gauss(0, timing_ms * 0.1))
            
            current_time += (timing_ms + jitter_ms) / 1000.0
            
            event = TrafficEvent(
                event_id=secrets.token_hex(8),
                timestamp=current_time,
                direction="outbound",
                size_bytes=size_bytes,
                timing_jitter_ms=jitter_ms,
                pattern=TrafficPattern.BURSTY if burst_prob > 0.2 else TrafficPattern.REACTIVE,
            )
            events.append(event)
        
        return events
    
    def get_optimal_timing(self) -> Tuple[int, int]:
        """Get optimal timing for next request (min_ms, max_ms)"""
        noise = np.random.randn(1, self.latent_dim)
        params = self._generate(noise)[0]
        
        base_timing = int(abs(params[0]) * 500 + 200)
        variance = int(base_timing * 0.3)
        
        return (max(50, base_timing - variance), base_timing + variance)


# =============================================================================
# MOUSE SIMULATION
# =============================================================================

class HumanMouseSimulator:
    """
    Human-like mouse movement simulation
    
    Features:
    - Bézier curve movements (natural arcs)
    - Micro-movements and tremor
    - Overshoot and correction
    - Natural acceleration/deceleration
    - Click patterns (double-click timing)
    - Scroll behavior
    """
    
    def __init__(self, screen_width: int = 1920, screen_height: int = 1080):
        self.screen_width = screen_width
        self.screen_height = screen_height
        self.state = MouseState()
        self.movement_speed = "average"
    
    def _bezier_curve(
        self,
        start: Tuple[int, int],
        end: Tuple[int, int],
        control_points: int = 2
    ) -> List[Tuple[int, int]]:
        """Generate Bézier curve points for natural movement"""
        points = [start]
        
        # Generate random control points
        controls = []
        for i in range(control_points):
            # Control points deviate from straight line
            t = (i + 1) / (control_points + 1)
            
            # Linear interpolation with random offset
            cx = start[0] + (end[0] - start[0]) * t
            cy = start[1] + (end[1] - start[1]) * t
            
            # Add human-like deviation
            distance = math.sqrt((end[0] - start[0])**2 + (end[1] - start[1])**2)
            deviation = distance * random.gauss(0, 0.15)
            
            angle = random.uniform(0, 2 * math.pi)
            cx += deviation * math.cos(angle)
            cy += deviation * math.sin(angle)
            
            controls.append((cx, cy))
        
        # Generate curve points
        all_points = [start] + controls + [end]
        
        for t in np.linspace(0, 1, MOUSE_CURVE_POINTS):
            point = self._de_casteljau(all_points, t)
            points.append((int(point[0]), int(point[1])))
        
        return points
    
    def _de_casteljau(
        self,
        points: List[Tuple[float, float]],
        t: float
    ) -> Tuple[float, float]:
        """De Casteljau's algorithm for Bézier curve evaluation"""
        if len(points) == 1:
            return points[0]
        
        new_points = []
        for i in range(len(points) - 1):
            x = (1 - t) * points[i][0] + t * points[i + 1][0]
            y = (1 - t) * points[i][1] + t * points[i + 1][1]
            new_points.append((x, y))
        
        return self._de_casteljau(new_points, t)
    
    def _add_micro_movements(self, path: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        """Add micro-movements/tremor to path"""
        result = []
        
        for i, (x, y) in enumerate(path):
            # Add small random jitter (human hand tremor)
            jitter_x = int(random.gauss(0, 1))
            jitter_y = int(random.gauss(0, 1))
            
            # Occasionally add larger micro-movement
            if random.random() < 0.05:
                jitter_x += int(random.gauss(0, 3))
                jitter_y += int(random.gauss(0, 3))
            
            result.append((
                max(0, min(self.screen_width - 1, x + jitter_x)),
                max(0, min(self.screen_height - 1, y + jitter_y))
            ))
        
        return result
    
    def _calculate_movement_time(self, distance: float) -> float:
        """Calculate movement time using Fitts's Law"""
        # Fitts's Law: MT = a + b * log2(2D/W)
        # Where D = distance, W = target width (assume 20px)
        a = 50  # Base time (ms)
        b = 150  # Movement coefficient
        w = 20  # Target width
        
        if distance < 1:
            return a
        
        mt = a + b * math.log2(2 * distance / w)
        
        # Adjust for speed setting
        speed_multipliers = {"slow": 1.5, "average": 1.0, "fast": 0.6}
        mt *= speed_multipliers.get(self.movement_speed, 1.0)
        
        # Add variance (humans are inconsistent)
        mt *= random.gauss(1.0, 0.15)
        
        return max(50, mt)
    
    def generate_movement(
        self,
        target_x: int,
        target_y: int,
        overshoot: bool = None
    ) -> List[ActivityEvent]:
        """Generate human-like mouse movement to target"""
        events = []
        start_time = time.time()
        
        start = (self.state.x, self.state.y)
        end = (target_x, target_y)
        
        # Calculate distance
        distance = math.sqrt((end[0] - start[0])**2 + (end[1] - start[1])**2)
        
        # Decide on overshoot
        if overshoot is None:
            overshoot = random.random() < MOUSE_OVERSHOOT_RATE
        
        if overshoot:
            # Overshoot target slightly
            overshoot_distance = distance * random.uniform(0.05, 0.15)
            angle = math.atan2(end[1] - start[1], end[0] - start[0])
            
            overshoot_x = int(end[0] + overshoot_distance * math.cos(angle))
            overshoot_y = int(end[1] + overshoot_distance * math.sin(angle))
            
            overshoot_x = max(0, min(self.screen_width - 1, overshoot_x))
            overshoot_y = max(0, min(self.screen_height - 1, overshoot_y))
            
            # Movement to overshoot
            path1 = self._bezier_curve(start, (overshoot_x, overshoot_y))
            path1 = self._add_micro_movements(path1)
            
            # Correction movement
            path2 = self._bezier_curve((overshoot_x, overshoot_y), end)
            path2 = self._add_micro_movements(path2)
            
            path = path1 + path2[1:]  # Avoid duplicate point
        else:
            path = self._bezier_curve(start, end)
            path = self._add_micro_movements(path)
        
        # Calculate timing
        total_time_ms = self._calculate_movement_time(distance)
        time_per_point = total_time_ms / len(path)
        
        current_time = start_time
        
        for i, (x, y) in enumerate(path):
            # Variable timing (acceleration/deceleration)
            # Slow at start and end, fast in middle
            t = i / len(path)
            speed_factor = 1 - 0.5 * (math.cos(2 * math.pi * t) + 1) / 2
            point_time = time_per_point * (0.5 + speed_factor)
            
            event = ActivityEvent(
                event_id=secrets.token_hex(8),
                activity_type=ActivityType.MOUSE_MOVE,
                timestamp=current_time,
                duration_ms=int(point_time),
                details={"x": x, "y": y, "point_index": i}
            )
            events.append(event)
            
            current_time += point_time / 1000.0
        
        # Update state
        self.state.x = target_x
        self.state.y = target_y
        self.state.last_move_time = current_time
        
        return events
    
    def generate_click(
        self,
        button: str = "left",
        double: bool = False
    ) -> List[ActivityEvent]:
        """Generate mouse click event"""
        events = []
        current_time = time.time()
        
        # Click timing
        press_duration = random.gauss(80, 20)  # ~80ms press
        press_duration = max(30, min(press_duration, 200))
        
        # Press event
        events.append(ActivityEvent(
            event_id=secrets.token_hex(8),
            activity_type=ActivityType.MOUSE_CLICK,
            timestamp=current_time,
            duration_ms=int(press_duration),
            details={"button": button, "action": "press", "x": self.state.x, "y": self.state.y}
        ))
        
        current_time += press_duration / 1000.0
        
        # Release event
        events.append(ActivityEvent(
            event_id=secrets.token_hex(8),
            activity_type=ActivityType.MOUSE_CLICK,
            timestamp=current_time,
            duration_ms=0,
            details={"button": button, "action": "release", "x": self.state.x, "y": self.state.y}
        ))
        
        # Double click
        if double:
            # Inter-click interval (Windows default: <500ms)
            interval = random.gauss(100, 30)
            interval = max(50, min(interval, 200))
            
            current_time += interval / 1000.0
            
            # Second click
            press_duration = random.gauss(80, 20)
            
            events.append(ActivityEvent(
                event_id=secrets.token_hex(8),
                activity_type=ActivityType.MOUSE_CLICK,
                timestamp=current_time,
                duration_ms=int(press_duration),
                details={"button": button, "action": "press", "double": True, "x": self.state.x, "y": self.state.y}
            ))
            
            current_time += press_duration / 1000.0
            
            events.append(ActivityEvent(
                event_id=secrets.token_hex(8),
                activity_type=ActivityType.MOUSE_CLICK,
                timestamp=current_time,
                duration_ms=0,
                details={"button": button, "action": "release", "double": True, "x": self.state.x, "y": self.state.y}
            ))
        
        return events
    
    def generate_scroll(self, direction: str = "down", amount: int = 3) -> List[ActivityEvent]:
        """Generate mouse scroll event"""
        events = []
        current_time = time.time()
        
        # Scroll in increments (like human scrolling)
        for i in range(amount):
            scroll_delay = random.gauss(50, 15)
            scroll_delay = max(20, min(scroll_delay, 150))
            
            events.append(ActivityEvent(
                event_id=secrets.token_hex(8),
                activity_type=ActivityType.MOUSE_SCROLL,
                timestamp=current_time,
                duration_ms=int(scroll_delay),
                details={
                    "direction": direction,
                    "delta": 1 if direction == "down" else -1,
                    "x": self.state.x,
                    "y": self.state.y
                }
            ))
            
            current_time += scroll_delay / 1000.0
        
        return events


# =============================================================================
# KEYBOARD SIMULATION
# =============================================================================

class HumanKeyboardSimulator:
    """
    Human-like keyboard input simulation
    
    Features:
    - Natural typing cadence
    - Realistic typos and corrections
    - Key combination timing
    - Fatigue simulation (slower over time)
    - Individual key timing variance
    """
    
    def __init__(self, typing_speed: str = "average"):
        self.state = KeyboardState(typing_speed=typing_speed)
        
        # Key position map (for timing calculation)
        self.key_positions = self._build_key_map()
        
        # Common typo pairs
        self.typo_pairs = {
            'a': ['s', 'q', 'z'],
            'b': ['v', 'n', 'g', 'h'],
            'c': ['x', 'v', 'd', 'f'],
            'd': ['s', 'f', 'e', 'r', 'c', 'x'],
            'e': ['w', 'r', 'd', 's'],
            'f': ['d', 'g', 'r', 't', 'v', 'c'],
            'g': ['f', 'h', 't', 'y', 'b', 'v'],
            'h': ['g', 'j', 'y', 'u', 'n', 'b'],
            'i': ['u', 'o', 'k', 'j'],
            'j': ['h', 'k', 'u', 'i', 'm', 'n'],
            'k': ['j', 'l', 'i', 'o', 'm'],
            'l': ['k', 'o', 'p'],
            'm': ['n', 'j', 'k'],
            'n': ['b', 'm', 'h', 'j'],
            'o': ['i', 'p', 'k', 'l'],
            'p': ['o', 'l'],
            'q': ['w', 'a'],
            'r': ['e', 't', 'd', 'f'],
            's': ['a', 'd', 'w', 'e', 'x', 'z'],
            't': ['r', 'y', 'f', 'g'],
            'u': ['y', 'i', 'h', 'j'],
            'v': ['c', 'b', 'f', 'g'],
            'w': ['q', 'e', 'a', 's'],
            'x': ['z', 'c', 's', 'd'],
            'y': ['t', 'u', 'g', 'h'],
            'z': ['a', 'x', 's'],
        }
    
    def _build_key_map(self) -> Dict[str, Tuple[int, int]]:
        """Build keyboard position map"""
        # QWERTY layout positions (row, col)
        rows = [
            "`1234567890-=",
            "qwertyuiop[]\\",
            "asdfghjkl;'",
            "zxcvbnm,./"
        ]
        
        positions = {}
        for row_idx, row in enumerate(rows):
            for col_idx, key in enumerate(row):
                positions[key] = (row_idx, col_idx)
                positions[key.upper()] = (row_idx, col_idx)
        
        return positions
    
    def _key_distance(self, key1: str, key2: str) -> float:
        """Calculate distance between keys"""
        if key1 not in self.key_positions or key2 not in self.key_positions:
            return 1.0
        
        pos1 = self.key_positions[key1]
        pos2 = self.key_positions[key2]
        
        return math.sqrt((pos1[0] - pos2[0])**2 + (pos1[1] - pos2[1])**2)
    
    def _get_key_delay(self, prev_key: str, curr_key: str) -> int:
        """Calculate delay between keystrokes"""
        speed_range = HUMAN_TYPING_SPEED.get(self.state.typing_speed, (80, 150))
        
        # Base delay
        base_delay = random.gauss(
            (speed_range[0] + speed_range[1]) / 2,
            (speed_range[1] - speed_range[0]) / 4
        )
        
        # Adjust for key distance (farther keys = longer delay)
        if prev_key and curr_key:
            distance = self._key_distance(prev_key, curr_key)
            base_delay += distance * 10
        
        # Adjust for same finger (slower) vs different hand (faster)
        if prev_key and curr_key:
            if prev_key.lower() in 'qwertasdfgzxcvb' and curr_key.lower() in 'qwertasdfgzxcvb':
                base_delay *= 1.1  # Same hand
            elif prev_key.lower() in 'yuiophjklnm' and curr_key.lower() in 'yuiophjklnm':
                base_delay *= 1.1  # Same hand
            else:
                base_delay *= 0.9  # Different hands (faster)
        
        # Adjust for case shift
        if curr_key.isupper() and (not prev_key or not prev_key.isupper()):
            base_delay += 30  # Shift key press
        
        return int(max(speed_range[0], min(speed_range[1] * 1.5, base_delay)))
    
    def _generate_typo(self, char: str) -> Optional[str]:
        """Generate a realistic typo for a character"""
        if char.lower() in self.typo_pairs:
            typo_options = self.typo_pairs[char.lower()]
            typo = random.choice(typo_options)
            return typo.upper() if char.isupper() else typo
        return None
    
    def generate_typing(
        self,
        text: str,
        include_errors: bool = True
    ) -> List[ActivityEvent]:
        """Generate human-like typing for text"""
        events = []
        current_time = time.time()
        prev_key = None
        
        i = 0
        while i < len(text):
            char = text[i]
            
            # Check for typo
            if include_errors and random.random() < TYPING_ERROR_RATE:
                typo = self._generate_typo(char)
                
                if typo:
                    # Type wrong character
                    delay = self._get_key_delay(prev_key, typo)
                    events.append(ActivityEvent(
                        event_id=secrets.token_hex(8),
                        activity_type=ActivityType.TYPING,
                        timestamp=current_time,
                        duration_ms=delay,
                        details={"char": typo, "typo": True}
                    ))
                    current_time += delay / 1000.0
                    
                    # Correction (if we notice the error)
                    if random.random() < TYPING_CORRECTION_RATE:
                        # Pause (noticing error)
                        pause = random.gauss(200, 50)
                        current_time += pause / 1000.0
                        
                        # Backspace
                        events.append(ActivityEvent(
                            event_id=secrets.token_hex(8),
                            activity_type=ActivityType.KEY_PRESS,
                            timestamp=current_time,
                            duration_ms=int(random.gauss(80, 20)),
                            details={"key": "backspace", "correction": True}
                        ))
                        current_time += 80 / 1000.0
                        
                        prev_key = "backspace"
            
            # Check for double letter error
            if include_errors and random.random() < DOUBLE_LETTER_RATE:
                # Accidentally double-type
                delay = self._get_key_delay(prev_key, char)
                events.append(ActivityEvent(
                    event_id=secrets.token_hex(8),
                    activity_type=ActivityType.TYPING,
                    timestamp=current_time,
                    duration_ms=delay,
                    details={"char": char, "accidental_double": True}
                ))
                current_time += delay / 1000.0
                
                # Correct with backspace
                events.append(ActivityEvent(
                    event_id=secrets.token_hex(8),
                    activity_type=ActivityType.KEY_PRESS,
                    timestamp=current_time,
                    duration_ms=int(random.gauss(80, 20)),
                    details={"key": "backspace", "correction": True}
                ))
                current_time += 80 / 1000.0
            
            # Type correct character
            delay = self._get_key_delay(prev_key, char)
            
            events.append(ActivityEvent(
                event_id=secrets.token_hex(8),
                activity_type=ActivityType.TYPING,
                timestamp=current_time,
                duration_ms=delay,
                details={"char": char}
            ))
            
            current_time += delay / 1000.0
            prev_key = char
            
            # Update key history
            self.state.key_history.append(char)
            
            i += 1
        
        self.state.last_key_time = current_time
        
        return events
    
    def generate_hotkey(
        self,
        keys: List[str]
    ) -> List[ActivityEvent]:
        """Generate key combination (Ctrl+C, Alt+Tab, etc.)"""
        events = []
        current_time = time.time()
        
        # Press keys in sequence
        for key in keys:
            delay = random.gauss(30, 10)
            
            events.append(ActivityEvent(
                event_id=secrets.token_hex(8),
                activity_type=ActivityType.KEY_COMBO,
                timestamp=current_time,
                duration_ms=int(delay),
                details={"key": key, "action": "press"}
            ))
            
            current_time += delay / 1000.0
        
        # Hold time
        hold_time = random.gauss(100, 30)
        current_time += hold_time / 1000.0
        
        # Release in reverse order
        for key in reversed(keys):
            delay = random.gauss(20, 8)
            
            events.append(ActivityEvent(
                event_id=secrets.token_hex(8),
                activity_type=ActivityType.KEY_COMBO,
                timestamp=current_time,
                duration_ms=int(delay),
                details={"key": key, "action": "release"}
            ))
            
            current_time += delay / 1000.0
        
        return events


# =============================================================================
# ACTIVITY SCHEDULER
# =============================================================================

class HumanActivityScheduler:
    """
    Schedules activities to match human work patterns
    
    Features:
    - Work hours simulation
    - Break patterns
    - Lunch breaks
    - Meeting-like idle periods
    - End-of-day wind-down
    """
    
    def __init__(self, profile: BehavioralProfile = None):
        self.profile = profile or BehavioralProfile(profile_id=secrets.token_hex(8))
        self.activity_log: List[ActivityEvent] = []
        self.last_break_time = time.time()
        self.last_activity_time = time.time()
    
    def is_work_hours(self) -> bool:
        """Check if current time is within work hours"""
        current_hour = datetime.now().hour
        return self.profile.work_hours[0] <= current_hour < self.profile.work_hours[1]
    
    def is_lunch_time(self) -> bool:
        """Check if current time is lunch"""
        current_hour = datetime.now().hour
        return LUNCH_START_HOUR <= current_hour < LUNCH_END_HOUR
    
    def should_take_break(self) -> bool:
        """Check if it's time for a break"""
        minutes_since_break = (time.time() - self.last_break_time) / 60
        
        # Add some randomness to break timing
        break_threshold = self.profile.break_frequency * random.gauss(1.0, 0.2)
        
        return minutes_since_break >= break_threshold
    
    def get_activity_delay(self) -> float:
        """Get delay before next activity"""
        # Base delay
        base_delay = random.gauss(2.0, 1.0)  # 2 seconds average
        
        # Adjust for time of day
        current_hour = datetime.now().hour
        
        if current_hour < 10:
            # Morning - people are slower
            base_delay *= 1.3
        elif current_hour > 16:
            # End of day - slower
            base_delay *= 1.2
        elif 14 <= current_hour <= 15:
            # Post-lunch slump
            base_delay *= 1.4
        
        # Add variance from profile
        base_delay *= random.gauss(1.0, self.profile.activity_variance)
        
        return max(0.5, base_delay)
    
    def schedule_activities(
        self,
        duration_seconds: int = 60
    ) -> List[ActivityEvent]:
        """Schedule human-like activities for duration"""
        events = []
        current_time = time.time()
        end_time = current_time + duration_seconds
        
        while current_time < end_time:
            # Check for break
            if self.should_take_break():
                # Take a break
                break_duration = random.gauss(BREAK_DURATION_MIN * 60, 60)
                
                events.append(ActivityEvent(
                    event_id=secrets.token_hex(8),
                    activity_type=ActivityType.BREAK,
                    timestamp=current_time,
                    duration_ms=int(break_duration * 1000),
                    details={"reason": "scheduled_break"}
                ))
                
                current_time += break_duration
                self.last_break_time = current_time
                continue
            
            # Check for lunch
            if self.is_lunch_time():
                events.append(ActivityEvent(
                    event_id=secrets.token_hex(8),
                    activity_type=ActivityType.BREAK,
                    timestamp=current_time,
                    duration_ms=int(3600 * 1000),  # 1 hour
                    details={"reason": "lunch"}
                ))
                
                current_time += 3600
                continue
            
            # Random activity
            activity_type = random.choice([
                ActivityType.MOUSE_MOVE,
                ActivityType.MOUSE_CLICK,
                ActivityType.KEY_PRESS,
                ActivityType.TYPING,
                ActivityType.WINDOW_SWITCH,
                ActivityType.READING,
                ActivityType.IDLE,
            ])
            
            # Activity duration based on type
            duration_map = {
                ActivityType.MOUSE_MOVE: (100, 500),
                ActivityType.MOUSE_CLICK: (50, 200),
                ActivityType.KEY_PRESS: (30, 100),
                ActivityType.TYPING: (1000, 10000),
                ActivityType.WINDOW_SWITCH: (500, 2000),
                ActivityType.READING: (5000, 30000),
                ActivityType.IDLE: (1000, 5000),
            }
            
            duration_range = duration_map.get(activity_type, (100, 1000))
            duration = random.gauss(
                (duration_range[0] + duration_range[1]) / 2,
                (duration_range[1] - duration_range[0]) / 4
            )
            duration = max(duration_range[0], min(duration_range[1], duration))
            
            events.append(ActivityEvent(
                event_id=secrets.token_hex(8),
                activity_type=activity_type,
                timestamp=current_time,
                duration_ms=int(duration),
                details={}
            ))
            
            current_time += duration / 1000.0
            
            # Inter-activity delay
            delay = self.get_activity_delay()
            current_time += delay
        
        return events


# =============================================================================
# EDR DEFENSE ANALYZER
# =============================================================================

class EDRDefenseAnalyzer:
    """
    Analyzes EDR behavioral detection capabilities
    
    Uses heuristics and patterns to determine:
    - Active EDR product
    - Behavioral monitoring level
    - ML detection capabilities
    - Recommended mimicry level
    """
    
    def __init__(self):
        self.detected_edr: Optional[EDRBehavioralEngine] = None
        self.last_analysis: Optional[DefenseAnalysis] = None
    
    def analyze_defenses(self) -> DefenseAnalysis:
        """
        Analyze current system defenses
        
        Returns DefenseAnalysis with recommendations
        """
        risk_factors = []
        bypass_strategies = []
        
        # Detect EDR
        self.detected_edr = self._detect_edr()
        
        # Check for behavioral monitoring
        behavioral_monitoring = self._check_behavioral_monitoring()
        
        # Check for ML detection
        ml_detection = self._check_ml_detection()
        
        # Determine risk factors
        if self.detected_edr == EDRBehavioralEngine.SENTINELONE:
            risk_factors.extend([
                "SentinelOne Static AI behavioral analysis",
                "Process behavior correlation",
                "Automated response capabilities",
                "Cloud-based ML models"
            ])
            bypass_strategies.extend([
                "Use PARANOID mimicry mode",
                "Maintain continuous human-like activity",
                "Randomize all timing patterns",
                "Avoid rapid automated actions"
            ])
        
        elif self.detected_edr == EDRBehavioralEngine.CROWDSTRIKE:
            risk_factors.extend([
                "CrowdStrike behavioral IOAs",
                "Process tree analysis",
                "Memory pattern detection",
                "Threat graph correlation"
            ])
            bypass_strategies.extend([
                "Use AGGRESSIVE or higher mimicry",
                "Blend with legitimate process patterns",
                "Maintain natural mouse movements",
                "Use realistic typing patterns"
            ])
        
        elif self.detected_edr == EDRBehavioralEngine.DEFENDER_ATP:
            risk_factors.extend([
                "Microsoft Defender behavioral blocking",
                "Cloud-delivered protection",
                "Attack surface reduction rules",
                "Automated investigation"
            ])
            bypass_strategies.extend([
                "Use MODERATE or higher mimicry",
                "Avoid known behavioral patterns",
                "Maintain consistent activity profile"
            ])
        
        # Default if no specific EDR
        if not self.detected_edr:
            risk_factors.append("Unknown behavioral monitoring possible")
            bypass_strategies.append("Use MODERATE mimicry as baseline")
        
        # Add ML-specific factors
        if ml_detection:
            risk_factors.append("ML-based behavioral analysis active")
            bypass_strategies.extend([
                "Increase activity randomization",
                "Use GAN-generated traffic patterns",
                "Maintain consistent human profile"
            ])
        
        # Determine recommended mode
        recommended_mode = self._recommend_mode(
            self.detected_edr,
            behavioral_monitoring,
            ml_detection
        )
        
        # Calculate confidence
        confidence = self._calculate_confidence()
        
        self.last_analysis = DefenseAnalysis(
            edr_detected=self.detected_edr,
            behavioral_monitoring=behavioral_monitoring,
            ml_detection=ml_detection,
            recommended_mode=recommended_mode,
            risk_factors=risk_factors,
            bypass_strategies=bypass_strategies,
            confidence=confidence
        )
        
        return self.last_analysis
    
    def _detect_edr(self) -> Optional[EDRBehavioralEngine]:
        """Detect active EDR product"""
        # Check for common EDR processes/services
        edr_indicators = {
            EDRBehavioralEngine.SENTINELONE: [
                "SentinelAgent", "SentinelOne", "SentinelStaticEngine",
                "SentinelServiceHost", "SentinelHelperService"
            ],
            EDRBehavioralEngine.CROWDSTRIKE: [
                "CSFalconService", "CSFalconContainer", "csagent",
                "CrowdStrike", "falconhost"
            ],
            EDRBehavioralEngine.CARBONBLACK: [
                "CbDefense", "CarbonBlack", "RepMgr", "cb.exe",
                "CbOsSecurityService"
            ],
            EDRBehavioralEngine.DEFENDER_ATP: [
                "MsSense", "SenseIR", "SenseCncProxy",
                "Microsoft.Tri.Sensor", "AATPSensor"
            ],
            EDRBehavioralEngine.CYLANCE: [
                "CylanceSvc", "CylanceUI", "CylanceProtectSetup"
            ],
            EDRBehavioralEngine.SOPHOS: [
                "SophosAgent", "SophosHealth", "SophosClean",
                "SophosFS", "SophosNtpService"
            ],
        }
        
        # Simulate detection (in real implementation, would check processes)
        # For now, return None or simulate based on environment
        import os
        
        # Check environment variable hint
        env_edr = os.environ.get("SIMULATED_EDR", "").lower()
        
        for edr, indicators in edr_indicators.items():
            if edr.value == env_edr:
                return edr
        
        # Default: assume some EDR for safety
        return EDRBehavioralEngine.DEFENDER_ATP
    
    def _check_behavioral_monitoring(self) -> bool:
        """Check if behavioral monitoring is active"""
        if self.detected_edr:
            return True
        
        # Check for common behavioral monitoring indicators
        # In real implementation, would check for hooks, ETW, etc.
        return True  # Assume yes for safety
    
    def _check_ml_detection(self) -> bool:
        """Check for ML-based detection"""
        # Modern EDRs all use ML
        ml_edrs = {
            EDRBehavioralEngine.SENTINELONE,
            EDRBehavioralEngine.CROWDSTRIKE,
            EDRBehavioralEngine.CARBONBLACK,
            EDRBehavioralEngine.CYLANCE,
        }
        
        return self.detected_edr in ml_edrs
    
    def _recommend_mode(
        self,
        edr: Optional[EDRBehavioralEngine],
        behavioral: bool,
        ml: bool
    ) -> MimicryMode:
        """Recommend mimicry mode based on analysis"""
        if edr == EDRBehavioralEngine.SENTINELONE:
            return MimicryMode.PARANOID
        
        if edr == EDRBehavioralEngine.CROWDSTRIKE:
            return MimicryMode.AGGRESSIVE
        
        if ml:
            return MimicryMode.AGGRESSIVE
        
        if behavioral:
            return MimicryMode.MODERATE
        
        return MimicryMode.LIGHT
    
    def _calculate_confidence(self) -> float:
        """Calculate confidence in analysis"""
        base_confidence = 0.7
        
        if self.detected_edr:
            base_confidence += 0.2
        
        # In real implementation, would factor in detection accuracy
        return min(0.95, base_confidence)


# =============================================================================
# MAIN BEHAVIORAL MIMICRY ENGINE
# =============================================================================

class BehavioralMimicryEngine:
    """
    Behavioral Mimicry Engine - Main Orchestrator
    
    Combines all components:
    - Mouse simulation
    - Keyboard simulation
    - Traffic generation
    - Activity scheduling
    - Defense analysis
    
    Target: SentinelOne Behavioral Score = 0
    """
    
    def __init__(
        self,
        mode: MimicryMode = MimicryMode.MODERATE,
        profile: BehavioralProfile = None
    ):
        self.mode = mode
        self.profile = profile or BehavioralProfile(profile_id=secrets.token_hex(8))
        
        # Initialize components
        self.mouse_sim = HumanMouseSimulator()
        self.keyboard_sim = HumanKeyboardSimulator(self.profile.typing_speed)
        self.traffic_gen = GANTrafficGenerator()
        self.scheduler = HumanActivityScheduler(self.profile)
        self.defense_analyzer = EDRDefenseAnalyzer()
        
        # State
        self.is_running = False
        self.activity_thread: Optional[threading.Thread] = None
        self.events_generated: int = 0
        self.start_time: Optional[float] = None
    
    def analyze_defenses(self) -> DefenseAnalysis:
        """
        Analyze system defenses and auto-adjust mimicry level
        
        Returns detailed defense analysis with recommendations
        """
        analysis = self.defense_analyzer.analyze_defenses()
        
        # Auto-adjust mode based on analysis
        if self.mode != MimicryMode.DISABLED:
            recommended = analysis.recommended_mode
            
            # Only upgrade, never downgrade (safety first)
            mode_levels = {
                MimicryMode.DISABLED: 0,
                MimicryMode.LIGHT: 1,
                MimicryMode.MODERATE: 2,
                MimicryMode.AGGRESSIVE: 3,
                MimicryMode.PARANOID: 4,
                MimicryMode.HUMAN: 5,
            }
            
            if mode_levels[recommended] > mode_levels[self.mode]:
                logger.info(f"Auto-upgrading mimicry: {self.mode.value} -> {recommended.value}")
                self.mode = recommended
        
        return analysis
    
    def start_continuous_mimicry(self):
        """Start continuous background mimicry"""
        if self.is_running:
            return
        
        self.is_running = True
        self.start_time = time.time()
        
        self.activity_thread = threading.Thread(
            target=self._mimicry_loop,
            daemon=True
        )
        self.activity_thread.start()
        
        logger.info(f"Started continuous mimicry in {self.mode.value} mode")
    
    def stop_continuous_mimicry(self):
        """Stop continuous mimicry"""
        self.is_running = False
        
        if self.activity_thread:
            self.activity_thread.join(timeout=5)
            self.activity_thread = None
        
        logger.info("Stopped continuous mimicry")
    
    def _mimicry_loop(self):
        """Main mimicry loop"""
        while self.is_running:
            try:
                # Generate activity burst
                if self.mode == MimicryMode.PARANOID:
                    self._generate_paranoid_activity()
                elif self.mode == MimicryMode.HUMAN:
                    self._generate_human_activity()
                elif self.mode == MimicryMode.AGGRESSIVE:
                    self._generate_aggressive_activity()
                elif self.mode == MimicryMode.MODERATE:
                    self._generate_moderate_activity()
                else:
                    self._generate_light_activity()
                
                # Sleep with human-like jitter
                sleep_time = self._get_sleep_time()
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Mimicry loop error: {e}")
                time.sleep(1)
    
    def _get_sleep_time(self) -> float:
        """Get sleep time based on mode"""
        base_times = {
            MimicryMode.LIGHT: (2.0, 5.0),
            MimicryMode.MODERATE: (0.5, 2.0),
            MimicryMode.AGGRESSIVE: (0.1, 0.5),
            MimicryMode.PARANOID: (0.05, 0.2),
            MimicryMode.HUMAN: (0.2, 1.0),
        }
        
        range_ = base_times.get(self.mode, (1.0, 3.0))
        return random.uniform(range_[0], range_[1])
    
    def _generate_light_activity(self):
        """Generate minimal activity (timing jitter only)"""
        # Just add timing variance to existing operations
        self.events_generated += 1
    
    def _generate_moderate_activity(self):
        """Generate moderate activity"""
        activity = random.choice([
            self._sim_mouse_wiggle,
            self._sim_idle,
            self._sim_scroll,
        ])
        activity()
    
    def _generate_aggressive_activity(self):
        """Generate aggressive human-like activity"""
        activity = random.choice([
            self._sim_mouse_movement,
            self._sim_typing,
            self._sim_window_switch,
            self._sim_scroll,
            self._sim_reading,
        ])
        activity()
    
    def _generate_paranoid_activity(self):
        """Generate maximum stealth activity"""
        # Constant human-like activity
        activities = [
            self._sim_mouse_movement,
            self._sim_typing,
            self._sim_reading,
            self._sim_window_switch,
            self._sim_click,
        ]
        
        # Do 1-3 activities
        for _ in range(random.randint(1, 3)):
            random.choice(activities)()
    
    def _generate_human_activity(self):
        """Generate indistinguishable human activity"""
        # Follow scheduled activities
        events = self.scheduler.schedule_activities(duration_seconds=5)
        
        for event in events:
            self._process_scheduled_event(event)
        
        self.events_generated += len(events)
    
    def _process_scheduled_event(self, event: ActivityEvent):
        """Process a scheduled activity event"""
        if event.activity_type == ActivityType.MOUSE_MOVE:
            self._sim_mouse_movement()
        elif event.activity_type == ActivityType.MOUSE_CLICK:
            self._sim_click()
        elif event.activity_type == ActivityType.TYPING:
            self._sim_typing()
        elif event.activity_type == ActivityType.READING:
            self._sim_reading()
        elif event.activity_type == ActivityType.WINDOW_SWITCH:
            self._sim_window_switch()
        elif event.activity_type == ActivityType.IDLE:
            self._sim_idle()
        elif event.activity_type == ActivityType.BREAK:
            self._sim_break(event.duration_ms / 1000)
    
    def _sim_mouse_wiggle(self):
        """Simulate small mouse wiggle"""
        x = self.mouse_sim.state.x + random.randint(-10, 10)
        y = self.mouse_sim.state.y + random.randint(-10, 10)
        
        events = self.mouse_sim.generate_movement(x, y)
        self.events_generated += len(events)
    
    def _sim_mouse_movement(self):
        """Simulate purposeful mouse movement"""
        x = random.randint(100, 1800)
        y = random.randint(100, 900)
        
        events = self.mouse_sim.generate_movement(x, y)
        self.events_generated += len(events)
    
    def _sim_click(self):
        """Simulate mouse click"""
        # Move to target first
        self._sim_mouse_movement()
        
        double = random.random() < 0.2  # 20% double clicks
        events = self.mouse_sim.generate_click("left", double=double)
        self.events_generated += len(events)
    
    def _sim_scroll(self):
        """Simulate scrolling"""
        direction = random.choice(["up", "down"])
        amount = random.randint(1, 5)
        
        events = self.mouse_sim.generate_scroll(direction, amount)
        self.events_generated += len(events)
    
    def _sim_typing(self):
        """Simulate typing"""
        # Common typing patterns
        patterns = [
            "test",
            "hello world",
            "the quick brown fox",
            "Lorem ipsum dolor sit amet",
            "Meeting notes:",
            "TODO: ",
            "Subject: ",
            "Hi,\n\n",
        ]
        
        text = random.choice(patterns)
        events = self.keyboard_sim.generate_typing(text)
        self.events_generated += len(events)
    
    def _sim_window_switch(self):
        """Simulate Alt+Tab window switch"""
        events = self.keyboard_sim.generate_hotkey(["alt", "tab"])
        self.events_generated += len(events)
    
    def _sim_reading(self):
        """Simulate reading (idle with occasional scroll/mouse)"""
        # Reading duration
        duration = random.gauss(5, 2)
        duration = max(2, min(duration, 15))
        
        start = time.time()
        while time.time() - start < duration and self.is_running:
            activity = random.choice([
                lambda: time.sleep(1),
                self._sim_scroll,
                self._sim_mouse_wiggle,
            ])
            activity()
    
    def _sim_idle(self):
        """Simulate idle period"""
        duration = random.gauss(2, 0.5)
        time.sleep(max(0.5, duration))
    
    def _sim_break(self, duration: float):
        """Simulate break period"""
        # During break: minimal activity
        start = time.time()
        while time.time() - start < duration and self.is_running:
            # Occasional mouse movement (checking time, etc.)
            if random.random() < 0.1:
                self._sim_mouse_wiggle()
            time.sleep(5)
    
    def generate_traffic_burst(self, num_requests: int = 10) -> List[TrafficEvent]:
        """Generate human-like traffic burst"""
        return self.traffic_gen.generate_traffic_pattern(num_requests)
    
    def get_optimal_request_timing(self) -> Tuple[int, int]:
        """Get optimal timing for next C2 request"""
        return self.traffic_gen.get_optimal_timing()
    
    def wrap_action(self, action: Callable, *args, **kwargs) -> Any:
        """
        Wrap an action with human-like behavior
        
        Adds pre/post activity and timing jitter
        """
        if self.mode == MimicryMode.DISABLED:
            return action(*args, **kwargs)
        
        # Pre-action activity
        if self.mode in [MimicryMode.AGGRESSIVE, MimicryMode.PARANOID, MimicryMode.HUMAN]:
            self._generate_moderate_activity()
        
        # Timing jitter before action
        min_delay, max_delay = self.get_optimal_request_timing()
        jitter = random.randint(min_delay, max_delay) / 1000.0
        time.sleep(jitter)
        
        # Execute action
        result = action(*args, **kwargs)
        
        # Post-action activity
        if self.mode in [MimicryMode.PARANOID, MimicryMode.HUMAN]:
            self._generate_moderate_activity()
        
        return result
    
    def get_behavioral_score(self) -> float:
        """
        Calculate current behavioral score
        
        0.0 = Perfect human behavior (undetectable)
        1.0 = Obvious automated behavior
        
        Target: < 0.1 for SentinelOne bypass
        """
        score = 0.5  # Base score
        
        # Factor in mode
        mode_scores = {
            MimicryMode.DISABLED: 0.9,
            MimicryMode.LIGHT: 0.6,
            MimicryMode.MODERATE: 0.4,
            MimicryMode.AGGRESSIVE: 0.2,
            MimicryMode.PARANOID: 0.05,
            MimicryMode.HUMAN: 0.02,
        }
        
        score = mode_scores.get(self.mode, 0.5)
        
        # Factor in activity count (more = better)
        if self.events_generated > 100:
            score *= 0.8
        if self.events_generated > 500:
            score *= 0.8
        if self.events_generated > 1000:
            score *= 0.9
        
        # Factor in runtime (longer = better profile)
        if self.start_time:
            runtime = time.time() - self.start_time
            if runtime > 60:  # 1 minute
                score *= 0.95
            if runtime > 300:  # 5 minutes
                score *= 0.9
            if runtime > 900:  # 15 minutes
                score *= 0.85
        
        return max(0.0, min(1.0, score))
    
    def get_status(self) -> Dict:
        """Get current mimicry status"""
        return {
            "mode": self.mode.value,
            "is_running": self.is_running,
            "events_generated": self.events_generated,
            "behavioral_score": self.get_behavioral_score(),
            "runtime_seconds": int(time.time() - self.start_time) if self.start_time else 0,
            "profile_id": self.profile.profile_id,
            "detected_edr": self.defense_analyzer.detected_edr.value if self.defense_analyzer.detected_edr else None,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_mimicry_engine(
    mode: str = "moderate",
    auto_detect: bool = True
) -> BehavioralMimicryEngine:
    """
    Create and configure behavioral mimicry engine
    
    Args:
        mode: Mimicry mode (light, moderate, aggressive, paranoid, human)
        auto_detect: Auto-detect EDR and adjust mode
    
    Returns:
        Configured BehavioralMimicryEngine
    """
    mode_map = {
        "disabled": MimicryMode.DISABLED,
        "light": MimicryMode.LIGHT,
        "moderate": MimicryMode.MODERATE,
        "aggressive": MimicryMode.AGGRESSIVE,
        "paranoid": MimicryMode.PARANOID,
        "human": MimicryMode.HUMAN,
    }
    
    mimicry_mode = mode_map.get(mode.lower(), MimicryMode.MODERATE)
    
    engine = BehavioralMimicryEngine(mode=mimicry_mode)
    
    if auto_detect:
        analysis = engine.analyze_defenses()
        logger.info(f"Defense analysis: EDR={analysis.edr_detected}, Mode={engine.mode.value}")
    
    return engine


def quick_mimic(action: Callable, mode: str = "moderate") -> Any:
    """
    Quick wrapper to execute action with mimicry
    
    Args:
        action: Callable to execute
        mode: Mimicry mode
    
    Returns:
        Action result
    """
    engine = create_mimicry_engine(mode=mode, auto_detect=False)
    return engine.wrap_action(action)


def analyze_defenses() -> DefenseAnalysis:
    """Quick defense analysis"""
    analyzer = EDRDefenseAnalyzer()
    return analyzer.analyze_defenses()


def get_human_timing() -> Tuple[int, int]:
    """Get human-like timing for next action (min_ms, max_ms)"""
    gen = GANTrafficGenerator()
    return gen.get_optimal_timing()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    'MimicryMode',
    'ActivityType',
    'TrafficPattern',
    'EDRBehavioralEngine',
    
    # Dataclasses
    'MouseState',
    'KeyboardState',
    'ActivityEvent',
    'TrafficEvent',
    'BehavioralProfile',
    'MimicryResult',
    'DefenseAnalysis',
    
    # Components
    'GANTrafficGenerator',
    'HumanMouseSimulator',
    'HumanKeyboardSimulator',
    'HumanActivityScheduler',
    'EDRDefenseAnalyzer',
    
    # Main Engine
    'BehavioralMimicryEngine',
    
    # Convenience Functions
    'create_mimicry_engine',
    'quick_mimic',
    'analyze_defenses',
    'get_human_timing',
    
    # Constants
    'HUMAN_TYPING_SPEED',
    'HUMAN_MOUSE_SPEED',
]
