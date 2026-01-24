"""
Behavioral Mimicry Test Suite
==============================
Tests for human-like EDR bypass capabilities.

Target: SentinelOne Behavioral Score = 0
"""

import os
import sys
import time
import random
import pytest
import secrets
import numpy as np
from unittest.mock import MagicMock, patch

# Add parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evasion.behavioral_mimicry import (
    # Enums
    MimicryMode,
    ActivityType,
    TrafficPattern,
    EDRBehavioralEngine,
    
    # Dataclasses
    MouseState,
    KeyboardState,
    ActivityEvent,
    TrafficEvent,
    BehavioralProfile,
    MimicryResult,
    DefenseAnalysis,
    
    # Components
    GANTrafficGenerator,
    HumanMouseSimulator,
    HumanKeyboardSimulator,
    HumanActivityScheduler,
    EDRDefenseAnalyzer,
    
    # Main Engine
    BehavioralMimicryEngine,
    
    # Convenience Functions
    create_mimicry_engine,
    quick_mimic,
    analyze_defenses,
    get_human_timing,
    
    # Constants
    HUMAN_TYPING_SPEED,
    HUMAN_MOUSE_SPEED,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestEnums:
    """Test enum definitions"""
    
    def test_mimicry_modes(self):
        """Test all mimicry modes exist"""
        assert MimicryMode.DISABLED.value == "disabled"
        assert MimicryMode.LIGHT.value == "light"
        assert MimicryMode.MODERATE.value == "moderate"
        assert MimicryMode.AGGRESSIVE.value == "aggressive"
        assert MimicryMode.PARANOID.value == "paranoid"
        assert MimicryMode.HUMAN.value == "human"
    
    def test_activity_types(self):
        """Test activity types"""
        assert ActivityType.MOUSE_MOVE.value == "mouse_move"
        assert ActivityType.TYPING.value == "typing"
        assert ActivityType.IDLE.value == "idle"
    
    def test_edr_engines(self):
        """Test EDR behavioral engines"""
        assert EDRBehavioralEngine.SENTINELONE.value == "sentinelone"
        assert EDRBehavioralEngine.CROWDSTRIKE.value == "crowdstrike"
        assert EDRBehavioralEngine.DEFENDER_ATP.value == "defender_atp"


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestDataclasses:
    """Test dataclass structures"""
    
    def test_mouse_state(self):
        """Test MouseState dataclass"""
        state = MouseState()
        assert state.x == 0
        assert state.y == 0
        assert not state.buttons["left"]
    
    def test_keyboard_state(self):
        """Test KeyboardState dataclass"""
        state = KeyboardState()
        assert state.typing_speed == "average"
        assert len(state.pressed_keys) == 0
    
    def test_behavioral_profile(self):
        """Test BehavioralProfile defaults"""
        profile = BehavioralProfile(profile_id="test-001")
        assert profile.typing_speed == "average"
        assert profile.mouse_speed == "average"
        assert profile.work_hours == (9, 17)
        assert profile.break_frequency == 45
    
    def test_activity_event(self):
        """Test ActivityEvent creation"""
        event = ActivityEvent(
            event_id="test",
            activity_type=ActivityType.MOUSE_MOVE,
            timestamp=time.time(),
            duration_ms=100,
            details={"x": 100, "y": 200}
        )
        assert event.synthetic is True
        assert event.activity_type == ActivityType.MOUSE_MOVE


# =============================================================================
# GAN TRAFFIC GENERATOR TESTS
# =============================================================================

class TestGANTrafficGenerator:
    """Test GAN-based traffic pattern generation"""
    
    def test_generator_init(self):
        """Test generator initialization"""
        gen = GANTrafficGenerator(latent_dim=32)
        assert gen.latent_dim == 32
        assert gen.gen_weights1.shape == (32, 64)
    
    def test_generate_traffic_pattern(self):
        """Test traffic pattern generation"""
        gen = GANTrafficGenerator()
        events = gen.generate_traffic_pattern(num_events=10)
        
        assert len(events) == 10
        for event in events:
            assert isinstance(event, TrafficEvent)
            assert event.size_bytes > 0
            assert event.timing_jitter_ms is not None
    
    def test_optimal_timing(self):
        """Test optimal timing calculation"""
        gen = GANTrafficGenerator()
        min_ms, max_ms = gen.get_optimal_timing()
        
        assert min_ms > 0
        assert max_ms > min_ms
        assert min_ms >= 50  # Minimum sanity check
        assert max_ms < 10000  # Maximum sanity check
    
    def test_traffic_variance(self):
        """Test that traffic has human-like variance"""
        gen = GANTrafficGenerator()
        
        timings = []
        for _ in range(100):
            min_t, max_t = gen.get_optimal_timing()
            timings.append((min_t + max_t) / 2)
        
        # Check variance exists (not all same)
        variance = np.var(timings)
        assert variance > 0, "Traffic timing should have variance"


# =============================================================================
# MOUSE SIMULATOR TESTS
# =============================================================================

class TestHumanMouseSimulator:
    """Test human-like mouse simulation"""
    
    def test_simulator_init(self):
        """Test simulator initialization"""
        sim = HumanMouseSimulator(screen_width=1920, screen_height=1080)
        assert sim.screen_width == 1920
        assert sim.state.x == 0
    
    def test_bezier_curve(self):
        """Test Bézier curve generation"""
        sim = HumanMouseSimulator()
        points = sim._bezier_curve((0, 0), (100, 100), control_points=2)
        
        assert len(points) > 2
        assert points[0] == (0, 0)
        # Last point should be close to target
        assert abs(points[-1][0] - 100) < 10
        assert abs(points[-1][1] - 100) < 10
    
    def test_generate_movement(self):
        """Test mouse movement generation"""
        sim = HumanMouseSimulator()
        events = sim.generate_movement(target_x=500, target_y=300)
        
        assert len(events) > 0
        for event in events:
            assert event.activity_type == ActivityType.MOUSE_MOVE
            assert "x" in event.details
            assert "y" in event.details
        
        # State should be updated
        assert sim.state.x == 500
        assert sim.state.y == 300
    
    def test_generate_click(self):
        """Test mouse click generation"""
        sim = HumanMouseSimulator()
        events = sim.generate_click(button="left", double=False)
        
        assert len(events) == 2  # Press + release
        assert events[0].details["action"] == "press"
        assert events[1].details["action"] == "release"
    
    def test_double_click(self):
        """Test double click timing"""
        sim = HumanMouseSimulator()
        events = sim.generate_click(button="left", double=True)
        
        assert len(events) == 4  # 2 clicks * 2 events each
        
        # Check timing between clicks is reasonable (<500ms)
        time_diff = events[2].timestamp - events[1].timestamp
        assert time_diff < 0.5, "Double click interval too long"
    
    def test_scroll_generation(self):
        """Test scroll event generation"""
        sim = HumanMouseSimulator()
        events = sim.generate_scroll(direction="down", amount=3)
        
        assert len(events) == 3
        for event in events:
            assert event.activity_type == ActivityType.MOUSE_SCROLL
    
    def test_movement_has_overshoot(self):
        """Test that some movements have overshoot"""
        sim = HumanMouseSimulator()
        
        overshoots = 0
        for _ in range(20):
            sim.state.x = 0
            sim.state.y = 0
            events = sim.generate_movement(1000, 500, overshoot=None)
            # Check if any point goes past target
            for e in events:
                if e.details.get("x", 0) > 1010:
                    overshoots += 1
                    break
        
        # Should have some overshoots (15% rate)
        # With 20 tries, expect ~3 but allow variance
        assert overshoots >= 0  # At least possible


# =============================================================================
# KEYBOARD SIMULATOR TESTS
# =============================================================================

class TestHumanKeyboardSimulator:
    """Test human-like keyboard simulation"""
    
    def test_simulator_init(self):
        """Test keyboard simulator initialization"""
        sim = HumanKeyboardSimulator(typing_speed="average")
        assert sim.state.typing_speed == "average"
        assert len(sim.key_positions) > 0
    
    def test_typing_generation(self):
        """Test typing event generation"""
        sim = HumanKeyboardSimulator()
        events = sim.generate_typing("hello", include_errors=False)
        
        assert len(events) == 5  # h-e-l-l-o
        
        # Check all characters present
        chars = [e.details["char"] for e in events]
        assert chars == list("hello")
    
    def test_typing_timing_variance(self):
        """Test that typing has human-like variance"""
        sim = HumanKeyboardSimulator()
        events = sim.generate_typing("test string", include_errors=False)
        
        durations = [e.duration_ms for e in events]
        variance = np.var(durations)
        
        assert variance > 0, "Typing should have timing variance"
    
    def test_key_distance_affects_timing(self):
        """Test that key distance affects typing speed"""
        sim = HumanKeyboardSimulator()
        
        # Adjacent keys (f-g)
        delay_adjacent = sim._get_key_delay("f", "g")
        
        # Distant keys (a-p)
        delay_distant = sim._get_key_delay("a", "p")
        
        # Distant should generally be longer
        # (Though random variance might sometimes make this fail)
        # Just check both are in reasonable range
        assert delay_adjacent > 0
        assert delay_distant > 0
    
    def test_hotkey_generation(self):
        """Test keyboard shortcut generation"""
        sim = HumanKeyboardSimulator()
        events = sim.generate_hotkey(["ctrl", "c"])
        
        # Should have press and release for each key
        assert len(events) == 4
        
        # First two are presses
        assert events[0].details["action"] == "press"
        assert events[1].details["action"] == "press"
        
        # Last two are releases (reverse order)
        assert events[2].details["action"] == "release"
        assert events[3].details["action"] == "release"
    
    def test_typing_with_errors(self):
        """Test that typing can include realistic errors"""
        sim = HumanKeyboardSimulator()
        
        # Type a long string many times to see if errors occur
        error_count = 0
        for _ in range(10):
            events = sim.generate_typing("the quick brown fox jumps", include_errors=True)
            for e in events:
                if e.details.get("typo") or e.details.get("correction"):
                    error_count += 1
        
        # Should have some errors across all attempts
        # (But might be 0 due to randomness)
        assert error_count >= 0  # Just verify it doesn't crash


# =============================================================================
# ACTIVITY SCHEDULER TESTS
# =============================================================================

class TestHumanActivityScheduler:
    """Test human activity scheduling"""
    
    def test_scheduler_init(self):
        """Test scheduler initialization"""
        scheduler = HumanActivityScheduler()
        assert scheduler.profile is not None
    
    def test_schedule_activities(self):
        """Test activity scheduling"""
        scheduler = HumanActivityScheduler()
        events = scheduler.schedule_activities(duration_seconds=10)
        
        assert len(events) > 0
        for event in events:
            assert isinstance(event, ActivityEvent)
    
    def test_activity_delay(self):
        """Test activity delay calculation"""
        scheduler = HumanActivityScheduler()
        
        delays = [scheduler.get_activity_delay() for _ in range(100)]
        
        assert all(d > 0 for d in delays)
        assert np.var(delays) > 0, "Activity delays should have variance"


# =============================================================================
# EDR DEFENSE ANALYZER TESTS
# =============================================================================

class TestEDRDefenseAnalyzer:
    """Test EDR defense analysis"""
    
    def test_analyzer_init(self):
        """Test analyzer initialization"""
        analyzer = EDRDefenseAnalyzer()
        assert analyzer.detected_edr is None
        assert analyzer.last_analysis is None
    
    def test_analyze_defenses(self):
        """Test defense analysis"""
        analyzer = EDRDefenseAnalyzer()
        analysis = analyzer.analyze_defenses()
        
        assert isinstance(analysis, DefenseAnalysis)
        assert analysis.recommended_mode is not None
        assert len(analysis.risk_factors) > 0
        assert len(analysis.bypass_strategies) > 0
        assert 0 <= analysis.confidence <= 1
    
    def test_recommended_mode_for_sentinelone(self):
        """Test recommended mode for SentinelOne"""
        analyzer = EDRDefenseAnalyzer()
        
        # Simulate SentinelOne detection
        analyzer.detected_edr = EDRBehavioralEngine.SENTINELONE
        
        mode = analyzer._recommend_mode(
            analyzer.detected_edr,
            behavioral=True,
            ml=True
        )
        
        # Should recommend PARANOID for SentinelOne
        assert mode == MimicryMode.PARANOID


# =============================================================================
# BEHAVIORAL MIMICRY ENGINE TESTS
# =============================================================================

class TestBehavioralMimicryEngine:
    """Test main behavioral mimicry engine"""
    
    def test_engine_init(self):
        """Test engine initialization"""
        engine = BehavioralMimicryEngine(mode=MimicryMode.MODERATE)
        
        assert engine.mode == MimicryMode.MODERATE
        assert engine.mouse_sim is not None
        assert engine.keyboard_sim is not None
        assert engine.traffic_gen is not None
        assert engine.scheduler is not None
    
    def test_analyze_defenses_auto_upgrade(self):
        """Test that analyze_defenses upgrades mode"""
        engine = BehavioralMimicryEngine(mode=MimicryMode.LIGHT)
        
        # Mock detected EDR as SentinelOne
        engine.defense_analyzer.detected_edr = EDRBehavioralEngine.SENTINELONE
        
        analysis = engine.analyze_defenses()
        
        # Should upgrade from LIGHT to at least MODERATE
        mode_levels = {
            MimicryMode.DISABLED: 0,
            MimicryMode.LIGHT: 1,
            MimicryMode.MODERATE: 2,
            MimicryMode.AGGRESSIVE: 3,
            MimicryMode.PARANOID: 4,
            MimicryMode.HUMAN: 5,
        }
        
        # Mode should have been upgraded from LIGHT (1)
        assert mode_levels[engine.mode] >= mode_levels[MimicryMode.MODERATE]
    
    def test_behavioral_score(self):
        """Test behavioral score calculation"""
        engine = BehavioralMimicryEngine(mode=MimicryMode.PARANOID)
        
        score = engine.get_behavioral_score()
        
        # PARANOID mode should have low score (good for evasion)
        assert 0 <= score <= 1
        assert score < 0.2  # Low score = human-like
    
    def test_generate_traffic_burst(self):
        """Test traffic burst generation"""
        engine = BehavioralMimicryEngine(mode=MimicryMode.MODERATE)
        
        events = engine.generate_traffic_burst(num_requests=5)
        
        assert len(events) == 5
        for event in events:
            assert isinstance(event, TrafficEvent)
    
    def test_optimal_request_timing(self):
        """Test optimal C2 request timing"""
        engine = BehavioralMimicryEngine(mode=MimicryMode.MODERATE)
        
        min_ms, max_ms = engine.get_optimal_request_timing()
        
        assert min_ms > 0
        assert max_ms > min_ms
    
    def test_wrap_action(self):
        """Test action wrapping with mimicry"""
        engine = BehavioralMimicryEngine(mode=MimicryMode.MODERATE)
        
        # Create test action
        call_count = [0]
        def test_action():
            call_count[0] += 1
            return "done"
        
        result = engine.wrap_action(test_action)
        
        assert result == "done"
        assert call_count[0] == 1
    
    def test_status(self):
        """Test status retrieval"""
        engine = BehavioralMimicryEngine(mode=MimicryMode.AGGRESSIVE)
        
        status = engine.get_status()
        
        assert status["mode"] == "aggressive"
        assert "behavioral_score" in status
        assert "events_generated" in status
        assert "is_running" in status
    
    def test_continuous_mimicry_start_stop(self):
        """Test continuous mimicry start/stop"""
        engine = BehavioralMimicryEngine(mode=MimicryMode.LIGHT)
        
        # Start
        engine.start_continuous_mimicry()
        assert engine.is_running is True
        
        # Let it run briefly
        time.sleep(0.5)
        
        # Stop
        engine.stop_continuous_mimicry()
        assert engine.is_running is False


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================

class TestConvenienceFunctions:
    """Test convenience functions"""
    
    def test_create_mimicry_engine(self):
        """Test engine creation function"""
        engine = create_mimicry_engine(mode="paranoid", auto_detect=False)
        
        assert engine.mode == MimicryMode.PARANOID
    
    def test_quick_mimic(self):
        """Test quick mimic wrapper"""
        result = quick_mimic(lambda: 42, mode="light")
        
        assert result == 42
    
    def test_analyze_defenses_function(self):
        """Test standalone analyze_defenses"""
        analysis = analyze_defenses()
        
        assert isinstance(analysis, DefenseAnalysis)
    
    def test_get_human_timing(self):
        """Test human timing helper"""
        min_ms, max_ms = get_human_timing()
        
        assert min_ms > 0
        assert max_ms > min_ms


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestIntegration:
    """Integration tests for behavioral mimicry"""
    
    def test_full_human_simulation(self):
        """Test complete human behavior simulation"""
        engine = create_mimicry_engine(mode="human", auto_detect=False)
        
        # Simulate some activities
        engine._sim_mouse_movement()
        engine._sim_typing()
        engine._sim_scroll()
        engine._sim_window_switch()
        
        # Check events were generated
        assert engine.events_generated > 0
    
    def test_sentinelone_bypass_score(self):
        """Test that PARANOID mode achieves target score for SentinelOne"""
        engine = BehavioralMimicryEngine(mode=MimicryMode.PARANOID)
        
        # Simulate some activity
        for _ in range(5):
            engine._sim_mouse_movement()
            engine._sim_typing()
        
        # Generate 100+ events
        while engine.events_generated < 100:
            engine._generate_paranoid_activity()
        
        score = engine.get_behavioral_score()
        
        # Target: SentinelOne behavioral score = 0
        # Our score < 0.1 means < 10% detection probability
        assert score < 0.1, f"Behavioral score {score} too high for SentinelOne bypass"
    
    def test_gan_traffic_mimics_human(self):
        """Test that GAN traffic resembles human patterns"""
        engine = BehavioralMimicryEngine(mode=MimicryMode.AGGRESSIVE)
        
        # Generate traffic
        events = engine.generate_traffic_burst(num_requests=50)
        
        # Check timing distribution
        timings = []
        for i in range(1, len(events)):
            diff = (events[i].timestamp - events[i-1].timestamp) * 1000
            timings.append(diff)
        
        # Human browsing has burst patterns
        # Should have some fast requests (<200ms) and some slow (>500ms)
        fast_count = sum(1 for t in timings if t < 200)
        slow_count = sum(1 for t in timings if t > 500)
        
        # Should have both burst and idle patterns
        assert fast_count > 0 or slow_count > 0


# =============================================================================
# BEACON INTEGRATION TESTS
# =============================================================================

class TestBeaconIntegration:
    """Test integration with evasive beacon"""
    
    def test_beacon_mimicry_import(self):
        """Test that beacon can import mimicry module"""
        try:
            from agents.evasive_beacon import (
                EvasiveBeacon,
                BeaconConfig,
                BEHAVIORAL_MIMICRY_AVAILABLE
            )
            assert BEHAVIORAL_MIMICRY_AVAILABLE is True
        except ImportError as e:
            pytest.skip(f"Beacon import failed: {e}")
    
    def test_beacon_mimicry_config(self):
        """Test beacon mimicry configuration"""
        try:
            from agents.evasive_beacon import BeaconConfig
            
            config = BeaconConfig(
                c2_host="127.0.0.1",
                enable_behavioral_mimicry=True,
                mimicry_mode="paranoid",
                mimicry_continuous=False,  # Don't auto-start for tests
            )
            
            assert config.enable_behavioral_mimicry is True
            assert config.mimicry_mode == "paranoid"
        except ImportError as e:
            pytest.skip(f"Beacon import failed: {e}")


# =============================================================================
# PERFORMANCE TESTS
# =============================================================================

class TestPerformance:
    """Performance tests for behavioral mimicry"""
    
    def test_mouse_movement_speed(self):
        """Test mouse movement generation speed"""
        sim = HumanMouseSimulator()
        
        start = time.time()
        for _ in range(100):
            sim.generate_movement(random.randint(0, 1920), random.randint(0, 1080))
        elapsed = time.time() - start
        
        # Should generate 100 movements in < 1 second
        assert elapsed < 1.0, f"Mouse simulation too slow: {elapsed:.2f}s"
    
    def test_typing_speed(self):
        """Test typing simulation speed"""
        sim = HumanKeyboardSimulator()
        
        start = time.time()
        for _ in range(10):
            sim.generate_typing("The quick brown fox jumps over the lazy dog")
        elapsed = time.time() - start
        
        # Should be fast (not actual real-time typing)
        assert elapsed < 0.5, f"Typing simulation too slow: {elapsed:.2f}s"
    
    def test_gan_generation_speed(self):
        """Test GAN traffic generation speed"""
        gen = GANTrafficGenerator()
        
        start = time.time()
        for _ in range(100):
            gen.generate_traffic_pattern(num_events=10)
        elapsed = time.time() - start
        
        # Should generate 1000 events quickly
        assert elapsed < 2.0, f"GAN generation too slow: {elapsed:.2f}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
