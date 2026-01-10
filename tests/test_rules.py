"""Tests for detection rules and rule engine."""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from vpsguard.config import (
    BreachDetectionConfig,
    BruteForceConfig,
    InvalidUserConfig,
    MultiVectorConfig,
    QuietHoursConfig,
    RootLoginConfig,
    VPSGuardConfig,
    load_config,
    validate_config,
)
from vpsguard.geo.reader import GeoLocation
from vpsguard.models.events import AuthEvent, EventType, Severity
from vpsguard.rules import (
    BreachDetectionRule,
    BruteForceRule,
    InvalidUserRule,
    MultiVectorRule,
    QuietHoursRule,
    RootLoginRule,
    RuleEngine,
)


class TestConfigLoading:
    """Test configuration loading and validation."""

    def test_default_config(self):
        """Test loading default configuration."""
        config = load_config()
        assert config is not None
        assert config.rules.brute_force.enabled is True
        assert config.rules.brute_force.threshold == 10
        assert config.rules.brute_force.window_minutes == 60
        assert config.rules.brute_force.severity == "high"

    def test_load_from_toml(self):
        """Test loading config from TOML file."""
        toml_content = """
[rules.brute_force]
enabled = true
threshold = 15
window_minutes = 30
severity = "critical"

[rules.breach_detection]
enabled = false
failures_before_success = 3
severity = "high"

[whitelist]
ips = ["127.0.0.1", "192.168.1.1"]

[output]
format = "json"
verbosity = 2
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(toml_content)
            f.flush()
            temp_path = f.name

        # Load config after file is closed (Windows compatibility)
        config = load_config(temp_path)

        assert config.rules.brute_force.threshold == 15
        assert config.rules.brute_force.window_minutes == 30
        assert config.rules.brute_force.severity == "critical"
        assert config.rules.breach_detection.enabled is False
        assert config.rules.breach_detection.failures_before_success == 3
        assert "127.0.0.1" in config.whitelist_ips
        assert "192.168.1.1" in config.whitelist_ips
        assert config.output.format == "json"
        assert config.output.verbosity == 2

        # Clean up
        Path(temp_path).unlink()

    def test_validate_config(self):
        """Test config validation."""
        config = VPSGuardConfig()
        warnings = validate_config(config)
        assert len(warnings) == 0  # Default config should be valid

        # Test invalid config
        config.rules.brute_force.threshold = 0
        config.rules.brute_force.severity = "invalid"
        config.rules.quiet_hours.start = 25
        warnings = validate_config(config)
        assert len(warnings) >= 3
        assert any("threshold" in w for w in warnings)
        assert any("severity" in w for w in warnings)
        assert any("quiet_hours.start" in w for w in warnings)


class TestBruteForceRule:
    """Test brute force detection rule."""

    def test_basic_brute_force(self):
        """Test basic brute force detection."""
        config = BruteForceConfig(threshold=5, window_minutes=60)
        rule = BruteForceRule(config)

        # Create 10 failed login attempts from same IP
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username=f"user{i}",
                success=False,
                raw_line="test"
            )
            for i in range(10)
        ]

        violations = rule.evaluate(events)
        assert len(violations) == 1
        assert violations[0].ip == "1.2.3.4"
        assert violations[0].severity == Severity.HIGH
        assert len(violations[0].affected_events) >= 5

    def test_no_violation_below_threshold(self):
        """Test no violation when below threshold."""
        config = BruteForceConfig(threshold=10, window_minutes=60)
        rule = BruteForceRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username=f"user{i}",
                success=False,
                raw_line="test"
            )
            for i in range(5)  # Only 5 attempts
        ]

        violations = rule.evaluate(events)
        assert len(violations) == 0

    def test_window_enforcement(self):
        """Test time window is properly enforced."""
        config = BruteForceConfig(threshold=5, window_minutes=10)
        rule = BruteForceRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            # 3 attempts in first 5 minutes
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username=f"user{i}",
                success=False,
                raw_line="test"
            )
            for i in range(3)
        ] + [
            # 3 more attempts 20 minutes later (outside window)
            AuthEvent(
                timestamp=base_time + timedelta(minutes=20 + i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username=f"user{i}",
                success=False,
                raw_line="test"
            )
            for i in range(3)
        ]

        violations = rule.evaluate(events)
        assert len(violations) == 0  # No single window has 5 attempts

    def test_disabled_rule(self):
        """Test disabled rule returns no violations."""
        config = BruteForceConfig(enabled=False, threshold=1)
        rule = BruteForceRule(config)

        events = [
            AuthEvent(
                timestamp=datetime.now(),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="user",
                success=False,
                raw_line="test"
            )
        ] * 100

        violations = rule.evaluate(events)
        assert len(violations) == 0


class TestBreachDetectionRule:
    """Test breach detection rule (most important rule)."""

    def test_basic_breach(self):
        """Test basic breach detection."""
        config = BreachDetectionConfig(failures_before_success=3)
        rule = BreachDetectionRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            # 5 failed attempts
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test"
            )
            for i in range(5)
        ] + [
            # Followed by successful login
            AuthEvent(
                timestamp=base_time + timedelta(minutes=5),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=True,
                raw_line="test"
            )
        ]

        violations = rule.evaluate(events)
        assert len(violations) == 1
        assert violations[0].ip == "1.2.3.4"
        assert violations[0].severity == Severity.CRITICAL
        assert "BREACH" in violations[0].description.upper()
        assert violations[0].details["failed_attempts"] == 5
        assert violations[0].details["successful_username"] == "admin"

    def test_no_breach_below_threshold(self):
        """Test no breach when failures below threshold."""
        config = BreachDetectionConfig(failures_before_success=10)
        rule = BreachDetectionRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test"
            )
            for i in range(5)
        ] + [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=5),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=True,
                raw_line="test"
            )
        ]

        violations = rule.evaluate(events)
        assert len(violations) == 0

    def test_success_without_failures(self):
        """Test successful login without prior failures."""
        config = BreachDetectionConfig(failures_before_success=3)
        rule = BreachDetectionRule(config)

        events = [
            AuthEvent(
                timestamp=datetime.now(),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=True,
                raw_line="test"
            )
        ]

        violations = rule.evaluate(events)
        assert len(violations) == 0

    def test_multiple_breaches(self):
        """Test detection of multiple breaches from different IPs."""
        config = BreachDetectionConfig(failures_before_success=2)
        rule = BreachDetectionRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = []

        # Breach from IP 1
        for i in range(3):
            events.append(AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=False,
                raw_line="test"
            ))
        events.append(AuthEvent(
            timestamp=base_time + timedelta(minutes=3),
            event_type=EventType.SUCCESSFUL_LOGIN,
            ip="1.1.1.1",
            username="admin",
            success=True,
            raw_line="test"
        ))

        # Breach from IP 2
        for i in range(3):
            events.append(AuthEvent(
                timestamp=base_time + timedelta(minutes=10 + i),
                event_type=EventType.FAILED_LOGIN,
                ip="2.2.2.2",
                username="root",
                success=False,
                raw_line="test"
            ))
        events.append(AuthEvent(
            timestamp=base_time + timedelta(minutes=13),
            event_type=EventType.SUCCESSFUL_LOGIN,
            ip="2.2.2.2",
            username="root",
            success=True,
            raw_line="test"
        ))

        violations = rule.evaluate(events)
        assert len(violations) == 2
        assert set(v.ip for v in violations) == {"1.1.1.1", "2.2.2.2"}


class TestQuietHoursRule:
    """Test quiet hours detection rule."""

    def test_login_during_quiet_hours(self):
        """Test detection of login during quiet hours."""
        config = QuietHoursConfig(start=23, end=6)
        rule = QuietHoursRule(config)

        # Login at 2 AM (during quiet hours)
        event = AuthEvent(
            timestamp=datetime(2024, 1, 1, 2, 30, 0),
            event_type=EventType.SUCCESSFUL_LOGIN,
            ip="1.2.3.4",
            username="admin",
            success=True,
            raw_line="test"
        )

        violations = rule.evaluate([event])
        assert len(violations) == 1
        assert violations[0].ip == "1.2.3.4"
        assert violations[0].details["hour"] == 2

    def test_login_outside_quiet_hours(self):
        """Test no detection when login is outside quiet hours."""
        config = QuietHoursConfig(start=23, end=6)
        rule = QuietHoursRule(config)

        # Login at 10 AM (outside quiet hours)
        event = AuthEvent(
            timestamp=datetime(2024, 1, 1, 10, 30, 0),
            event_type=EventType.SUCCESSFUL_LOGIN,
            ip="1.2.3.4",
            username="admin",
            success=True,
            raw_line="test"
        )

        violations = rule.evaluate([event])
        assert len(violations) == 0

    def test_failed_login_ignored(self):
        """Test that failed logins are not flagged (only successful)."""
        config = QuietHoursConfig(start=23, end=6)
        rule = QuietHoursRule(config)

        event = AuthEvent(
            timestamp=datetime(2024, 1, 1, 2, 30, 0),
            event_type=EventType.FAILED_LOGIN,
            ip="1.2.3.4",
            username="admin",
            success=False,
            raw_line="test"
        )

        violations = rule.evaluate([event])
        assert len(violations) == 0

    def test_wraparound_quiet_hours(self):
        """Test quiet hours that wrap around midnight."""
        config = QuietHoursConfig(start=22, end=7)
        rule = QuietHoursRule(config)

        # Test various hours
        test_cases = [
            (23, True),   # 11 PM - quiet
            (0, True),    # midnight - quiet
            (6, True),    # 6 AM - quiet
            (7, False),   # 7 AM - not quiet
            (10, False),  # 10 AM - not quiet
            (21, False),  # 9 PM - not quiet
        ]

        for hour, should_flag in test_cases:
            event = AuthEvent(
                timestamp=datetime(2024, 1, 1, hour, 30, 0),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=True,
                raw_line="test"
            )
            violations = rule.evaluate([event])
            assert (len(violations) > 0) == should_flag, f"Hour {hour} failed"


class TestInvalidUserRule:
    """Test invalid user detection rule."""

    def test_basic_enumeration(self):
        """Test basic username enumeration detection."""
        config = InvalidUserConfig(threshold=5, window_minutes=60)
        rule = InvalidUserRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.INVALID_USER,
                ip="1.2.3.4",
                username=f"user{i}",
                success=False,
                raw_line="test"
            )
            for i in range(10)
        ]

        violations = rule.evaluate(events)
        assert len(violations) == 1
        assert violations[0].ip == "1.2.3.4"
        assert violations[0].details["invalid_attempts"] >= 5

    def test_no_violation_below_threshold(self):
        """Test no violation when below threshold."""
        config = InvalidUserConfig(threshold=10, window_minutes=60)
        rule = InvalidUserRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.INVALID_USER,
                ip="1.2.3.4",
                username=f"user{i}",
                success=False,
                raw_line="test"
            )
            for i in range(5)
        ]

        violations = rule.evaluate(events)
        assert len(violations) == 0


class TestRootLoginRule:
    """Test root login detection rule."""

    def test_root_login_attempt(self):
        """Test detection of root login attempt."""
        config = RootLoginConfig()
        rule = RootLoginRule(config)

        event = AuthEvent(
            timestamp=datetime.now(),
            event_type=EventType.FAILED_LOGIN,
            ip="1.2.3.4",
            username="root",
            success=False,
            raw_line="test"
        )

        violations = rule.evaluate([event])
        assert len(violations) == 1
        assert violations[0].ip == "1.2.3.4"
        assert "root" in violations[0].description.lower()

    def test_successful_root_login(self):
        """Test detection of successful root login."""
        config = RootLoginConfig()
        rule = RootLoginRule(config)

        event = AuthEvent(
            timestamp=datetime.now(),
            event_type=EventType.SUCCESSFUL_LOGIN,
            ip="1.2.3.4",
            username="root",
            success=True,
            raw_line="test"
        )

        violations = rule.evaluate([event])
        assert len(violations) == 1
        assert violations[0].details["success"] is True

    def test_non_root_login_ignored(self):
        """Test that non-root logins are ignored."""
        config = RootLoginConfig()
        rule = RootLoginRule(config)

        event = AuthEvent(
            timestamp=datetime.now(),
            event_type=EventType.FAILED_LOGIN,
            ip="1.2.3.4",
            username="admin",
            success=False,
            raw_line="test"
        )

        violations = rule.evaluate([event])
        assert len(violations) == 0

    def test_case_insensitive(self):
        """Test that root detection is case-insensitive."""
        config = RootLoginConfig()
        rule = RootLoginRule(config)

        for username in ["root", "Root", "ROOT", "RoOt"]:
            event = AuthEvent(
                timestamp=datetime.now(),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username=username,
                success=False,
                raw_line="test"
            )
            violations = rule.evaluate([event])
            assert len(violations) == 1, f"Failed for username: {username}"



class TestRuleEngine:
    """Test the rule engine orchestration."""

    def test_basic_engine_run(self):
        """Test basic engine execution."""
        config = VPSGuardConfig()
        engine = RuleEngine(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test"
            )
            for i in range(15)  # Enough to trigger brute force
        ]

        result = engine.evaluate(events)
        assert result is not None
        assert len(result.violations) > 0  # Should trigger brute force rule
        assert "1.2.3.4" in result.flagged_ips

    def test_clean_events_separation(self):
        """Test that clean events are properly separated."""
        config = VPSGuardConfig()
        engine = RuleEngine(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)

        # Mix of events: some will trigger rules, some won't
        events = [
            # Brute force from IP 1 (will be flagged)
            *[AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=False,
                raw_line="test"
            ) for i in range(15)],

            # Normal activity from IP 2 (should be clean)
            AuthEvent(
                timestamp=base_time + timedelta(minutes=20),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="2.2.2.2",
                username="user",
                success=True,
                raw_line="test"
            ),
            AuthEvent(
                timestamp=base_time + timedelta(minutes=25),
                event_type=EventType.FAILED_LOGIN,
                ip="2.2.2.2",
                username="user",
                success=False,
                raw_line="test"
            ),
        ]

        result = engine.evaluate(events)

        # Should have violations from IP 1
        assert len(result.violations) > 0
        assert "1.1.1.1" in result.flagged_ips

        # Should have clean events from IP 2
        assert len(result.clean_events) > 0

    def test_whitelist_filtering(self):
        """Test that whitelisted IPs are not flagged."""
        config = VPSGuardConfig()
        config.whitelist_ips = ["1.2.3.4"]
        engine = RuleEngine(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test"
            )
            for i in range(20)  # Enough to trigger brute force
        ]

        result = engine.evaluate(events)
        assert len(result.violations) == 0  # Whitelisted IP
        assert "1.2.3.4" not in result.flagged_ips
        assert len(result.clean_events) == len(events)  # Whitelisted events remain clean

    def test_disabled_rules_dont_run(self):
        """Test that disabled rules don't produce violations."""
        config = VPSGuardConfig()
        config.rules.brute_force.enabled = False
        engine = RuleEngine(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test"
            )
            for i in range(20)
        ]

        result = engine.evaluate(events)
        # No brute force violations since rule is disabled
        brute_force_violations = [v for v in result.violations if v.rule_name == "brute_force"]
        assert len(brute_force_violations) == 0

    def test_multiple_rules_trigger(self):
        """Test that multiple rules can trigger on same events."""
        config = VPSGuardConfig()
        config.rules.brute_force.threshold = 3
        config.rules.breach_detection.failures_before_success = 3
        engine = RuleEngine(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            # 5 failed attempts
            *[AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test"
            ) for i in range(5)],
            # Successful login
            AuthEvent(
                timestamp=base_time + timedelta(minutes=5),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=True,
                raw_line="test"
            )
        ]

        result = engine.evaluate(events)

        # Should trigger both brute force AND breach detection
        rule_names = set(v.rule_name for v in result.violations)
        assert "brute_force" in rule_names
        assert "breach_detection" in rule_names

    def test_empty_events(self):
        """Test engine handles empty events gracefully."""
        config = VPSGuardConfig()
        engine = RuleEngine(config)

        result = engine.evaluate([])
        assert result.violations == []
        assert result.clean_events == []
        assert result.flagged_ips == set()

    def test_geo_velocity_rule_integration(self):
        """Test that geo velocity rule is triggered when geo_data is provided."""
        config = VPSGuardConfig()
        config.rules.geo_velocity.enabled = True
        config.rules.geo_velocity.max_velocity_km_h = 1000
        engine = RuleEngine(config)

        # NYC and Tokyo coordinates - impossible travel in 30 minutes
        nyc = GeoLocation(latitude=40.7128, longitude=-74.0060, country_code="US", city="New York")
        tokyo = GeoLocation(latitude=35.6762, longitude=139.6503, country_code="JP", city="Tokyo")

        geo_data = {
            "1.1.1.1": nyc,
            "2.2.2.2": tokyo,
        }

        base_time = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            AuthEvent(
                timestamp=base_time,
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=True,
                raw_line="test"
            ),
            # Same user logs in from Tokyo 30 minutes later (impossible!)
            AuthEvent(
                timestamp=base_time + timedelta(minutes=30),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip="2.2.2.2",
                username="admin",
                success=True,
                raw_line="test"
            ),
        ]

        result = engine.evaluate(events, geo_data=geo_data)

        # Should have geo velocity violation
        geo_violations = [v for v in result.violations if v.rule_name == "geo_velocity"]
        assert len(geo_violations) >= 1


class TestMultiVectorRule:
    """Test multi-vector attack detection rule."""

    def test_basic_multi_vector_detection(self):
        """Test detection of IP appearing in multiple log sources."""
        config = MultiVectorConfig(min_sources=2, min_events_per_source=3)
        rule = MultiVectorRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = []

        # IP 1.2.3.4 active in auth.log (3 events)
        for i in range(3):
            events.append(AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test",
                log_source="auth.log"
            ))

        # Same IP 1.2.3.4 active in nginx.log (3 events)
        for i in range(3):
            events.append(AuthEvent(
                timestamp=base_time + timedelta(minutes=10 + i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="www-data",
                success=False,
                raw_line="test",
                log_source="nginx.log"
            ))

        violations = rule.evaluate(events)
        assert len(violations) == 1
        assert violations[0].ip == "1.2.3.4"
        assert violations[0].rule_name == "multi_vector"
        assert violations[0].details["source_count"] == 2
        assert set(violations[0].details["sources"]) == {"auth.log", "nginx.log"}

    def test_no_violation_below_min_sources(self):
        """Test no detection when IP only appears in one source."""
        config = MultiVectorConfig(min_sources=2, min_events_per_source=3)
        rule = MultiVectorRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = [
            AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test",
                log_source="auth.log"
            )
            for i in range(10)  # Lots of events but only one source
        ]

        violations = rule.evaluate(events)
        assert len(violations) == 0

    def test_no_violation_below_min_events_per_source(self):
        """Test no detection when source has too few events."""
        config = MultiVectorConfig(min_sources=2, min_events_per_source=5)
        rule = MultiVectorRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = []

        # Only 2 events from auth.log (below min_events_per_source=5)
        for i in range(2):
            events.append(AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test",
                log_source="auth.log"
            ))

        # Only 2 events from nginx.log
        for i in range(2):
            events.append(AuthEvent(
                timestamp=base_time + timedelta(minutes=10 + i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test",
                log_source="nginx.log"
            ))

        violations = rule.evaluate(events)
        assert len(violations) == 0

    def test_multiple_ips_multi_vector(self):
        """Test detection of multiple IPs with multi-vector attacks."""
        config = MultiVectorConfig(min_sources=2, min_events_per_source=2)
        rule = MultiVectorRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = []

        # IP 1 in two sources
        for i in range(2):
            events.append(AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=False,
                raw_line="test",
                log_source="auth.log"
            ))
            events.append(AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.1.1.1",
                username="admin",
                success=False,
                raw_line="test",
                log_source="nginx.log"
            ))

        # IP 2 in three sources
        for source in ["auth.log", "nginx.log", "syslog"]:
            for i in range(2):
                events.append(AuthEvent(
                    timestamp=base_time + timedelta(minutes=20 + i),
                    event_type=EventType.FAILED_LOGIN,
                    ip="2.2.2.2",
                    username="root",
                    success=False,
                    raw_line="test",
                    log_source=source
                ))

        violations = rule.evaluate(events)
        assert len(violations) == 2
        ips = {v.ip for v in violations}
        assert ips == {"1.1.1.1", "2.2.2.2"}

        # IP 2 should have 3 sources
        ip2_violation = [v for v in violations if v.ip == "2.2.2.2"][0]
        assert ip2_violation.details["source_count"] == 3

    def test_disabled_rule(self):
        """Test that disabled rule returns no violations."""
        config = MultiVectorConfig(enabled=False)
        rule = MultiVectorRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = []

        for source in ["auth.log", "nginx.log"]:
            for i in range(5):
                events.append(AuthEvent(
                    timestamp=base_time + timedelta(minutes=i),
                    event_type=EventType.FAILED_LOGIN,
                    ip="1.2.3.4",
                    username="admin",
                    success=False,
                    raw_line="test",
                    log_source=source
                ))

        violations = rule.evaluate(events)
        assert len(violations) == 0

    def test_log_sources_property(self):
        """Test RuleViolation.log_sources property."""
        config = MultiVectorConfig(min_sources=2, min_events_per_source=2)
        rule = MultiVectorRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = []

        for source in ["auth.log", "nginx.log", "secure"]:
            for i in range(2):
                events.append(AuthEvent(
                    timestamp=base_time + timedelta(minutes=i),
                    event_type=EventType.FAILED_LOGIN,
                    ip="1.2.3.4",
                    username="admin",
                    success=False,
                    raw_line="test",
                    log_source=source
                ))

        violations = rule.evaluate(events)
        assert len(violations) == 1

        # Test the log_sources property on RuleViolation
        sources = violations[0].log_sources
        assert sources == ["auth.log", "nginx.log", "secure"]  # Sorted

    def test_events_without_log_source(self):
        """Test that events without log_source are gracefully ignored."""
        config = MultiVectorConfig(min_sources=2, min_events_per_source=2)
        rule = MultiVectorRule(config)

        base_time = datetime(2024, 1, 1, 12, 0, 0)
        events = []

        # Events without log_source
        for i in range(10):
            events.append(AuthEvent(
                timestamp=base_time + timedelta(minutes=i),
                event_type=EventType.FAILED_LOGIN,
                ip="1.2.3.4",
                username="admin",
                success=False,
                raw_line="test",
                log_source=None
            ))

        violations = rule.evaluate(events)
        assert len(violations) == 0
