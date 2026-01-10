"""Comprehensive tests for synthetic log generators."""

import json
import os
import tempfile
from datetime import datetime

import pytest

from vpsguard.generators import (
    AttackConfig,
    AttackProfile,
    GeneratorConfig,
    SyntheticLogGenerator,
)
from vpsguard.parsers import AuthLogParser, JournaldParser, SecureLogParser


class TestAttackProfile:
    """Tests for AttackProfile enum."""

    def test_all_profiles_exist(self):
        """Test that all six attack profiles are defined."""
        profiles = [
            AttackProfile.BRUTE_FORCE,
            AttackProfile.BOTNET,
            AttackProfile.CREDENTIAL_STUFFING,
            AttackProfile.LOW_AND_SLOW,
            AttackProfile.BREACH,
            AttackProfile.RECON,
        ]
        assert len(profiles) == 6

    def test_profile_values(self):
        """Test that profiles have correct string values."""
        assert AttackProfile.BRUTE_FORCE.value == "brute"
        assert AttackProfile.BOTNET.value == "botnet"
        assert AttackProfile.CREDENTIAL_STUFFING.value == "stuffing"
        assert AttackProfile.LOW_AND_SLOW.value == "low-slow"
        assert AttackProfile.BREACH.value == "breach"
        assert AttackProfile.RECON.value == "recon"


class TestAttackConfig:
    """Tests for AttackConfig dataclass."""

    def test_create_basic_config(self):
        """Test creating a basic attack config."""
        config = AttackConfig(
            profile=AttackProfile.BRUTE_FORCE,
            ratio=0.1
        )
        assert config.profile == AttackProfile.BRUTE_FORCE
        assert config.ratio == 0.1
        assert config.ips_count == 1
        assert config.attempts_per_ip == 50
        assert config.time_window_minutes == 10

    def test_create_custom_config(self):
        """Test creating a config with custom parameters."""
        config = AttackConfig(
            profile=AttackProfile.BOTNET,
            ratio=0.2,
            ips_count=100,
            attempts_per_ip=3,
            target_users=["root", "admin"],
            time_window_minutes=5
        )
        assert config.ips_count == 100
        assert config.attempts_per_ip == 3
        assert config.target_users == ["root", "admin"]
        assert config.time_window_minutes == 5

    def test_ratio_validation(self):
        """Test that ratio must be between 0.0 and 1.0."""
        with pytest.raises(ValueError, match="ratio must be between"):
            AttackConfig(profile=AttackProfile.BRUTE_FORCE, ratio=1.5)

        with pytest.raises(ValueError, match="ratio must be between"):
            AttackConfig(profile=AttackProfile.BRUTE_FORCE, ratio=-0.1)

    def test_ips_count_validation(self):
        """Test that ips_count must be at least 1."""
        with pytest.raises(ValueError, match="ips_count must be at least"):
            AttackConfig(profile=AttackProfile.BRUTE_FORCE, ratio=0.1, ips_count=0)

    def test_attempts_per_ip_validation(self):
        """Test that attempts_per_ip must be at least 1."""
        with pytest.raises(ValueError, match="attempts_per_ip must be at least"):
            AttackConfig(profile=AttackProfile.BRUTE_FORCE, ratio=0.1, attempts_per_ip=0)

    def test_time_window_validation(self):
        """Test that time_window_minutes must be at least 1."""
        with pytest.raises(ValueError, match="time_window_minutes must be at least"):
            AttackConfig(profile=AttackProfile.BRUTE_FORCE, ratio=0.1, time_window_minutes=0)


class TestGeneratorConfig:
    """Tests for GeneratorConfig dataclass."""

    def test_default_config(self):
        """Test default generator configuration."""
        config = GeneratorConfig()
        assert config.entries == 1000
        assert config.baseline_ips == 50
        assert len(config.baseline_users) == 5
        assert "ubuntu" in config.baseline_users
        assert config.attack_profiles == []

    def test_time_defaults(self):
        """Test that start_time and end_time have proper defaults."""
        config = GeneratorConfig()
        assert config.start_time is not None
        assert config.end_time is not None
        assert config.end_time > config.start_time

        # Should be approximately 24 hours apart
        time_diff = (config.end_time - config.start_time).total_seconds()
        assert 23.9 * 3600 < time_diff < 24.1 * 3600

    def test_custom_config(self):
        """Test creating a custom generator configuration."""
        start = datetime(2024, 1, 1, 0, 0, 0)
        end = datetime(2024, 1, 2, 0, 0, 0)
        attacks = [AttackConfig(profile=AttackProfile.BRUTE_FORCE, ratio=0.1)]

        config = GeneratorConfig(
            entries=500,
            attack_profiles=attacks,
            baseline_ips=25,
            baseline_users=["user1", "user2"],
            start_time=start,
            end_time=end,
            seed=42
        )

        assert config.entries == 500
        assert config.baseline_ips == 25
        assert config.baseline_users == ["user1", "user2"]
        assert config.start_time == start
        assert config.end_time == end
        assert config.seed == 42


class TestSyntheticLogGenerator:
    """Tests for SyntheticLogGenerator."""

    def test_create_generator(self):
        """Test creating a basic generator."""
        config = GeneratorConfig(entries=100, seed=42)
        gen = SyntheticLogGenerator(config)
        assert gen.config == config
        assert len(gen.normal_ips) == 50

    def test_seed_reproducibility(self):
        """Test that same seed produces same output."""
        config1 = GeneratorConfig(entries=100, seed=42)
        gen1 = SyntheticLogGenerator(config1)
        output1 = gen1.generate()

        config2 = GeneratorConfig(entries=100, seed=42)
        gen2 = SyntheticLogGenerator(config2)
        output2 = gen2.generate()

        assert output1 == output2

    def test_different_seeds_produce_different_output(self):
        """Test that different seeds produce different output."""
        config1 = GeneratorConfig(entries=100, seed=42)
        gen1 = SyntheticLogGenerator(config1)
        output1 = gen1.generate()

        config2 = GeneratorConfig(entries=100, seed=123)
        gen2 = SyntheticLogGenerator(config2)
        output2 = gen2.generate()

        assert output1 != output2

    def test_generate_normal_traffic_only(self):
        """Test generating only normal traffic."""
        config = GeneratorConfig(entries=50, seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate()

        lines = output.strip().split("\n")
        assert len(lines) == 50

        # All lines should be parseable
        for line in lines:
            assert "sshd" in line
            assert "from" in line

    def test_brute_force_pattern(self):
        """Test brute force attack pattern generation."""
        attack = AttackConfig(
            profile=AttackProfile.BRUTE_FORCE,
            ratio=0.5,
            attempts_per_ip=10,
            time_window_minutes=5
        )
        config = GeneratorConfig(entries=100, attack_profiles=[attack], seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate()

        lines = output.strip().split("\n")

        # Should have mix of normal and attack traffic
        failed_lines = [line for line in lines if "Failed password" in line]
        assert len(failed_lines) > 0

        # Extract IPs from failed attempts - focus on attacker IPs (192.168.x.x)
        attack_ips = set()
        normal_ips = set()
        for line in failed_lines:
            if "from" in line:
                parts = line.split("from")
                if len(parts) > 1:
                    ip = parts[1].split()[0]
                    if ip.startswith("192.168"):
                        attack_ips.add(ip)
                    else:
                        normal_ips.add(ip)

        # Brute force should use very few attack IPs (ideally 1 per execution)
        # Allow up to 10 for multiple executions
        assert len(attack_ips) <= 10

    def test_botnet_pattern(self):
        """Test botnet attack pattern generation."""
        attack = AttackConfig(
            profile=AttackProfile.BOTNET,
            ratio=0.3,
            ips_count=20,
            attempts_per_ip=2,
            time_window_minutes=5
        )
        config = GeneratorConfig(entries=200, attack_profiles=[attack], seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate()

        lines = output.strip().split("\n")
        failed_lines = [line for line in lines if "Failed password" in line and "192.168" in line]

        # Extract IPs from failed attempts
        ips = set()
        for line in failed_lines:
            if "from" in line:
                parts = line.split("from")
                if len(parts) > 1:
                    ip = parts[1].split()[0]
                    ips.add(ip)

        # Botnet should have many IPs
        assert len(ips) >= 10

    def test_credential_stuffing_pattern(self):
        """Test credential stuffing attack pattern."""
        attack = AttackConfig(
            profile=AttackProfile.CREDENTIAL_STUFFING,
            ratio=0.4,
            ips_count=10,
            attempts_per_ip=5
        )
        config = GeneratorConfig(entries=150, attack_profiles=[attack], seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate()

        lines = output.strip().split("\n")

        # Should have many different usernames
        usernames = set()
        for line in lines:
            if "Failed password for" in line and "192.168" in line:
                parts = line.split("for")
                if len(parts) > 1:
                    username_part = parts[1].split("from")[0].strip()
                    if username_part.startswith("invalid user"):
                        username = username_part.replace("invalid user", "").strip()
                    else:
                        username = username_part
                    usernames.add(username)

        # Should have variety of usernames
        assert len(usernames) >= 3

    def test_low_and_slow_pattern(self):
        """Test low-and-slow attack pattern."""
        start = datetime(2024, 1, 1, 0, 0, 0)
        end = datetime(2024, 1, 8, 0, 0, 0)  # 7 days
        attack = AttackConfig(
            profile=AttackProfile.LOW_AND_SLOW,
            ratio=0.2,
            ips_count=2,
            attempts_per_ip=5
        )
        config = GeneratorConfig(
            entries=100,
            attack_profiles=[attack],
            start_time=start,
            end_time=end,
            seed=42
        )
        gen = SyntheticLogGenerator(config)
        output = gen.generate()

        lines = output.strip().split("\n")

        # Parse timestamps from attack lines
        attack_lines = [line for line in lines if "Failed password" in line and "192.168" in line]

        # Should be spread out over time
        assert len(attack_lines) >= 5

    def test_breach_pattern(self):
        """Test breach attack pattern (failures then success)."""
        attack = AttackConfig(
            profile=AttackProfile.BREACH,
            ratio=0.3,
            attempts_per_ip=20
        )
        config = GeneratorConfig(entries=100, attack_profiles=[attack], seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate()

        lines = output.strip().split("\n")

        # Find attack IP
        attack_ip = None
        for line in lines:
            if "192.168" in line:
                parts = line.split("from")
                if len(parts) > 1:
                    attack_ip = parts[1].split()[0]
                    break

        assert attack_ip is not None

        # Check for failures and success from same IP
        ip_lines = [line for line in lines if attack_ip in line]
        failed = [line for line in ip_lines if "Failed password" in line]
        accepted = [line for line in ip_lines if "Accepted password" in line]

        # Should have failures followed by success
        assert len(failed) > 0
        assert len(accepted) > 0

    def test_recon_pattern(self):
        """Test reconnaissance attack pattern."""
        attack = AttackConfig(
            profile=AttackProfile.RECON,
            ratio=0.3,
            ips_count=5,
            attempts_per_ip=10
        )
        config = GeneratorConfig(entries=150, attack_profiles=[attack], seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate()

        lines = output.strip().split("\n")
        invalid_user_lines = [line for line in lines if "Invalid user" in line]

        # Should have invalid user attempts
        assert len(invalid_user_lines) > 0

    def test_multiple_attack_profiles(self):
        """Test generating multiple attack profiles simultaneously."""
        attacks = [
            AttackConfig(profile=AttackProfile.BRUTE_FORCE, ratio=0.2),
            AttackConfig(profile=AttackProfile.BOTNET, ratio=0.1, ips_count=10),
            AttackConfig(profile=AttackProfile.BREACH, ratio=0.1),
        ]
        config = GeneratorConfig(entries=200, attack_profiles=attacks, seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate()

        lines = output.strip().split("\n")

        # Should have at least some lines
        # Note: actual count depends on attack execution rounding
        assert len(lines) >= 100

    def test_attack_ratio_validation(self):
        """Test that total attack ratio cannot exceed 1.0."""
        attacks = [
            AttackConfig(profile=AttackProfile.BRUTE_FORCE, ratio=0.6),
            AttackConfig(profile=AttackProfile.BOTNET, ratio=0.5),
        ]
        config = GeneratorConfig(entries=100, attack_profiles=attacks)
        gen = SyntheticLogGenerator(config)

        with pytest.raises(ValueError, match="Sum of attack ratios exceeds 1.0"):
            gen.generate()

    def test_auth_log_format(self):
        """Test auth.log format output."""
        config = GeneratorConfig(entries=10, seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate(format_type="auth.log")

        lines = output.strip().split("\n")

        # Should have syslog timestamp format
        for line in lines:
            assert "sshd[" in line
            assert "from" in line
            # Should start with month
            assert line.split()[0] in ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    def test_secure_format(self):
        """Test secure log format output (same as auth.log)."""
        config = GeneratorConfig(entries=10, seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate(format_type="secure")

        lines = output.strip().split("\n")

        # Should have same format as auth.log
        for line in lines:
            assert "sshd[" in line
            assert "from" in line

    def test_journald_format(self):
        """Test journald JSON format output."""
        config = GeneratorConfig(entries=10, seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate(format_type="journald")

        lines = output.strip().split("\n")

        # Should be valid JSON
        for line in lines:
            data = json.loads(line)
            assert "__REALTIME_TIMESTAMP" in data
            assert "_PID" in data
            assert "SYSLOG_IDENTIFIER" in data
            assert "MESSAGE" in data

    def test_generate_to_file(self):
        """Test generating to a file."""
        config = GeneratorConfig(entries=50, seed=42)
        gen = SyntheticLogGenerator(config)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
            temp_path = f.name

        try:
            gen.generate_to_file(temp_path, format_type="auth.log")

            # Verify file exists and has content
            assert os.path.exists(temp_path)
            with open(temp_path, "r") as f:
                content = f.read()
                lines = content.strip().split("\n")
                assert len(lines) == 50
        finally:
            os.unlink(temp_path)

    def test_parseable_by_auth_log_parser(self):
        """Test that generated auth.log is parseable by AuthLogParser."""
        attack = AttackConfig(profile=AttackProfile.BRUTE_FORCE, ratio=0.3)
        config = GeneratorConfig(entries=100, attack_profiles=[attack], seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate(format_type="auth.log")

        # Parse with AuthLogParser
        parser = AuthLogParser()
        result = parser.parse(output)

        # Should parse without errors
        assert len(result.parse_errors) == 0
        assert len(result.events) > 0
        assert result.format_type == "auth.log"

    def test_parseable_by_secure_parser(self):
        """Test that generated secure log is parseable by SecureLogParser."""
        config = GeneratorConfig(entries=50, seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate(format_type="secure")

        # Parse with SecureLogParser
        parser = SecureLogParser()
        result = parser.parse(output)

        # Should parse without errors
        assert len(result.parse_errors) == 0
        assert len(result.events) > 0
        assert result.format_type == "secure"

    def test_parseable_by_journald_parser(self):
        """Test that generated journald log is parseable by JournaldParser."""
        attack = AttackConfig(profile=AttackProfile.RECON, ratio=0.2, ips_count=5)
        config = GeneratorConfig(entries=80, attack_profiles=[attack], seed=42)
        gen = SyntheticLogGenerator(config)
        output = gen.generate(format_type="journald")

        # Parse with JournaldParser
        parser = JournaldParser()
        result = parser.parse(output)

        # Should parse without errors
        assert len(result.parse_errors) == 0
        assert len(result.events) > 0
        assert result.format_type == "journald"

    def test_all_attack_profiles_parseable(self):
        """Test that all attack profiles generate parseable logs."""
        for profile in [AttackProfile.BRUTE_FORCE, AttackProfile.BOTNET,
                       AttackProfile.CREDENTIAL_STUFFING, AttackProfile.LOW_AND_SLOW,
                       AttackProfile.BREACH, AttackProfile.RECON]:

            attack = AttackConfig(profile=profile, ratio=0.5)
            config = GeneratorConfig(entries=50, attack_profiles=[attack], seed=42)
            gen = SyntheticLogGenerator(config)
            output = gen.generate()

            parser = AuthLogParser()
            result = parser.parse(output)

            # All should parse without errors
            assert len(result.parse_errors) == 0, f"Profile {profile} failed to parse"
            assert len(result.events) > 0, f"Profile {profile} generated no events"
