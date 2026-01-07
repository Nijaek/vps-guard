"""Tests for CLI commands."""

import json
import tempfile
from pathlib import Path
from typer.testing import CliRunner
import pytest

from vpsguard.cli import app

runner = CliRunner()


class TestParseCommand:
    """Tests for the parse command."""

    def test_parse_auth_log_file(self):
        """Test parsing an auth.log file."""
        # Create a temporary auth.log file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n")
            f.write("Jan 15 03:12:48 server sshd[1235]: Accepted password for ubuntu from 10.0.0.1 port 22346 ssh2\n")
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file])
            assert result.exit_code == 0
            assert "Parsed Events" in result.stdout or "192.168.1.100" in result.stdout
        finally:
            Path(temp_file).unlink()

    def test_parse_with_stats(self):
        """Test parsing with statistics."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n")
            f.write("Jan 15 03:12:48 server sshd[1235]: Accepted password for ubuntu from 10.0.0.1 port 22346 ssh2\n")
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file, "--stats"])
            assert result.exit_code == 0
            assert "Statistics" in result.stdout or "Total Events" in result.stdout
        finally:
            Path(temp_file).unlink()

    def test_parse_json_output(self):
        """Test parsing with JSON output."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n")
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file, "--format", "json"])
            assert result.exit_code == 0
            # Should be valid JSON
            output = json.loads(result.stdout)
            assert "total_events" in output
            assert "events" in output
            assert len(output["events"]) > 0
        finally:
            Path(temp_file).unlink()

    def test_parse_json_with_stats(self):
        """Test parsing with JSON output and statistics."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n")
            f.write("Jan 15 03:12:48 server sshd[1235]: Accepted password for ubuntu from 10.0.0.1 port 22346 ssh2\n")
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file, "--format", "json", "--stats"])
            assert result.exit_code == 0
            output = json.loads(result.stdout)
            assert "statistics" in output
            assert "unique_ips" in output["statistics"]
            assert "unique_users" in output["statistics"]
        finally:
            Path(temp_file).unlink()

    def test_parse_stdin(self):
        """Test parsing from stdin."""
        log_content = "Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n"
        result = runner.invoke(app, ["parse", "-"], input=log_content)
        assert result.exit_code == 0

    def test_parse_with_input_format(self):
        """Test parsing with explicit input format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n")
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file, "--input-format", "auth.log"])
            assert result.exit_code == 0
        finally:
            Path(temp_file).unlink()

    def test_parse_secure_format(self):
        """Test parsing secure log format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n")
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file, "--input-format", "secure"])
            assert result.exit_code == 0
        finally:
            Path(temp_file).unlink()

    def test_parse_journald_format(self):
        """Test parsing journald (JSON) format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"__REALTIME_TIMESTAMP": "1234567890", "_PID": "1234", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "Failed password for root from 192.168.1.100 port 22345 ssh2", "_HOSTNAME": "server"}\n')
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file, "--input-format", "journald"])
            assert result.exit_code == 0
        finally:
            Path(temp_file).unlink()

    def test_parse_file_not_found(self):
        """Test error handling for missing file."""
        result = runner.invoke(app, ["parse", "/nonexistent/file.log"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower() or "error" in result.stdout.lower()

    def test_parse_invalid_format(self):
        """Test error handling for invalid format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n")
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file, "--input-format", "invalid"])
            assert result.exit_code == 1
        finally:
            Path(temp_file).unlink()

    def test_parse_auto_detect_auth_log(self):
        """Test auto-detection of auth.log format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='auth.log', delete=False) as f:
            f.write("Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n")
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file])
            assert result.exit_code == 0
            assert "auth.log" in result.stdout
        finally:
            Path(temp_file).unlink()

    def test_parse_auto_detect_secure(self):
        """Test auto-detection of secure log format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='secure', delete=False) as f:
            f.write("Jan 15 03:12:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2\n")
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file])
            assert result.exit_code == 0
            assert "secure" in result.stdout
        finally:
            Path(temp_file).unlink()

    def test_parse_auto_detect_journald(self):
        """Test auto-detection of journald (JSON) format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"__REALTIME_TIMESTAMP": "1234567890", "_PID": "1234", "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "Failed password for root from 192.168.1.100 port 22345 ssh2", "_HOSTNAME": "server"}\n')
            temp_file = f.name

        try:
            result = runner.invoke(app, ["parse", temp_file])
            assert result.exit_code == 0
            assert "journald" in result.stdout
        finally:
            Path(temp_file).unlink()


class TestGenerateCommand:
    """Tests for the generate command."""

    def test_generate_basic(self):
        """Test basic log generation to stdout."""
        result = runner.invoke(app, ["generate", "--entries", "10"])
        assert result.exit_code == 0
        # Should have some log output
        assert len(result.stdout) > 0
        # Should have multiple lines
        assert result.stdout.count('\n') >= 10

    def test_generate_to_file(self):
        """Test generating logs to a file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            temp_file = f.name

        try:
            result = runner.invoke(app, ["generate", "--entries", "100", "--output", temp_file])
            assert result.exit_code == 0
            assert "Generated" in result.stdout
            assert Path(temp_file).exists()

            # Check file content
            content = Path(temp_file).read_text()
            assert len(content) > 0
            # Note: 100 entries means 100 log lines, but count('\n') may be 99 or 100
            # depending on trailing newline handling
            assert content.count('\n') >= 99
        finally:
            if Path(temp_file).exists():
                Path(temp_file).unlink()

    def test_generate_with_seed(self):
        """Test reproducibility with seed.

        Note: The generator uses datetime.now() for time range when not specified,
        so we test that the structure/content is deterministic, not exact byte match.
        With the same seed, IPs, usernames, and event types should be identical.
        """
        import re

        result1 = runner.invoke(app, ["generate", "--entries", "50", "--seed", "42"])
        result2 = runner.invoke(app, ["generate", "--entries", "50", "--seed", "42"])

        assert result1.exit_code == 0
        assert result2.exit_code == 0

        # Parse lines and compare everything except timestamps
        lines1 = result1.stdout.strip().split('\n')
        lines2 = result2.stdout.strip().split('\n')

        assert len(lines1) == len(lines2), "Same seed should produce same number of lines"

        # Extract non-timestamp parts (IP, username, event type)
        # Format: "Dec 30 14:58:20 server sshd[10105]: Accepted publickey for www-data from 10.116.148.253 port 53861 ssh2"
        # Use regex to extract the message after "sshd[pid]: " which is deterministic with seed
        # This handles variable timestamp formats and single-digit days with double spaces
        sshd_pattern = re.compile(r'sshd\[\d+\]: (.+)$')

        for l1, l2 in zip(lines1, lines2):
            match1 = sshd_pattern.search(l1)
            match2 = sshd_pattern.search(l2)
            if match1 and match2:
                # Compare the message content after "sshd[pid]: "
                assert match1.group(1) == match2.group(1), f"Content mismatch with same seed: {match1.group(1)} != {match2.group(1)}"

    def test_generate_with_attack_profile(self):
        """Test generation with attack profile."""
        result = runner.invoke(app, ["generate", "--entries", "100", "--attack-profile", "botnet:0.1"])
        assert result.exit_code == 0
        assert len(result.stdout) > 0

    def test_generate_with_multiple_attack_profiles(self):
        """Test generation with multiple attack profiles."""
        result = runner.invoke(app, [
            "generate",
            "--entries", "200",
            "--attack-profile", "botnet:0.05",
            "--attack-profile", "breach:0.02"
        ])
        assert result.exit_code == 0
        assert len(result.stdout) > 0

    def test_generate_journald_format(self):
        """Test generation in journald (JSON) format."""
        result = runner.invoke(app, ["generate", "--entries", "10", "--format", "journald"])
        assert result.exit_code == 0
        # Should be JSON lines
        lines = result.stdout.strip().split('\n')
        for line in lines[:5]:  # Check first few lines
            try:
                json.loads(line)
            except json.JSONDecodeError:
                pytest.fail(f"Invalid JSON line: {line}")

    def test_generate_secure_format(self):
        """Test generation in secure log format."""
        result = runner.invoke(app, ["generate", "--entries", "10", "--format", "secure"])
        assert result.exit_code == 0
        assert len(result.stdout) > 0

    def test_generate_invalid_attack_profile_format(self):
        """Test error handling for invalid attack profile format."""
        result = runner.invoke(app, ["generate", "--entries", "100", "--attack-profile", "botnet"])
        assert result.exit_code == 1
        assert "Invalid attack profile format" in result.stdout or "Error" in result.stdout

    def test_generate_unknown_attack_profile(self):
        """Test error handling for unknown attack profile."""
        result = runner.invoke(app, ["generate", "--entries", "100", "--attack-profile", "unknown:0.1"])
        assert result.exit_code == 1
        assert "Unknown attack profile" in result.stdout or "Error" in result.stdout

    def test_generate_invalid_ratio(self):
        """Test error handling for invalid ratio."""
        result = runner.invoke(app, ["generate", "--entries", "100", "--attack-profile", "botnet:invalid"])
        assert result.exit_code == 1
        assert "Invalid ratio" in result.stdout or "Error" in result.stdout

    def test_generate_all_attack_profiles(self):
        """Test generation with all attack profile types."""
        profiles = ["brute:0.05", "botnet:0.05", "stuffing:0.05", "low-slow:0.02", "breach:0.02", "recon:0.03"]
        result = runner.invoke(app, [
            "generate",
            "--entries", "500",
            *[f"--attack-profile={p}" for p in profiles]
        ])
        assert result.exit_code == 0

    def test_generate_brute_force_profile(self):
        """Test brute force attack profile."""
        result = runner.invoke(app, ["generate", "--entries", "100", "--attack-profile", "brute:0.2"])
        assert result.exit_code == 0

    def test_generate_credential_stuffing_profile(self):
        """Test credential stuffing attack profile."""
        result = runner.invoke(app, ["generate", "--entries", "100", "--attack-profile", "credential_stuffing:0.15"])
        assert result.exit_code == 0


class TestInitCommand:
    """Tests for the init command."""

    def test_init_default(self):
        """Test creating default config file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "vpsguard.toml"
            result = runner.invoke(app, ["init", "--output", str(config_path)])

            assert result.exit_code == 0
            assert "Created configuration file" in result.stdout
            assert config_path.exists()

            # Check content
            content = config_path.read_text()
            assert "[rules.brute_force]" in content
            assert "[rules.breach_detection]" in content
            assert "[rules.quiet_hours]" in content
            assert "[whitelist]" in content
            assert "[output]" in content

    def test_init_custom_path(self):
        """Test creating config file with custom path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "custom-config.toml"
            result = runner.invoke(app, ["init", "--output", str(config_path)])

            assert result.exit_code == 0
            assert config_path.exists()

    def test_init_no_overwrite(self):
        """Test that init won't overwrite existing file without --force."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "vpsguard.toml"

            # Create file first
            config_path.write_text("existing content")

            result = runner.invoke(app, ["init", "--output", str(config_path)])

            assert result.exit_code == 1
            assert "already exists" in result.stdout
            # Original content should be preserved
            assert config_path.read_text() == "existing content"

    def test_init_force_overwrite(self):
        """Test that init can overwrite with --force flag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "vpsguard.toml"

            # Create file first
            config_path.write_text("existing content")

            result = runner.invoke(app, ["init", "--output", str(config_path), "--force"])

            assert result.exit_code == 0
            assert "Created configuration file" in result.stdout
            # Content should be new config
            content = config_path.read_text()
            assert "[rules.brute_force]" in content
            assert "existing content" not in content

    def test_init_shows_next_steps(self):
        """Test that init shows helpful next steps."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "vpsguard.toml"
            result = runner.invoke(app, ["init", "--output", str(config_path)])

            assert result.exit_code == 0
            assert "Next steps" in result.stdout
            assert "parse" in result.stdout.lower()
            assert "generate" in result.stdout.lower()


class TestCLIIntegration:
    """Integration tests for CLI commands working together."""

    def test_generate_and_parse_roundtrip(self):
        """Test generating logs and then parsing them."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.log"

            # Generate logs
            result_gen = runner.invoke(app, [
                "generate",
                "--entries", "100",
                "--attack-profile", "botnet:0.1",
                "--output", str(log_file),
                "--seed", "42"
            ])
            assert result_gen.exit_code == 0

            # Parse logs
            result_parse = runner.invoke(app, ["parse", str(log_file), "--stats"])
            assert result_parse.exit_code == 0
            assert "Statistics" in result_parse.stdout or "Total Events" in result_parse.stdout

    def test_generate_and_parse_json_roundtrip(self):
        """Test generating and parsing journald (JSON) logs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.json"

            # Generate logs
            result_gen = runner.invoke(app, [
                "generate",
                "--entries", "50",
                "--format", "journald",
                "--output", str(log_file)
            ])
            assert result_gen.exit_code == 0

            # Parse logs
            result_parse = runner.invoke(app, [
                "parse",
                str(log_file),
                "--input-format", "journald",
                "--format", "json"
            ])
            assert result_parse.exit_code == 0
            output = json.loads(result_parse.stdout)
            assert output["total_events"] > 0

    def test_init_and_verify_config(self):
        """Test init creates valid TOML config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "vpsguard.toml"

            # Create config
            result = runner.invoke(app, ["init", "--output", str(config_path)])
            assert result.exit_code == 0

            # Verify it's valid TOML by trying to parse it
            try:
                import tomllib
            except ImportError:
                import tomli as tomllib

            content = config_path.read_text()
            config = tomllib.loads(content)

            # Verify structure
            assert "rules" in config
            assert "brute_force" in config["rules"]
            assert "breach_detection" in config["rules"]
            assert "quiet_hours" in config["rules"]
            assert "whitelist" in config
            assert "output" in config
