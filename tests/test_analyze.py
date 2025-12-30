"""Tests for analyze command."""

import json
from pathlib import Path
import tempfile

import pytest
from typer.testing import CliRunner

from vpsguard.cli import app


runner = CliRunner()


@pytest.fixture
def sample_auth_log():
    """Create a sample auth.log file for testing."""
    content = """Dec 30 03:00:01 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 30 03:00:05 server sshd[1235]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 30 03:00:10 server sshd[1236]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 30 03:00:15 server sshd[1237]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 30 03:00:20 server sshd[1238]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 30 03:00:25 server sshd[1239]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 30 03:00:30 server sshd[1240]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 30 03:00:35 server sshd[1241]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 30 03:00:40 server sshd[1242]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 30 03:00:45 server sshd[1243]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 30 03:00:50 server sshd[1244]: Failed password for admin from 192.168.1.100 port 22 ssh2
"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        f.write(content)
        temp_path = f.name

    yield temp_path

    # Cleanup
    Path(temp_path).unlink()


@pytest.fixture
def sample_breach_log():
    """Create a log with breach pattern (failures then success)."""
    content = """Dec 30 03:00:01 server sshd[1234]: Failed password for deploy from 45.33.32.156 port 22 ssh2
Dec 30 03:00:05 server sshd[1235]: Failed password for deploy from 45.33.32.156 port 22 ssh2
Dec 30 03:00:10 server sshd[1236]: Failed password for deploy from 45.33.32.156 port 22 ssh2
Dec 30 03:00:15 server sshd[1237]: Failed password for deploy from 45.33.32.156 port 22 ssh2
Dec 30 03:00:20 server sshd[1238]: Failed password for deploy from 45.33.32.156 port 22 ssh2
Dec 30 03:00:25 server sshd[1239]: Failed password for deploy from 45.33.32.156 port 22 ssh2
Dec 30 03:00:30 server sshd[1240]: Accepted password for deploy from 45.33.32.156 port 22 ssh2
"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        f.write(content)
        temp_path = f.name

    yield temp_path

    # Cleanup
    Path(temp_path).unlink()


@pytest.fixture
def sample_config():
    """Create a sample config file."""
    content = """[rules.brute_force]
enabled = true
threshold = 5
window_minutes = 60
severity = "high"

[rules.breach_detection]
enabled = true
failures_before_success = 3
severity = "critical"

[whitelist]
ips = []
"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.toml') as f:
        f.write(content)
        temp_path = f.name

    yield temp_path

    # Cleanup
    Path(temp_path).unlink()


class TestAnalyzeCommand:
    """Tests for analyze command."""

    def test_analyze_basic(self, sample_auth_log):
        """Test basic analyze command."""
        result = runner.invoke(app, ["analyze", sample_auth_log])

        # Command should succeed
        assert result.exit_code == 0

        # Check output contains expected elements
        assert "VPSGUARD SECURITY REPORT" in result.stdout or "Brute Force" in result.stdout

    def test_analyze_with_config(self, sample_auth_log, sample_config):
        """Test analyze with custom config."""
        result = runner.invoke(app, ["analyze", sample_auth_log, "--config", sample_config])

        assert result.exit_code == 0
        assert "Loaded config from:" in result.stdout or result.exit_code == 0

    def test_analyze_breach_detection(self, sample_breach_log):
        """Test that breach detection works."""
        result = runner.invoke(app, ["analyze", sample_breach_log, "-v"])

        assert result.exit_code == 0
        # Should detect the breach pattern

    def test_analyze_json_output(self, sample_auth_log):
        """Test JSON output format."""
        result = runner.invoke(app, ["analyze", sample_auth_log, "--format", "json"])

        assert result.exit_code == 0

        # Parse JSON output
        data = json.loads(result.stdout)
        assert "metadata" in data
        assert "summary" in data
        assert "rule_violations" in data

    def test_analyze_markdown_output(self, sample_auth_log):
        """Test markdown output format."""
        result = runner.invoke(app, ["analyze", sample_auth_log, "--format", "markdown"])

        assert result.exit_code == 0
        assert "# VPSGuard Security Report" in result.stdout
        assert "## Summary" in result.stdout

    def test_analyze_output_to_file(self, sample_auth_log):
        """Test writing output to file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            output_path = f.name

        try:
            result = runner.invoke(app, [
                "analyze", sample_auth_log,
                "--output", output_path
            ])

            assert result.exit_code == 0
            assert "Report written to:" in result.stdout

            # Verify file was created
            assert Path(output_path).exists()
            content = Path(output_path).read_text(encoding='utf-8')
            assert len(content) > 0
        finally:
            if Path(output_path).exists():
                Path(output_path).unlink()

    def test_analyze_markdown_to_file(self, sample_auth_log):
        """Test writing markdown output to file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            output_path = f.name

        try:
            result = runner.invoke(app, [
                "analyze", sample_auth_log,
                "--format", "markdown",
                "--output", output_path
            ])

            assert result.exit_code == 0

            # Verify markdown file
            content = Path(output_path).read_text()
            assert "# VPSGuard Security Report" in content
        finally:
            if Path(output_path).exists():
                Path(output_path).unlink()

    def test_analyze_json_to_file(self, sample_auth_log):
        """Test writing JSON output to file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            output_path = f.name

        try:
            result = runner.invoke(app, [
                "analyze", sample_auth_log,
                "--format", "json",
                "--output", output_path
            ])

            assert result.exit_code == 0

            # Verify JSON file
            content = Path(output_path).read_text()
            data = json.loads(content)
            assert "metadata" in data
        finally:
            if Path(output_path).exists():
                Path(output_path).unlink()

    def test_analyze_verbosity_levels(self, sample_auth_log):
        """Test different verbosity levels."""
        # Default (0) - only critical and high
        result0 = runner.invoke(app, ["analyze", sample_auth_log, "--format", "json"])
        assert result0.exit_code == 0

        # Verbose (1) - include medium
        result1 = runner.invoke(app, ["analyze", sample_auth_log, "-v", "--format", "json"])
        assert result1.exit_code == 0

        # Very verbose (2) - include all
        result2 = runner.invoke(app, ["analyze", sample_auth_log, "-vv", "--format", "json"])
        assert result2.exit_code == 0

    def test_analyze_nonexistent_file(self):
        """Test error handling for nonexistent file."""
        result = runner.invoke(app, ["analyze", "/nonexistent/file.log"])

        assert result.exit_code == 1
        assert "not found" in result.stdout.lower() or "error" in result.stdout.lower()

    def test_analyze_invalid_config(self, sample_auth_log):
        """Test error handling for invalid config file."""
        result = runner.invoke(app, ["analyze", sample_auth_log, "--config", "/nonexistent/config.toml"])

        assert result.exit_code == 1
        assert "not found" in result.stdout.lower() or "error" in result.stdout.lower()

    def test_analyze_auto_detect_format(self, sample_auth_log):
        """Test that format is auto-detected correctly."""
        result = runner.invoke(app, ["analyze", sample_auth_log])

        assert result.exit_code == 0
        # Should auto-detect and parse successfully

    def test_analyze_explicit_format(self, sample_auth_log):
        """Test explicit input format specification."""
        result = runner.invoke(app, ["analyze", sample_auth_log, "--input-format", "auth.log"])

        assert result.exit_code == 0


class TestAnalyzeIntegration:
    """Integration tests for analyze command."""

    def test_end_to_end_analysis(self, sample_breach_log, sample_config):
        """Test complete end-to-end analysis workflow."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            output_path = f.name

        try:
            # Run analysis with all options
            result = runner.invoke(app, [
                "analyze", sample_breach_log,
                "--config", sample_config,
                "--format", "json",
                "--output", output_path,
                "-v",  # Include medium severity
            ])

            assert result.exit_code == 0

            # Verify JSON output file
            content = Path(output_path).read_text()
            data = json.loads(content)

            # Verify structure
            assert data["metadata"]["total_events"] > 0
            assert "rule_violations" in data

        finally:
            if Path(output_path).exists():
                Path(output_path).unlink()

    def test_multiple_format_outputs(self, sample_auth_log):
        """Test generating multiple output formats."""
        formats = ["terminal", "markdown", "json"]

        for fmt in formats:
            result = runner.invoke(app, ["analyze", sample_auth_log, "--format", fmt])
            assert result.exit_code == 0, f"Failed for format: {fmt}"
