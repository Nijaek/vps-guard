"""Tests for report generators."""

import json
from datetime import datetime
from pathlib import Path
import tempfile

import pytest

from vpsguard.models.events import (
    AnalysisReport,
    RuleViolation,
    Severity,
    AuthEvent,
    EventType,
)
from vpsguard.reporters import (
    TerminalReporter,
    MarkdownReporter,
    JSONReporter,
    get_reporter,
)


@pytest.fixture
def sample_violation():
    """Create a sample rule violation for testing."""
    return RuleViolation(
        rule_name="Brute Force Attack",
        severity=Severity.HIGH,
        ip="192.168.1.100",
        description="Multiple failed login attempts detected",
        timestamp=datetime(2024, 12, 30, 3, 15, 0),
        details={
            "failed_attempts": 25,
            "time_window": "60 minutes",
            "target_user": "admin",
        },
        affected_events=[
            AuthEvent(
                timestamp=datetime(2024, 12, 30, 3, 0, 0),
                event_type=EventType.FAILED_LOGIN,
                ip="192.168.1.100",
                username="admin",
                success=False,
                raw_line="test line",
            )
        ],
    )


@pytest.fixture
def sample_critical_violation():
    """Create a critical severity violation."""
    return RuleViolation(
        rule_name="Successful Breach",
        severity=Severity.CRITICAL,
        ip="45.33.32.156",
        description="Successful login after multiple failures",
        timestamp=datetime(2024, 12, 30, 3, 12, 47),
        details={
            "failed_attempts": 31,
            "pattern": "31 failed attempts → successful login",
        },
        affected_events=[],
    )


@pytest.fixture
def sample_report(sample_violation, sample_critical_violation):
    """Create a sample analysis report for testing."""
    return AnalysisReport(
        timestamp=datetime(2024, 12, 30, 3, 47, 0),
        log_source="/var/log/auth.log",
        total_events=48291,
        rule_violations=[sample_critical_violation, sample_violation],
        anomalies=[],
        baseline_drift=None,
        summary=None,
    )


@pytest.fixture
def empty_report():
    """Create an empty analysis report."""
    return AnalysisReport(
        timestamp=datetime(2024, 12, 30, 3, 47, 0),
        log_source="/var/log/auth.log",
        total_events=1000,
        rule_violations=[],
        anomalies=[],
        baseline_drift=None,
        summary=None,
    )


class TestTerminalReporter:
    """Tests for TerminalReporter."""

    def test_generate_report(self, sample_report):
        """Test generating terminal report as string."""
        reporter = TerminalReporter()
        output = reporter.generate(sample_report)

        # Check that output contains key elements
        assert "VPSGUARD SECURITY REPORT" in output
        assert "2024-12-30" in output
        assert "CRITICAL: 1" in output
        assert "HIGH: 1" in output
        assert "Scanned: 48,291" in output
        assert "Successful Breach" in output
        assert "Brute Force Attack" in output

    def test_generate_empty_report(self, empty_report):
        """Test generating report with no violations."""
        reporter = TerminalReporter()
        output = reporter.generate(empty_report)

        assert "VPSGUARD SECURITY REPORT" in output
        assert "No security violations detected" in output

    def test_generate_to_file(self, sample_report):
        """Test writing report to file."""
        reporter = TerminalReporter()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            temp_path = f.name

        try:
            reporter.generate_to_file(sample_report, temp_path)

            # Read back and verify with UTF-8 encoding
            content = Path(temp_path).read_text(encoding='utf-8')
            assert "VPSGUARD SECURITY REPORT" in content
            assert "Successful Breach" in content
        finally:
            Path(temp_path).unlink()

    def test_max_per_severity(self, sample_violation):
        """Test limiting violations per severity level."""
        # Create report with many violations
        violations = [sample_violation] * 20
        report = AnalysisReport(
            timestamp=datetime(2024, 12, 30, 3, 47, 0),
            log_source="/var/log/auth.log",
            total_events=1000,
            rule_violations=violations,
            anomalies=[],
        )

        reporter = TerminalReporter(max_per_severity=5)
        output = reporter.generate(report)

        # Should mention there are more violations
        assert "... and 15 more high findings" in output


class TestMarkdownReporter:
    """Tests for MarkdownReporter."""

    def test_generate_report(self, sample_report):
        """Test generating markdown report."""
        reporter = MarkdownReporter()
        output = reporter.generate(sample_report)

        # Check markdown structure
        assert "# VPSGuard Security Report" in output
        assert "## Summary" in output
        assert "| Severity | Count |" in output
        assert "## Critical Findings" in output
        assert "## High Findings" in output
        assert "### Successful Breach" in output
        assert "### Brute Force Attack" in output
        assert "**IP:** 45.33.32.156" in output
        assert "**IP:** 192.168.1.100" in output

    def test_generate_empty_report(self, empty_report):
        """Test generating markdown report with no violations."""
        reporter = MarkdownReporter()
        output = reporter.generate(empty_report)

        assert "# VPSGuard Security Report" in output
        assert "## Summary" in output
        assert "No security violations detected" in output

    def test_severity_counts(self, sample_report):
        """Test severity counts in summary table."""
        reporter = MarkdownReporter()
        output = reporter.generate(sample_report)

        # Check that severity counts are correct
        lines = output.split('\n')
        for line in lines:
            if "| Critical |" in line:
                assert "| 1 |" in line
            elif "| High |" in line:
                assert "| 1 |" in line
            elif "| Medium |" in line:
                assert "| 0 |" in line
            elif "| Low |" in line:
                assert "| 0 |" in line

    def test_generate_to_file(self, sample_report):
        """Test writing markdown report to file."""
        reporter = MarkdownReporter()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
            temp_path = f.name

        try:
            reporter.generate_to_file(sample_report, temp_path)

            # Read back and verify
            content = Path(temp_path).read_text()
            assert "# VPSGuard Security Report" in content
            assert "### Successful Breach" in content
        finally:
            Path(temp_path).unlink()


class TestJSONReporter:
    """Tests for JSONReporter."""

    def test_generate_report(self, sample_report):
        """Test generating JSON report."""
        reporter = JSONReporter()
        output = reporter.generate(sample_report)

        # Parse JSON to verify structure
        data = json.loads(output)

        assert "metadata" in data
        assert data["metadata"]["log_source"] == "/var/log/auth.log"
        assert data["metadata"]["total_events"] == 48291

        assert "summary" in data
        assert data["summary"]["total_violations"] == 2
        assert data["summary"]["severity_counts"]["critical"] == 1
        assert data["summary"]["severity_counts"]["high"] == 1

        assert "rule_violations" in data
        assert len(data["rule_violations"]) == 2

        # Check violation details
        violations = {v["rule_name"]: v for v in data["rule_violations"]}
        assert "Successful Breach" in violations
        assert violations["Successful Breach"]["severity"] == "critical"
        assert violations["Successful Breach"]["ip"] == "45.33.32.156"

        assert "Brute Force Attack" in violations
        assert violations["Brute Force Attack"]["severity"] == "high"
        assert violations["Brute Force Attack"]["ip"] == "192.168.1.100"

    def test_generate_empty_report(self, empty_report):
        """Test generating JSON report with no violations."""
        reporter = JSONReporter()
        output = reporter.generate(empty_report)

        data = json.loads(output)
        assert data["summary"]["total_violations"] == 0
        assert data["rule_violations"] == []

    def test_compact_json(self, sample_report):
        """Test generating compact JSON (no indentation)."""
        reporter = JSONReporter(indent=None)
        output = reporter.generate(sample_report)

        # Compact JSON should not have newlines (except in strings)
        data = json.loads(output)
        assert data["metadata"]["total_events"] == 48291

    def test_generate_to_file(self, sample_report):
        """Test writing JSON report to file."""
        reporter = JSONReporter()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = f.name

        try:
            reporter.generate_to_file(sample_report, temp_path)

            # Read back and verify
            content = Path(temp_path).read_text()
            data = json.loads(content)
            assert data["summary"]["total_violations"] == 2
        finally:
            Path(temp_path).unlink()


class TestGetReporter:
    """Tests for get_reporter function."""

    def test_get_terminal_reporter(self):
        """Test getting terminal reporter."""
        reporter = get_reporter("terminal")
        assert isinstance(reporter, TerminalReporter)
        assert reporter.name == "terminal"

    def test_get_markdown_reporter(self):
        """Test getting markdown reporter."""
        reporter = get_reporter("markdown")
        assert isinstance(reporter, MarkdownReporter)
        assert reporter.name == "markdown"

    def test_get_json_reporter(self):
        """Test getting JSON reporter."""
        reporter = get_reporter("json")
        assert isinstance(reporter, JSONReporter)
        assert reporter.name == "json"

    def test_get_unknown_reporter_defaults_to_terminal(self):
        """Test that unknown format defaults to terminal."""
        reporter = get_reporter("unknown")
        assert isinstance(reporter, TerminalReporter)

    def test_get_reporter_empty_string(self):
        """Test that empty string defaults to terminal."""
        reporter = get_reporter("")
        assert isinstance(reporter, TerminalReporter)
