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
from vpsguard.reporters.html import HTMLReporter
from vpsguard.models.events import AnomalyResult, Confidence
from vpsguard.geo.reader import GeoLocation


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

    def test_get_html_reporter(self):
        """Test getting HTML reporter."""
        reporter = get_reporter("html")
        assert isinstance(reporter, HTMLReporter)
        assert reporter.name == "html"


class TestHTMLReporter:
    """Tests for HTMLReporter."""

    def test_generate_report(self, sample_report):
        """Test generating HTML report."""
        reporter = HTMLReporter()
        output = reporter.generate(sample_report)

        # Check HTML structure
        assert "<!DOCTYPE html>" in output
        assert "<html lang=\"en\">" in output
        assert "VPSGuard Security Report" in output
        assert "</html>" in output

        # Check CSS is embedded
        assert "<style>" in output
        assert "</style>" in output

        # Check JavaScript is embedded
        assert "<script>" in output
        assert "filterFindings" in output

        # Check report content
        assert "2024-12-30" in output
        assert "48,291" in output  # Total events formatted
        assert "Successful Breach" in output
        assert "Brute Force Attack" in output

        # Check severity counts in summary cards
        assert "Critical" in output
        assert "High" in output

    def test_generate_empty_report(self, empty_report):
        """Test generating HTML report with no violations."""
        reporter = HTMLReporter()
        output = reporter.generate(empty_report)

        assert "<!DOCTYPE html>" in output
        assert "No Rule Violations Detected" in output
        assert "No security violations were detected" in output

    def test_generate_to_file(self, sample_report):
        """Test writing HTML report to file."""
        reporter = HTMLReporter()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html') as f:
            temp_path = f.name

        try:
            reporter.generate_to_file(sample_report, temp_path)

            # Read back and verify
            content = Path(temp_path).read_text(encoding='utf-8')
            assert "<!DOCTYPE html>" in content
            assert "VPSGuard Security Report" in content
            assert "Successful Breach" in content
        finally:
            Path(temp_path).unlink()

    def test_severity_colors(self, sample_report):
        """Test that severity classes are applied correctly."""
        reporter = HTMLReporter()
        output = reporter.generate(sample_report)

        # Check severity-specific CSS classes
        assert 'class="finding-header critical"' in output
        assert 'class="finding-header high"' in output
        assert 'finding-badge critical' in output
        assert 'finding-badge high' in output

    def test_escape_html(self):
        """Test HTML escaping of special characters."""
        reporter = HTMLReporter()

        assert reporter._escape_html("<script>") == "&lt;script&gt;"
        assert reporter._escape_html("A & B") == "A &amp; B"
        assert reporter._escape_html('"quoted"') == "&quot;quoted&quot;"
        assert reporter._escape_html("it's") == "it&#39;s"
        assert reporter._escape_html(123) == "123"  # Non-string input

    def test_filter_controls(self, sample_report):
        """Test that filter controls are included."""
        reporter = HTMLReporter()
        output = reporter.generate(sample_report)

        # Check filter controls exist
        assert 'id="severity-filter"' in output
        assert 'id="ip-filter"' in output
        assert 'id="time-filter"' in output
        assert 'id="visible-count"' in output

    def test_report_with_anomalies(self, sample_report):
        """Test HTML report with ML anomalies."""
        # Create report with anomalies
        anomaly = AnomalyResult(
            ip="10.0.0.1",
            score=0.85,
            confidence=Confidence.HIGH,
            explanation=["High failure ratio", "Unusual username entropy"],
            features={"failure_ratio": 0.9, "username_entropy": 3.5},
        )
        report_with_anomalies = AnalysisReport(
            timestamp=sample_report.timestamp,
            log_source=sample_report.log_source,
            total_events=sample_report.total_events,
            rule_violations=sample_report.rule_violations,
            anomalies=[anomaly],
        )

        reporter = HTMLReporter()
        output = reporter.generate(report_with_anomalies)

        # Check anomaly section
        assert "ML Anomalies Detected" in output
        assert "10.0.0.1" in output
        assert "85%" in output  # Score percentage
        assert "High failure ratio" in output
        assert "Unusual username entropy" in output

    def test_report_with_baseline_drift(self, sample_report):
        """Test HTML report with baseline drift warning."""
        # Create report with drift
        report_with_drift = AnalysisReport(
            timestamp=sample_report.timestamp,
            log_source=sample_report.log_source,
            total_events=sample_report.total_events,
            rule_violations=sample_report.rule_violations,
            anomalies=[],
            baseline_drift={
                'drift_detected': True,
                'drifted_features': ['failure_ratio', 'username_entropy'],
            },
        )

        reporter = HTMLReporter()
        output = reporter.generate(report_with_drift)

        # Check drift warning
        assert "Baseline Drift Detected" in output
        assert "failure_ratio" in output
        assert "username_entropy" in output
        assert "Consider retraining" in output

    def test_report_with_geo_data(self, sample_violation, sample_critical_violation):
        """Test HTML report with GeoIP data."""
        geo_data = {
            "192.168.1.100": GeoLocation(country_code="US", country_name="United States", city="New York"),
            "45.33.32.156": GeoLocation(country_code="RU", country_name="Russia", city="Moscow"),
        }

        report = AnalysisReport(
            timestamp=datetime(2024, 12, 30, 3, 47, 0),
            log_source="/var/log/auth.log",
            total_events=1000,
            rule_violations=[sample_violation, sample_critical_violation],
            anomalies=[],
            geo_data=geo_data,
        )

        reporter = HTMLReporter()
        output = reporter.generate(report)

        # Check geo locations are displayed (format is "city, country_code")
        assert "New York, US" in output
        assert "Moscow, RU" in output
        assert "Location:" in output

    def test_finding_data_attributes(self, sample_report):
        """Test that findings have data attributes for filtering."""
        reporter = HTMLReporter()
        output = reporter.generate(sample_report)

        # Check data attributes for JavaScript filtering
        assert 'data-severity="critical"' in output
        assert 'data-severity="high"' in output
        assert 'data-ip="' in output
        assert 'data-time="' in output

    def test_responsive_meta_tag(self, sample_report):
        """Test that viewport meta tag is included for mobile."""
        reporter = HTMLReporter()
        output = reporter.generate(sample_report)

        assert 'name="viewport"' in output
        assert 'width=device-width' in output

    def test_all_severity_levels(self):
        """Test report with all severity levels."""
        violations = [
            RuleViolation(
                rule_name="Critical Issue",
                severity=Severity.CRITICAL,
                ip="1.1.1.1",
                description="Critical",
                timestamp=datetime.now(),
                details={},
                affected_events=[],
            ),
            RuleViolation(
                rule_name="High Issue",
                severity=Severity.HIGH,
                ip="2.2.2.2",
                description="High",
                timestamp=datetime.now(),
                details={},
                affected_events=[],
            ),
            RuleViolation(
                rule_name="Medium Issue",
                severity=Severity.MEDIUM,
                ip="3.3.3.3",
                description="Medium",
                timestamp=datetime.now(),
                details={},
                affected_events=[],
            ),
            RuleViolation(
                rule_name="Low Issue",
                severity=Severity.LOW,
                ip="4.4.4.4",
                description="Low",
                timestamp=datetime.now(),
                details={},
                affected_events=[],
            ),
        ]

        report = AnalysisReport(
            timestamp=datetime.now(),
            log_source="test.log",
            total_events=100,
            rule_violations=violations,
            anomalies=[],
        )

        reporter = HTMLReporter()
        output = reporter.generate(report)

        # Check all severity sections
        assert "Critical Findings (1)" in output
        assert "High Findings (1)" in output
        assert "Medium Findings (1)" in output
        assert "Low Findings (1)" in output

    def test_violation_details(self, sample_violation):
        """Test that violation details are rendered."""
        report = AnalysisReport(
            timestamp=datetime.now(),
            log_source="test.log",
            total_events=100,
            rule_violations=[sample_violation],
            anomalies=[],
        )

        reporter = HTMLReporter()
        output = reporter.generate(report)

        # Check details are rendered
        assert "Failed Attempts:" in output
        assert "25" in output
        assert "Time Window:" in output
        assert "60 minutes" in output
        assert "Target User:" in output
        assert "admin" in output


class TestJSONReporterWithGeoData:
    """Tests for JSONReporter with GeoIP data."""

    def test_report_with_geo_data(self, sample_violation, sample_critical_violation):
        """Test JSON report includes geo_data section."""
        geo_data = {
            "192.168.1.100": GeoLocation(
                country_code="US",
                country_name="United States",
                city="New York",
                latitude=40.7128,
                longitude=-74.0060,
            ),
            "45.33.32.156": GeoLocation(
                country_code="RU",
                country_name="Russia",
                city="Moscow",
                latitude=55.7558,
                longitude=37.6173,
            ),
        }

        report = AnalysisReport(
            timestamp=datetime(2024, 12, 30, 3, 47, 0),
            log_source="/var/log/auth.log",
            total_events=1000,
            rule_violations=[sample_violation, sample_critical_violation],
            anomalies=[],
            geo_data=geo_data,
        )

        reporter = JSONReporter()
        output = reporter.generate(report)
        data = json.loads(output)

        # Check geo_data section exists
        assert "geo_data" in data
        assert "192.168.1.100" in data["geo_data"]
        assert data["geo_data"]["192.168.1.100"]["country_code"] == "US"
        assert data["geo_data"]["192.168.1.100"]["country_name"] == "United States"
        assert data["geo_data"]["192.168.1.100"]["city"] == "New York"
        assert data["geo_data"]["192.168.1.100"]["latitude"] == 40.7128
        assert data["geo_data"]["192.168.1.100"]["longitude"] == -74.0060

        # Check metadata shows geoip_enabled
        assert data["metadata"]["geoip_enabled"] is True

    def test_violation_includes_location(self, sample_violation):
        """Test violations include location from geo_data."""
        geo_data = {
            "192.168.1.100": GeoLocation(
                country_code="US",
                country_name="United States",
                city="New York",
            ),
        }

        report = AnalysisReport(
            timestamp=datetime(2024, 12, 30, 3, 47, 0),
            log_source="/var/log/auth.log",
            total_events=1000,
            rule_violations=[sample_violation],
            anomalies=[],
            geo_data=geo_data,
        )

        reporter = JSONReporter()
        output = reporter.generate(report)
        data = json.loads(output)

        # Check violation has location
        violation = data["rule_violations"][0]
        assert "location" in violation
        assert "New York, US" in violation["location"]

    def test_anomaly_includes_location(self):
        """Test anomalies include location from geo_data."""
        anomaly = AnomalyResult(
            ip="10.0.0.1",
            score=0.85,
            confidence=Confidence.HIGH,
            explanation=["High failure ratio"],
            features={"failure_ratio": 0.9},
        )

        geo_data = {
            "10.0.0.1": GeoLocation(
                country_code="DE",
                country_name="Germany",
                city="Berlin",
            ),
        }

        report = AnalysisReport(
            timestamp=datetime(2024, 12, 30, 3, 47, 0),
            log_source="/var/log/auth.log",
            total_events=1000,
            rule_violations=[],
            anomalies=[anomaly],
            geo_data=geo_data,
        )

        reporter = JSONReporter()
        output = reporter.generate(report)
        data = json.loads(output)

        # Check anomaly has location
        anomaly_data = data["anomalies"][0]
        assert "location" in anomaly_data
        assert "Berlin, DE" in anomaly_data["location"]

        # Check anomaly fields are serialized
        assert anomaly_data["ip"] == "10.0.0.1"
        assert anomaly_data["score"] == 0.85
        assert anomaly_data["confidence"] == "high"
        assert "High failure ratio" in anomaly_data["explanation"]
        assert anomaly_data["features"]["failure_ratio"] == 0.9

    def test_unknown_geo_not_included_in_location(self, sample_violation):
        """Test that unknown geo locations don't add location field."""
        geo_data = {
            "192.168.1.100": GeoLocation(),  # Unknown location
        }

        report = AnalysisReport(
            timestamp=datetime(2024, 12, 30, 3, 47, 0),
            log_source="/var/log/auth.log",
            total_events=1000,
            rule_violations=[sample_violation],
            anomalies=[],
            geo_data=geo_data,
        )

        reporter = JSONReporter()
        output = reporter.generate(report)
        data = json.loads(output)

        # Unknown location should not add location field
        violation = data["rule_violations"][0]
        assert "location" not in violation
