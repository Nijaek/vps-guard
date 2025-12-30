"""Basic tests for core data models."""

from datetime import datetime
import pytest

from vpsguard.models.events import (
    AuthEvent,
    EventType,
    Severity,
    Confidence,
    ParsedLog,
    RuleViolation,
    RuleEngineOutput,
    AnomalyResult,
    BaselineStats,
    AnalysisReport,
)


def test_auth_event_instantiation():
    """Test that AuthEvent can be instantiated with required fields."""
    event = AuthEvent(
        timestamp=datetime.now(),
        event_type=EventType.FAILED_LOGIN,
        ip="192.168.1.1",
        username="testuser",
        success=False,
        raw_line="Test log line",
    )
    assert event.ip == "192.168.1.1"
    assert event.username == "testuser"
    assert event.success is False
    assert event.event_type == EventType.FAILED_LOGIN


def test_auth_event_with_optional_fields():
    """Test that AuthEvent can be instantiated with optional fields."""
    event = AuthEvent(
        timestamp=datetime.now(),
        event_type=EventType.SUCCESSFUL_LOGIN,
        ip="10.0.0.1",
        username="admin",
        success=True,
        raw_line="SSH login",
        port=22,
        pid=1234,
        service="sshd",
    )
    assert event.port == 22
    assert event.pid == 1234
    assert event.service == "sshd"


def test_parsed_log_instantiation():
    """Test that ParsedLog can be instantiated."""
    event = AuthEvent(
        timestamp=datetime.now(),
        event_type=EventType.FAILED_LOGIN,
        ip="192.168.1.1",
        username="root",
        success=False,
        raw_line="Failed login",
    )
    parsed_log = ParsedLog(
        events=[event],
        source_file="/var/log/auth.log",
        format_type="auth.log",
        parse_errors=[],
    )
    assert len(parsed_log.events) == 1
    assert parsed_log.source_file == "/var/log/auth.log"
    assert parsed_log.format_type == "auth.log"
    assert len(parsed_log.parse_errors) == 0


def test_rule_violation_instantiation():
    """Test that RuleViolation can be instantiated."""
    event = AuthEvent(
        timestamp=datetime.now(),
        event_type=EventType.FAILED_LOGIN,
        ip="1.2.3.4",
        username="root",
        success=False,
        raw_line="Failed login",
    )
    violation = RuleViolation(
        rule_name="brute_force",
        severity=Severity.HIGH,
        ip="1.2.3.4",
        description="Multiple failed login attempts",
        timestamp=datetime.now(),
        details={"count": 10},
        affected_events=[event],
    )
    assert violation.rule_name == "brute_force"
    assert violation.severity == Severity.HIGH
    assert violation.ip == "1.2.3.4"
    assert len(violation.affected_events) == 1


def test_rule_engine_output_instantiation():
    """Test that RuleEngineOutput can be instantiated."""
    event = AuthEvent(
        timestamp=datetime.now(),
        event_type=EventType.FAILED_LOGIN,
        ip="1.2.3.4",
        username="root",
        success=False,
        raw_line="Failed login",
    )
    violation = RuleViolation(
        rule_name="test_rule",
        severity=Severity.MEDIUM,
        ip="1.2.3.4",
        description="Test violation",
        timestamp=datetime.now(),
        details={},
        affected_events=[event],
    )
    output = RuleEngineOutput(
        violations=[violation],
        clean_events=[],
        flagged_ips={"1.2.3.4"},
    )
    assert len(output.violations) == 1
    assert len(output.clean_events) == 0
    assert "1.2.3.4" in output.flagged_ips


def test_anomaly_result_instantiation():
    """Test that AnomalyResult can be instantiated."""
    anomaly = AnomalyResult(
        ip="5.6.7.8",
        score=0.85,
        confidence=Confidence.HIGH,
        explanation=["Unusual login pattern"],
        features={"login_rate": 10.5, "unique_usernames": 5.0},
    )
    assert anomaly.ip == "5.6.7.8"
    assert anomaly.score == 0.85
    assert anomaly.confidence == Confidence.HIGH
    assert len(anomaly.explanation) == 1
    assert "login_rate" in anomaly.features


def test_baseline_stats_instantiation():
    """Test that BaselineStats can be instantiated."""
    stats = BaselineStats(
        trained_at=datetime.now(),
        event_count=1000,
        feature_means={"login_rate": 2.5},
        feature_stds={"login_rate": 0.5},
        model_path="/path/to/model.pkl",
    )
    assert stats.event_count == 1000
    assert "login_rate" in stats.feature_means
    assert stats.model_path == "/path/to/model.pkl"


def test_analysis_report_instantiation():
    """Test that AnalysisReport can be instantiated."""
    event = AuthEvent(
        timestamp=datetime.now(),
        event_type=EventType.FAILED_LOGIN,
        ip="1.2.3.4",
        username="root",
        success=False,
        raw_line="Failed login",
    )
    violation = RuleViolation(
        rule_name="test_rule",
        severity=Severity.HIGH,
        ip="1.2.3.4",
        description="Test",
        timestamp=datetime.now(),
        details={},
        affected_events=[event],
    )
    anomaly = AnomalyResult(
        ip="5.6.7.8",
        score=0.9,
        confidence=Confidence.HIGH,
        explanation=["Test"],
        features={},
    )
    report = AnalysisReport(
        timestamp=datetime.now(),
        log_source="/var/log/auth.log",
        total_events=100,
        rule_violations=[violation],
        anomalies=[anomaly],
        baseline_drift=None,
        summary={"total_ips": 10},
    )
    assert report.total_events == 100
    assert len(report.rule_violations) == 1
    assert len(report.anomalies) == 1
    assert report.summary["total_ips"] == 10


def test_event_type_enum():
    """Test EventType enum values."""
    assert EventType.FAILED_LOGIN.value == "failed_login"
    assert EventType.SUCCESSFUL_LOGIN.value == "successful_login"
    assert EventType.INVALID_USER.value == "invalid_user"
    assert EventType.SUDO.value == "sudo"
    assert EventType.DISCONNECT.value == "disconnect"
    assert EventType.OTHER.value == "other"


def test_severity_enum():
    """Test Severity enum values."""
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"


def test_confidence_enum():
    """Test Confidence enum values."""
    assert Confidence.HIGH.value == "high"
    assert Confidence.MEDIUM.value == "medium"
    assert Confidence.LOW.value == "low"
