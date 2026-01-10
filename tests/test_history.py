"""Tests for history database and watch state persistence."""

from datetime import datetime, timedelta, timezone

import pytest

from vpsguard.history import HistoryDB
from vpsguard.models.events import (
    AnalysisReport,
    AnomalyResult,
    Confidence,
    RuleViolation,
    Severity,
)


@pytest.fixture
def history_db(tmp_path):
    """Create a test history database."""
    db_path = tmp_path / "test_history.db"
    return HistoryDB(db_path=db_path)


@pytest.fixture
def sample_report():
    """Create a sample AnalysisReport for testing."""
    now = datetime.now(timezone.utc)
    violations = [
        RuleViolation(
            rule_name="brute_force",
            severity=Severity.CRITICAL,
            ip="192.168.1.100",
            description="Brute force attack detected",
            timestamp=now,
            details={"attempts": 50},
            affected_events=[]
        ),
        RuleViolation(
            rule_name="breach_detection",
            severity=Severity.HIGH,
            ip="192.168.1.101",
            description="Possible breach detected",
            timestamp=now,
            details={"failures_before_success": 10},
            affected_events=[]
        )
    ]
    anomalies = [
        AnomalyResult(
            ip="10.0.0.50",
            score=0.85,
            confidence=Confidence.HIGH,
            explanation=["Unusual login pattern"],
            features={"failure_ratio": 0.9}
        )
    ]
    return AnalysisReport(
        timestamp=now,
        log_source="/var/log/auth.log",
        total_events=1000,
        rule_violations=violations,
        anomalies=anomalies,
        baseline_drift=None
    )


def test_save_and_load_watch_state(history_db):
    """Should persist and retrieve watch daemon state."""
    from vpsguard.models.events import WatchState

    # Create initial state
    state = WatchState(
        log_path="/var/log/auth.log",
        inode=12345,
        byte_offset=1024000,
        last_run_time=datetime.now(timezone.utc),
        run_count=5,
        last_findings_counts={"critical": 0, "high": 2, "medium": 10}
    )

    history_db.save_watch_state(state)

    # Load it back
    loaded = history_db.get_watch_state("/var/log/auth.log")

    assert loaded is not None
    assert loaded.log_path == "/var/log/auth.log"
    assert loaded.inode == 12345
    assert loaded.byte_offset == 1024000
    assert loaded.run_count == 5


def test_watch_state_updates(history_db):
    """Should update existing watch state for same log path."""
    from vpsguard.models.events import WatchState

    # Initial save
    state = WatchState(
        log_path="/var/log/auth.log",
        inode=12345,
        byte_offset=1000,
        last_run_time=datetime.now(timezone.utc),
        run_count=1,
        last_findings_counts={}
    )
    history_db.save_watch_state(state)

    # Update with new offset
    state.byte_offset = 5000
    state.run_count = 2
    history_db.save_watch_state(state)

    loaded = history_db.get_watch_state("/var/log/auth.log")
    assert loaded.byte_offset == 5000
    assert loaded.run_count == 2


def test_history_persists_all_run_data(history_db, sample_report):
    """Should persist all analysis run data correctly."""
    run_id = history_db.save_run(sample_report)

    run = history_db.get_run(run_id)

    assert run is not None
    assert run['log_source'] == sample_report.log_source
    assert run['total_events'] == sample_report.total_events
    assert run['critical_count'] == 1
    assert run['high_count'] == 1


def test_history_violations_persisted(history_db, sample_report):
    """Should persist all violation details."""
    run_id = history_db.save_run(sample_report)

    violations = history_db.get_run_violations(run_id)

    assert len(violations) == 2
    assert violations[0]['ip'] == '192.168.1.100'
    assert violations[0]['severity'] == 'critical'  # Stored as lowercase enum value


def test_history_anomalies_persisted(history_db, sample_report):
    """Should persist all anomaly data."""
    run_id = history_db.save_run(sample_report)

    anomalies = history_db.get_run_anomalies(run_id)

    assert len(anomalies) == 1
    assert anomalies[0]['ip'] == '10.0.0.50'
    assert anomalies[0]['score'] > 0


def test_history_cleanup_old_runs(history_db):
    """Should delete runs older than specified days."""
    # Create an old run
    old_report = AnalysisReport(
        timestamp=datetime.now(timezone.utc) - timedelta(days=100),
        log_source="/old/log",
        total_events=100,
        rule_violations=[],
        anomalies=None,
        baseline_drift=None
    )
    history_db.save_run(old_report)

    # Create a recent run
    recent_report = AnalysisReport(
        timestamp=datetime.now(timezone.utc),
        log_source="/recent/log",
        total_events=100,
        rule_violations=[],
        anomalies=None,
        baseline_drift=None
    )
    history_db.save_run(recent_report)

    # Cleanup runs older than 30 days
    deleted = history_db.cleanup_old_runs(days=30)

    assert deleted == 1

    # Verify old run is gone, recent run remains
    recent_runs = history_db.get_recent_runs(limit=10)
    assert len(recent_runs) == 1
    assert recent_runs[0]['log_source'] == "/recent/log"


def test_get_ip_history(history_db, sample_report):
    """Should get violation history for a specific IP."""
    # Save the report
    history_db.save_run(sample_report)

    # Get history for the IP in the violation
    history = history_db.get_ip_history("192.168.1.100", days=30)

    assert history["ip"] == "192.168.1.100"
    assert history["days"] == 30
    assert history["total_violations"] >= 1
    assert "violations" in history
    assert "anomaly_count" in history
    assert "avg_anomaly_score" in history


def test_get_ip_history_no_violations(history_db):
    """Should return zero counts for IP with no history."""
    history = history_db.get_ip_history("1.2.3.4", days=30)

    assert history["ip"] == "1.2.3.4"
    assert history["total_violations"] == 0
    assert history["anomaly_count"] == 0


def test_get_top_offenders(history_db, sample_report):
    """Should get top offending IPs."""
    # Save the report
    history_db.save_run(sample_report)

    # Get top offenders
    offenders = history_db.get_top_offenders(days=30, limit=10)

    assert isinstance(offenders, list)
    if len(offenders) > 0:
        assert "ip" in offenders[0]
        assert "total" in offenders[0]
        assert "critical" in offenders[0]
        assert "high" in offenders[0]


def test_get_top_offenders_empty(history_db):
    """Should return empty list when no violations."""
    offenders = history_db.get_top_offenders(days=30, limit=10)

    assert offenders == []
