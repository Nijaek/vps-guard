"""Tests for watch daemon."""

import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from vpsguard.watch import WatchDaemon, parse_interval, detect_log_format
from vpsguard.models.events import WatchState
from vpsguard.history import HistoryDB


@pytest.fixture
def history_db(tmp_path):
    """Create a test history database."""
    db_path = tmp_path / "test_history.db"
    return HistoryDB(db_path=db_path)


def test_parse_interval():
    """Should parse interval strings to seconds."""
    assert parse_interval("5m") == 300
    assert parse_interval("1h") == 3600
    assert parse_interval("24h") == 86400
    assert parse_interval("1d") == 86400

    with pytest.raises(ValueError):
        parse_interval("invalid")


def test_watch_state_initialization(tmp_path, history_db):
    """Should initialize watch state for new log file."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("Jan  1 00:00:00 server sshd[1]: Test log\n")

    daemon = WatchDaemon(log_path=str(log_file), interval="1h", history_db=history_db)
    state = daemon.get_state()

    assert state.log_path == str(log_file)
    assert state.byte_offset == 0
    assert state.run_count == 0


def test_incremental_parsing(tmp_path, history_db):
    """Should only parse new lines since last run."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("Jan  1 00:00:00 server sshd[1]: Failed password for user1 from 192.168.1.1 port 22 ssh2\n")

    daemon = WatchDaemon(
        log_path=str(log_file),
        interval="1h",
        history_db=history_db
    )

    # First run - parse all
    events1 = daemon.parse_log()
    assert len(events1) == 1

    # Add more content using append mode
    with open(log_file, 'a') as f:
        f.write("Jan  1 00:01:00 server sshd[1]: Failed password for user2 from 192.168.1.2 port 22 ssh2\n")

    # Second run - should only parse new content
    events2 = daemon.parse_log()
    assert len(events2) == 1
    # Verify it's the second event (different IP)
    assert events2[0].ip == "192.168.1.2"


def test_log_rotation_detection(tmp_path, history_db):
    """Should detect log rotation and restart from beginning."""
    # Create a larger initial file to ensure we have a non-zero offset
    initial_content = "Jan  1 00:00:00 server sshd[1]: " + "x" * 100 + " Old log line one\n"
    initial_content += "Jan  1 00:00:01 server sshd[1]: " + "x" * 100 + " Old log line two\n"
    log_file = tmp_path / "auth.log"
    log_file.write_text(initial_content)

    daemon = WatchDaemon(
        log_path=str(log_file),
        interval="1h",
        history_db=history_db
    )

    # First run - reads the whole file and sets byte_offset to end
    daemon.parse_log()
    saved_offset = daemon.get_state().byte_offset
    assert saved_offset > 0  # Ensure we have a non-zero offset

    # Simulate log rotation: new file is SMALLER than our saved offset
    # This is the reliable cross-platform way to detect rotation
    log_file.write_text("Jan  2 00:00:00 server sshd[1]: New\n")  # Much smaller

    # This should detect rotation because file size < saved offset
    rotation_detected = daemon._detect_inode_change()

    assert rotation_detected is True
    assert daemon.get_state().byte_offset == 0  # Reset to start


def test_should_alert_logic():
    """Should trigger alerts based on thresholds."""
    from vpsguard.models.events import Severity

    # Create mock findings
    class MockFinding:
        def __init__(self, severity):
            self.severity = severity

    current_findings = [MockFinding(Severity.CRITICAL)]

    last_counts = {"critical": 0, "high": 0}
    thresholds = {"critical_threshold": 1, "high_threshold": 5}

    # Test with a simple daemon instance
    from vpsguard.watch import WatchDaemon
    result = WatchDaemon.should_alert(current_findings, last_counts, thresholds)
    assert result is True


def test_should_alert_below_threshold():
    """Should not alert when below threshold."""
    from vpsguard.models.events import Severity

    class MockFinding:
        def __init__(self, severity):
            self.severity = severity

    # No critical findings, only high but below threshold
    current_findings = [
        MockFinding(Severity.HIGH),
        MockFinding(Severity.HIGH),
    ]

    last_counts = {"critical": 0, "high": 0}
    thresholds = {"critical_threshold": 1, "high_threshold": 5}

    from vpsguard.watch import WatchDaemon
    result = WatchDaemon.should_alert(current_findings, last_counts, thresholds)
    assert result is False


def test_parse_log_file_not_found(tmp_path, history_db):
    """Should return empty list when log file doesn't exist."""
    log_file = tmp_path / "nonexistent.log"

    daemon = WatchDaemon(
        log_path=str(log_file),
        interval="1h",
        history_db=history_db
    )

    events = daemon.parse_log()
    assert events == []


class TestDetectLogFormat:
    """Tests for detect_log_format function."""

    def test_detect_auth_log(self):
        """Should detect auth.log format."""
        assert detect_log_format("/var/log/auth.log") == "auth.log"
        assert detect_log_format("/var/log/AUTH.LOG") == "auth.log"
        assert detect_log_format("/logs/myauth.log") == "auth.log"

    def test_detect_secure_log(self):
        """Should detect secure log format."""
        assert detect_log_format("/var/log/secure") == "secure"
        assert detect_log_format("/var/log/SECURE") == "secure"
        assert detect_log_format("/logs/secure.log") == "secure"

    def test_detect_nginx_log(self):
        """Should detect nginx log format."""
        assert detect_log_format("/var/log/nginx/access.log") == "nginx"
        assert detect_log_format("/var/log/nginx.log") == "nginx"
        assert detect_log_format("/logs/access.log") == "nginx"

    def test_detect_journald_log(self):
        """Should detect journald format."""
        assert detect_log_format("/var/log/journal.log") == "journald"
        assert detect_log_format("/logs/journal-export") == "journald"

    def test_detect_default_syslog(self):
        """Should default to syslog for unknown files."""
        assert detect_log_format("/var/log/messages") == "syslog"
        assert detect_log_format("/var/log/system.log") == "syslog"
        assert detect_log_format("/logs/custom.log") == "syslog"


def test_parse_interval_invalid():
    """Should raise ValueError for invalid interval format."""
    with pytest.raises(ValueError, match="Invalid interval format"):
        parse_interval("5x")  # Invalid suffix

    with pytest.raises(ValueError, match="Invalid interval format"):
        parse_interval("abc")  # No number
