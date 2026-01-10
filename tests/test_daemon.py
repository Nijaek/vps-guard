"""Tests for daemon manager."""

import os
import signal
import sys

import pytest

from vpsguard.daemon import DaemonManager


def test_pid_file_creation(tmp_path):
    """Should create PID file when daemon starts."""
    pid_file = tmp_path / "test.pid"

    manager = DaemonManager(pid_file=pid_file)
    manager.start()

    assert pid_file.exists()
    pid_content = pid_file.read_text()
    assert pid_content.isdigit()

    manager.stop()


def test_pid_file_cleanup_on_stop(tmp_path):
    """Should remove PID file when daemon stops."""
    pid_file = tmp_path / "test.pid"

    manager = DaemonManager(pid_file=pid_file)
    manager.start()
    assert pid_file.exists()

    manager.stop()
    assert not pid_file.exists()


def test_prevents_duplicate_daemon(tmp_path):
    """Should raise error if daemon already running."""
    pid_file = tmp_path / "test.pid"

    manager1 = DaemonManager(pid_file=pid_file)
    manager1.start()

    manager2 = DaemonManager(pid_file=pid_file)
    with pytest.raises(RuntimeError, match="already running"):
        manager2.start()

    manager1.stop()


@pytest.mark.skipif(sys.platform == 'win32', reason="SIGTERM not available on Windows")
def test_signal_handler_sets_shutdown_flag(tmp_path):
    """Should set shutdown flag on SIGTERM."""
    pid_file = tmp_path / "test.pid"

    manager = DaemonManager(pid_file=pid_file)
    manager.start()

    assert not manager.shutdown_requested

    # Send SIGTERM to self
    os.kill(os.getpid(), signal.SIGTERM)

    # Give signal handler time to run
    import time
    time.sleep(0.1)

    assert manager.shutdown_requested

    manager.stop()


def test_get_running_pid(tmp_path):
    """Should return PID when daemon is running."""
    pid_file = tmp_path / "test.pid"

    manager = DaemonManager(pid_file=pid_file)

    # Before start, should return None
    assert manager.get_running_pid() is None

    manager.start()

    # After start, should return current PID
    assert manager.get_running_pid() == os.getpid()

    manager.stop()

    # After stop, should return None
    assert manager.get_running_pid() is None


def test_stale_pid_file_cleanup(tmp_path):
    """Should clean up stale PID file from dead process."""
    pid_file = tmp_path / "test.pid"

    # Write a fake PID that doesn't exist
    pid_file.write_text("999999")  # Unlikely to be a real PID

    manager = DaemonManager(pid_file=pid_file)
    # Should start successfully, cleaning up stale PID
    manager.start()

    assert pid_file.exists()
    assert pid_file.read_text() == str(os.getpid())

    manager.stop()
