"""Daemon manager for background watch mode."""

import os
import signal
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class DaemonManager:
    """Manages daemon lifecycle: PID file, signals, graceful shutdown."""

    def __init__(self, pid_file: Optional[Path] = None):
        """Initialize daemon manager.

        Args:
            pid_file: Path to PID file. Defaults to ~/.vpsguard/watch.pid
        """
        self.pid_file = pid_file or Path.home() / ".vpsguard" / "watch.pid"
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        self.shutdown_requested = False
        self._setup_signals()

    def _setup_signals(self):
        """Register signal handlers for graceful shutdown."""
        # SIGTERM and SIGINT work cross-platform for graceful shutdown
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_requested = True

    def start(self):
        """Start daemon: create PID file, check for duplicates."""
        # Check if already running
        if self.pid_file.exists():
            existing_pid = int(self.pid_file.read_text().strip())
            if self._is_process_running(existing_pid):
                raise RuntimeError(f"Daemon already running (PID {existing_pid})")
            else:
                # Stale PID file, remove it
                logger.warning(f"Removing stale PID file (process {existing_pid} not running)")
                self.pid_file.unlink()

        # Write current PID
        self.pid_file.write_text(str(os.getpid()))
        logger.info(f"Daemon started (PID {os.getpid()})")

    def stop(self):
        """Stop daemon: remove PID file."""
        if self.pid_file.exists():
            self.pid_file.unlink()
            logger.info("Daemon stopped")

    @staticmethod
    def _is_process_running(pid: int) -> bool:
        """Check if a process with given PID is running.

        Args:
            pid: Process ID to check.

        Returns:
            True if process is running, False otherwise.
        """
        if os.name == 'nt':  # Windows
            try:
                import psutil
                return psutil.Process(pid).is_running()
            except Exception:
                # psutil not installed or process doesn't exist
                try:
                    # Fallback: try to use Windows-specific check
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                    if handle:
                        kernel32.CloseHandle(handle)
                        return True
                    return False
                except Exception:
                    return False
        else:  # Unix-like
            try:
                os.kill(pid, 0)  # Signal 0 doesn't kill, just checks existence
                return True
            except OSError:
                return False

    def get_running_pid(self) -> Optional[int]:
        """Get PID of running daemon if any.

        Returns:
            PID if daemon is running, None otherwise.
        """
        if not self.pid_file.exists():
            return None

        pid = int(self.pid_file.read_text().strip())
        if self._is_process_running(pid):
            return pid
        return None
