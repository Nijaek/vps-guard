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
        """Start daemon: create PID file atomically, check for duplicates.

        Uses atomic file creation to prevent race conditions where multiple
        processes could start simultaneously.
        """
        pid = os.getpid()
        pid_str = str(pid)

        # Try atomic creation first (prevents race condition)
        try:
            # O_CREAT | O_EXCL ensures atomic creation - fails if file exists
            fd = os.open(str(self.pid_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, pid_str.encode('utf-8'))
            os.close(fd)
            logger.info(f"Daemon started (PID {pid})")
            return
        except FileExistsError:
            # PID file exists - check if it's stale
            pass
        except OSError as e:
            raise RuntimeError(f"Failed to create PID file: {e}")

        # PID file exists - check if process is running
        try:
            existing_pid = self._read_pid_file()
            if existing_pid is not None and self._is_process_running(existing_pid):
                raise RuntimeError(f"Daemon already running (PID {existing_pid})")

            # Stale PID file - remove and retry
            logger.warning(f"Removing stale PID file (process {existing_pid} not running)")
            try:
                self.pid_file.unlink()
            except FileNotFoundError:
                pass  # Already removed by another process

            # Retry atomic creation
            try:
                fd = os.open(str(self.pid_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                os.write(fd, pid_str.encode('utf-8'))
                os.close(fd)
                logger.info(f"Daemon started (PID {pid})")
            except FileExistsError:
                # Another process won the race
                raise RuntimeError("Another daemon started during initialization")
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"Failed to start daemon: {e}")

    def _read_pid_file(self) -> Optional[int]:
        """Read and parse PID file safely.

        Returns:
            PID as integer, or None if file is missing/corrupted.
        """
        try:
            content = self.pid_file.read_text().strip()
            return int(content)
        except FileNotFoundError:
            return None
        except (ValueError, UnicodeDecodeError) as e:
            logger.warning(f"Malformed PID file, treating as stale: {e}")
            return None

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
        pid = self._read_pid_file()
        if pid is not None and self._is_process_running(pid):
            return pid
        return None
