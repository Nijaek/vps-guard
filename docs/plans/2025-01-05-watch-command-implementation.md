# VPSGuard Phase 4-5: Watch Command Implementation

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build scheduled batch mode (`vpsguard watch`) for continuous log monitoring with daemon support, alerting, and state persistence.

**Architecture:** Watch daemon runs in background, tracks file position (inode + byte offset) for incremental parsing, executes full analysis at configured intervals, persists state to SQLite, and triggers alerts based on threshold deltas between runs.

**Tech Stack:** Python 3.10+, dataclasses (state), signal module (SIGTERM/SIGINT), sqlite3 (persistence), typer (CLI), schedule/time.sleep (intervals), pathlib (file ops)

---

## Task 1: Config Schema - Add Watch Schedule Section

**Files:**
- Modify: `src/vpsguard/config.py`
- Create: `tests/test_watch_config.py`

**Step 1: Write the failing test**

```python
# tests/test_watch_config.py
"""Tests for watch configuration schema."""

import pytest
from pathlib import Path
from vpsguard.config import load_config, validate_config


def test_watch_schedule_defaults():
    """Watch schedule config should have sensible defaults."""
    config = load_config()

    assert hasattr(config, 'watch_schedule')
    assert config.watch_schedule.interval == "1h"
    assert config.watch_schedule.retention_days == 30


def test_watch_schedule_from_toml():
    """Should load watch schedule from TOML config."""
    toml_content = """
[watch.schedule]
interval = "30m"
retention_days = 14

[watch.schedule.alerts]
critical_threshold = 1
high_threshold = 10
anomaly_threshold = 5

[watch.output]
directory = "/tmp/vpsguard"
formats = ["markdown", "json"]
"""
    config_path = Path("/tmp/test_watch_config.toml")
    config_path.write_text(toml_content)

    config = load_config(config_path)

    assert config.watch_schedule.interval == "30m"
    assert config.watch_schedule.retention_days == 14
    assert config.watch_schedule.alerts['critical_threshold'] == 1
    assert config.watch_schedule.alerts['high_threshold'] == 10
    assert config.watch_schedule.alerts['anomaly_threshold'] == 5
    assert config.watch_output.directory == "/tmp/vpsguard"
    assert config.watch_output.formats == ["markdown", "json"]


def test_watch_interval_validation():
    """Should reject invalid interval formats."""
    config = load_config()
    config.watch_schedule.interval = "invalid"

    warnings = validate_config(config)
    assert any("interval" in w.lower() for w in warnings)


def test_watch_alert_thresholds_validation():
    """Should validate alert thresholds are non-negative."""
    config = load_config()
    config.watch_schedule.alerts = {'critical_threshold': -1}

    warnings = validate_config(config)
    assert any("threshold" in w.lower() for w in warnings)
```

Run: `python -m pytest tests/test_watch_config.py -v`
Expected: FAIL - `AttributeError: 'VPSGuardConfig' object has no attribute 'watch_schedule'`

---

**Step 2: Add WatchScheduleConfig and WatchOutputConfig dataclasses**

```python
# Add to src/vpsguard/config.py after line 70 (after OutputConfig)

@dataclass
class WatchAlertConfig:
    """Alert thresholds for watch mode."""
    critical_threshold: int = 1
    high_threshold: int = 5
    anomaly_threshold: int = 3


@dataclass
class WatchOutputConfig:
    """Output configuration for watch mode reports."""
    directory: str = "~/.vpsguard/reports"
    formats: list[str] = field(default_factory=lambda: ["markdown", "json"])


@dataclass
class WatchScheduleConfig:
    """Configuration for watch daemon scheduling."""
    interval: str = "1h"  # Duration: 5m, 1h, 6h, 24h
    retention_days: int = 30
    alerts: dict = field(default_factory=lambda: {
        "critical_threshold": 1,
        "high_threshold": 5,
        "anomaly_threshold": 3
    })
```

---

**Step 3: Update VPSGuardConfig to include watch sections**

```python
# Modify src/vpsguard/config.py line 73-78

@dataclass
class VPSGuardConfig:
    """Main configuration container for VPSGuard."""
    rules: RulesConfig = field(default_factory=RulesConfig)
    whitelist_ips: list[str] = field(default_factory=list)
    output: OutputConfig = field(default_factory=OutputConfig)
    watch_schedule: WatchScheduleConfig = field(default_factory=WatchScheduleConfig)
    watch_output: WatchOutputConfig = field(default_factory=WatchOutputConfig)
```

---

**Step 4: Add watch config parsing in _build_config()**

```python
# Add to src/vpsguard/config.py in _build_config() after line 170 (after output config loading)

    # Load watch configuration
    if "watch" in data:
        watch_data = data["watch"]

        if "schedule" in watch_data:
            schedule = watch_data["schedule"]
            alerts = schedule.get("alerts", {})

            config.watch_schedule = WatchScheduleConfig(
                interval=schedule.get("interval", "1h"),
                retention_days=schedule.get("retention_days", 30),
                alerts={
                    "critical_threshold": alerts.get("critical_threshold", 1),
                    "high_threshold": alerts.get("high_threshold", 5),
                    "anomaly_threshold": alerts.get("anomaly_threshold", 3)
                }
            )

        if "output" in watch_data:
            output = watch_data["output"]
            config.watch_output = WatchOutputConfig(
                directory=output.get("directory", "~/.vpsguard/reports"),
                formats=output.get("formats", ["markdown", "json"])
            )
```

---

**Step 5: Add watch config validation**

```python
# Add to src/vpsguard/config.py in validate_config() after line 235 (after whitelist validation)

    # Validate watch schedule config
    valid_intervals = {"5m", "15m", "30m", "1h", "6h", "12h", "24h"}
    if config.watch_schedule.interval not in valid_intervals:
        warnings.append(f"watch.schedule.interval '{config.watch_schedule.interval}' must be one of: {', '.join(sorted(valid_intervals))}")

    if config.watch_schedule.retention_days < 1:
        warnings.append("watch.schedule.retention_days must be >= 1")

    for threshold_name, threshold_value in config.watch_schedule.alerts.items():
        if threshold_value < 0:
            warnings.append(f"watch.schedule.alerts.{threshold_name} must be >= 0")
```

---

**Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/test_watch_config.py -v`
Expected: PASS (all 4 tests pass)

---

**Step 7: Commit**

```bash
git add src/vpsguard/config.py tests/test_watch_config.py
git commit -m "feat: add watch schedule configuration schema"
```

---

## Task 2: SQLite Schema Extensions - Watch State Table

**Files:**
- Modify: `src/vpsguard/history.py`
- Modify: `tests/test_history.py` (add tests)

**Step 1: Write the failing test**

```python
# Add to tests/test_history.py

def test_save_and_load_watch_state(history_db):
    """Should persist and retrieve watch daemon state."""
    from datetime import datetime, timezone

    # Create initial state
    state = WatchState(
        log_path="/var/log/auth.log",
        inode=12345,
        byte_offset=1024000,
        last_run_time=datetime.now(timezone.utc),
        run_count=5,
        last_findings_counts={"critical": 0, "high": 2, "medium": 10}
    )

    run_id = history_db.save_watch_state(state)

    # Load it back
    loaded = history_db.get_watch_state("/var/log/auth.log")

    assert loaded is not None
    assert loaded.log_path == "/var/log/auth.log"
    assert loaded.inode == 12345
    assert loaded.byte_offset == 1024000
    assert loaded.run_count == 5


def test_watch_state_updates(history_db):
    """Should update existing watch state for same log path."""
    from datetime import datetime, timezone

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
```

Run: `python -m pytest tests/test_history.py::test_save_and_load_watch_state -v`
Expected: FAIL - `NameError: name 'WatchState' is not defined`

---

**Step 2: Add WatchState dataclass**

```python
# Add to src/vpsguard/models/events.py (after AnomalyResult dataclass)

@dataclass
class WatchState:
    """Persistent state for watch daemon tracking.

    Tracks where we left off in the log file to enable incremental parsing.
    """
    log_path: str                      # File being monitored
    inode: int                         # File inode (detect log rotation)
    byte_offset: int                   # Last read position
    last_run_time: datetime            # When we last ran analysis
    run_count: int                     # Total analysis runs
    last_findings_counts: dict         # {severity: count} from last run
```

---

**Step 3: Add watch_state table to HistoryDB._init_db()**

```python
# Modify src/vpsguard/history.py - add to _init_db() after line 77 (after anomalies table creation)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS watch_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_path TEXT UNIQUE NOT NULL,
                    inode INTEGER NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    last_run_time TEXT NOT NULL,
                    run_count INTEGER NOT NULL,
                    last_findings_counts TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # Create index for watch_state lookups
            conn.execute("CREATE INDEX IF NOT EXISTS idx_watch_state_path ON watch_state(log_path)")
```

---

**Step 4: Add save_watch_state() method to HistoryDB**

```python
# Add to src/vpsguard/history.py after save_run() method (after line 156)

    def save_watch_state(self, state: WatchState) -> int:
        """Save or update watch daemon state.

        Args:
            state: WatchState instance to persist.

        Returns:
            The row ID of the saved/updated record.
        """
        import json
        from datetime import datetime, timezone

        findings_json = json.dumps(state.last_findings_counts)
        updated_at = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO watch_state (log_path, inode, byte_offset, last_run_time, run_count, last_findings_counts, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(log_path) DO UPDATE SET
                    inode = excluded.inode,
                    byte_offset = excluded.byte_offset,
                    last_run_time = excluded.last_run_time,
                    run_count = excluded.run_count,
                    last_findings_counts = excluded.last_findings_counts,
                    updated_at = excluded.updated_at
            """, (
                state.log_path,
                state.inode,
                state.byte_offset,
                state.last_run_time.isoformat(),
                state.run_count,
                findings_json,
                updated_at
            ))

            conn.commit()
            return cursor.lastrowid
```

---

**Step 5: Add get_watch_state() method to HistoryDB**

```python
# Add to src/vpsguard/history.py after save_watch_state()

    def get_watch_state(self, log_path: str) -> Optional[WatchState]:
        """Get watch state for a specific log path.

        Args:
            log_path: Path to the log file.

        Returns:
            WatchState instance or None if not found.
        """
        import json
        from datetime import datetime

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM watch_state
                WHERE log_path = ?
            """, (log_path,))

            row = cursor.fetchone()
            if not row:
                return None

            return WatchState(
                log_path=row['log_path'],
                inode=row['inode'],
                byte_offset=row['byte_offset'],
                last_run_time=datetime.fromisoformat(row['last_run_time']),
                run_count=row['run_count'],
                last_findings_counts=json.loads(row['last_findings_counts'])
            )
```

---

**Step 6: Update imports in history.py**

```python
# Modify src/vpsguard/history.py line 10 - add WatchState to imports

from vpsguard.models.events import AnalysisReport, RuleViolation, AnomalyResult, Severity, Confidence, WatchState
```

---

**Step 7: Run tests to verify they pass**

Run: `python -m pytest tests/test_history.py::test_save_and_load_watch_state tests/test_history.py::test_watch_state_updates -v`
Expected: PASS (both tests pass)

---

**Step 8: Commit**

```bash
git add src/vpsguard/history.py src/vpsguard/models/events.py tests/test_history.py
git commit -m "feat: add watch state persistence to SQLite"
```

---

## Task 3: Daemon Manager - PID File and Signal Handling

**Files:**
- Create: `src/vpsguard/daemon.py`
- Create: `tests/test_daemon.py`

**Step 1: Write the failing test**

```python
# tests/test_daemon.py
"""Tests for daemon manager."""

import pytest
import signal
from pathlib import Path
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


def test_signal_handler_sets_shutdown_flag(tmp_path):
    """Should set shutdown flag on SIGTERM."""
    pid_file = tmp_path / "test.pid"

    manager = DaemonManager(pid_file=pid_file)
    manager.start()

    assert not manager.shutdown_requested

    # Send SIGTERM to self
    import os
    os.kill(os.getpid(), signal.SIGTERM)

    # Give signal handler time to run
    import time
    time.sleep(0.1)

    assert manager.shutdown_requested

    manager.stop()
```

Run: `python -m pytest tests/test_daemon.py -v`
Expected: FAIL - `ModuleNotFoundError: No module named 'vpsguard.daemon'`

---

**Step 2: Create DaemonManager class**

```python
# src/vpsguard/daemon.py
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
            import psutil
            try:
                return psutil.Process(pid).is_running()
            except psutil.NoSuchProcess:
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
```

---

**Step 3: Add psutil to project dependencies**

```bash
# Add to pyproject.toml dependencies if not present
# (psutil is cross-platform, needed for Windows process checking)
```

---

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_daemon.py -v`
Expected: PASS (all 4 tests pass)

---

**Step 5: Commit**

```bash
git add src/vpsguard/daemon.py tests/test_daemon.py
git commit -m "feat: add daemon manager with PID file and signal handling"
```

---

## Task 4: Watch Daemon - Core Implementation

**Files:**
- Create: `src/vpsguard/watch.py`
- Create: `tests/test_watch.py`

**Step 1: Write the failing test**

```python
# tests/test_watch.py
"""Tests for watch daemon."""

import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from vpsguard.watch import WatchDaemon
from vpsguard.models.events import WatchState


def test_watch_state_initialization(tmp_path):
    """Should initialize watch state for new log file."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("Jan 1 00:00:00 server sshd[1]: Test log\n")

    daemon = WatchDaemon(log_path=str(log_file), interval="1h")
    state = daemon.get_state()

    assert state.log_path == str(log_file)
    assert state.byte_offset == 0
    assert state.run_count == 0


def test_incremental_parsing(tmp_path, history_db):
    """Should only parse new lines since last run."""
    from vpsguard.parsers import get_parser

    log_file = tmp_path / "auth.log"
    log_file.write_text("Jan 1 00:00:00 server sshd[1]: First line\n")

    daemon = WatchDaemon(
        log_path=str(log_file),
        interval="1h",
        history_db=history_db
    )

    # First run - parse all
    events1 = daemon.parse_log()
    assert len(events1) == 1

    # Add more content
    log_file.write_text("Jan 1 00:01:00 server sshd[1]: Second line\n", append=True)

    # Second run - should only parse new content
    events2 = daemon.parse_log()
    assert len(events2) == 1
    assert events2[0].timestamp > events1[0].timestamp


def test_log_rotation_detection(tmp_path, history_db):
    """Should detect log rotation and restart from beginning."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("Jan 1 00:00:00 server sshd[1]: Old log\n")

    daemon = WatchDaemon(
        log_path=str(log_file),
        interval="1h",
        history_db=history_db
    )

    # First run
    daemon.parse_log()
    initial_inode = daemon.get_state().inode

    # Simulate log rotation (new file, same path, different inode)
    log_file.write_text("Jan 2 00:00:00 server sshd[1]: New log\n")

    daemon._detect_inode_change()
    new_inode = daemon.get_state().inode

    assert new_inode != initial_inode
    assert daemon.get_state().byte_offset == 0  # Reset to start


def test_should_alert_logic():
    """Should trigger alerts based on thresholds."""
    daemon = WatchDaemon(log_path="/var/log/auth.log", interval="1h")

    current_findings = [
        type('Obj', (), {'severity': 'CRITICAL'})()
    ]

    last_counts = {"critical": 0, "high": 0}
    thresholds = {"critical_threshold": 1, "high_threshold": 5}

    assert daemon.should_alert(current_findings, last_counts, thresholds) is True
```

Run: `python -m pytest tests/test_watch.py -v`
Expected: FAIL - `ModuleNotFoundError: No module named 'vpsguard.watch'`

---

**Step 2: Create WatchDaemon class**

```python
# src/vpsguard/watch.py
"""Watch daemon for scheduled batch analysis."""

import os
import time
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

from vpsguard.parsers import get_parser
from vpsguard.models.events import WatchState, Severity
from vpsguard.history import HistoryDB
from vpsguard.daemon import DaemonManager

logger = logging.getLogger(__name__)


def parse_interval(interval: str) -> int:
    """Parse interval string to seconds.

    Args:
        interval: Interval string (e.g., "5m", "1h", "24h")

    Returns:
        Interval in seconds.

    Raises:
        ValueError: If interval format is invalid.
    """
    interval = interval.lower().strip()
    if interval.endswith('m'):
        return int(interval[:-1]) * 60
    elif interval.endswith('h'):
        return int(interval[:-1]) * 3600
    elif interval.endswith('d'):
        return int(interval[:-1]) * 86400
    else:
        raise ValueError(f"Invalid interval format: {interval}")


class WatchDaemon:
    """Watch daemon for scheduled batch analysis.

    Runs full analysis at configured intervals, tracking file position
    for incremental parsing.
    """

    def __init__(
        self,
        log_path: str,
        interval: str = "1h",
        history_db: Optional[HistoryDB] = None,
        daemon_manager: Optional[DaemonManager] = None
    ):
        """Initialize watch daemon.

        Args:
            log_path: Path to log file to monitor.
            interval: Schedule interval (e.g., "5m", "1h").
            history_db: HistoryDB instance. Creates default if None.
            daemon_manager: DaemonManager instance. Creates default if None.
        """
        self.log_path = Path(log_path)
        self.interval_seconds = parse_interval(interval)
        self.history_db = history_db or HistoryDB()
        self.daemon_manager = daemon_manager or DaemonManager()

        self._state: Optional[WatchState] = None

    def get_state(self) -> WatchState:
        """Get current watch state, loading from DB if needed."""
        if self._state is None:
            self._state = self.history_db.get_watch_state(str(self.log_path))
            if self._state is None:
                # Initialize new state
                self._state = WatchState(
                    log_path=str(self.log_path),
                    inode=self._get_inode(),
                    byte_offset=0,
                    last_run_time=datetime.now(timezone.utc),
                    run_count=0,
                    last_findings_counts={}
                )
        return self._state

    def _get_inode(self) -> int:
        """Get file inode to detect log rotation."""
        if os.name == 'nt':  # Windows
            # Use file size and modification time as proxy
            stat = self.log_path.stat()
            return hash((stat.st_size, stat.st_mtime))
        else:
            return self.log_path.stat().st_ino

    def _detect_inode_change(self) -> bool:
        """Check if log file was rotated.

        Returns:
            True if inode changed (log rotated), False otherwise.
        """
        current_inode = self._get_inode()
        state = self.get_state()

        if current_inode != state.inode:
            logger.info(f"Log rotation detected (inode {state.inode} -> {current_inode})")
            state.inode = current_inode
            state.byte_offset = 0  # Restart from beginning
            return True
        return False

    def parse_log(self) -> list:
        """Parse log file incrementally from saved offset.

        Returns:
            List of newly parsed events since last run.
        """
        if not self.log_path.exists():
            logger.warning(f"Log file not found: {self.log_path}")
            return []

        self._detect_inode_change()
        state = self.get_state()

        parser = get_parser(str(self.log_path))
        events = []

        with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(state.byte_offset)
            new_lines = f.readlines()
            new_offset = f.tell()

        for line in new_lines:
            event = parser.parse_line(line.strip())
            if event:
                events.append(event)

        # Update offset
        state.byte_offset = new_offset

        return events

    def should_alert(
        self,
        current_findings: list,
        last_counts: dict,
        thresholds: dict
    ) -> bool:
        """Check if alert conditions are met.

        Args:
            current_findings: List of current findings.
            last_counts: Previous run counts by severity.
            thresholds: Alert thresholds from config.

        Returns:
            True if should alert, False otherwise.
        """
        current_counts = {}
        for finding in current_findings:
            severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            current_counts[severity] = current_counts.get(severity, 0) + 1

        # Check critical threshold
        if thresholds.get('critical_threshold', 0) > 0:
            if current_counts.get('CRITICAL', 0) >= thresholds['critical_threshold']:
                return True

        # Check high threshold
        if thresholds.get('high_threshold', 0) > 0:
            if current_counts.get('HIGH', 0) >= thresholds['high_threshold']:
                return True

        # Check anomaly threshold
        if thresholds.get('anomaly_threshold', 0) > 0:
            # Count anomalies (would need to pass them separately)
            pass

        return False

    def run_once(self, config) -> dict:
        """Run single analysis cycle.

        Args:
            config: VPSGuardConfig instance.

        Returns:
            Dict with run results (events count, findings count, etc.)
        """
        from vpsguard.rules.engine import RuleEngine
        from vpsguard.ml.engine import MLEngine

        # Parse log
        events = self.parse_log()

        if not events:
            return {"events": 0, "findings": 0}

        # Run rules
        rule_engine = RuleEngine(config.rules, config.whitelist_ips)
        violations = []
        clean_events = []

        for event in events:
            event_violations = rule_engine.check_event(event)
            if event_violations:
                violations.extend(event_violations)
            else:
                clean_events.append(event)

        # Run ML if model available
        anomalies = []
        if config.ml.model_path and Path(config.ml.model_path).exists():
            ml_engine = MLEngine(config.ml)
            anomalies = ml_engine.detect_anomalies(clean_events)

        # Save state
        state = self.get_state()
        state.last_run_time = datetime.now(timezone.utc)
        state.run_count += 1
        state.last_findings_counts = {
            'critical': sum(1 for v in violations if v.severity == Severity.CRITICAL),
            'high': sum(1 for v in violations if v.severity == Severity.HIGH),
            'medium': sum(1 for v in violations if v.severity == Severity.MEDIUM),
            'low': sum(1 for v in violations if v.severity == Severity.LOW),
        }
        self.history_db.save_watch_state(state)

        return {
            "events": len(events),
            "violations": len(violations),
            "anomalies": len(anomalies),
            "findings_counts": state.last_findings_counts
        }
```

---

**Step 3: Run tests to verify they pass**

Run: `python -m pytest tests/test_watch.py -v`
Expected: PASS (all 4 tests pass)

---

**Step 4: Commit**

```bash
git add src/vpsguard/watch.py tests/test_watch.py
git commit -m "feat: implement watch daemon core logic"
```

---

## Task 5: CLI - Add Watch Command

**Files:**
- Modify: `src/vpsguard/cli.py`

**Step 1: Add watch command to CLI**

```python
# Add to src/vpsguard/cli.py after the analyze command (around line 300+)

@app.command()
def watch(
    log_file: str = typer.Argument(..., help="Path to log file to monitor"),
    interval: Optional[str] = typer.Option(None, "--interval", "-i", help="Schedule interval (e.g., 5m, 1h)"),
    foreground: bool = typer.Option(False, "--foreground", "-f", help="Run in foreground (don't daemonize)"),
    once: bool = typer.Option(False, "--once", help="Run single analysis cycle then exit"),
    status: bool = typer.Option(False, "--status", help="Show daemon status"),
    stop: bool = typer.Option(False, "--stop", help="Stop running daemon"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config file")
):
    """Run scheduled batch analysis on log file.

    Monitors log file at configured intervals, running full analysis each time.
    Persists state between runs for incremental parsing.
    """
    from vpsguard.config import load_config
    from vpsguard.daemon import DaemonManager
    from vpsguard.watch import WatchDaemon

    # Load config
    cfg = load_config(config) if config else load_config()

    # Get interval from CLI or config
    watch_interval = interval or cfg.watch_schedule.interval

    # Handle status command
    if status:
        daemon_manager = DaemonManager()
        pid = daemon_manager.get_running_pid()
        if pid:
            console.print(f"[green]Watch daemon running (PID {pid})[/green]")
            # Show state from DB
            from vpsguard.history import HistoryDB
            db = HistoryDB()
            state = db.get_watch_state(log_file)
            if state:
                console.print(f"  Last run: {state.last_run_time}")
                console.print(f"  Total runs: {state.run_count}")
                console.print(f"  Byte offset: {state.byte_offset}")
        else:
            console.print("[yellow]No watch daemon running[/yellow]")
        raise typer.Exit()

    # Handle stop command
    if stop:
        daemon_manager = DaemonManager()
        pid = daemon_manager.get_running_pid()
        if pid:
            import os
            import signal
            os.kill(pid, signal.SIGTERM)
            console.print(f"[green]Sent shutdown signal to daemon (PID {pid})[/green]")
        else:
            console.print("[yellow]No watch daemon running[/yellow]")
        raise typer.Exit()

    # Validate log file exists
    log_path = Path(log_file)
    if not log_path.exists():
        console.print(f"[red]Error: Log file not found: {log_file}[/red]")
        raise typer.Exit(1)

    # Create daemon instance
    daemon = WatchDaemon(
        log_path=str(log_path),
        interval=watch_interval
    )

    # Run once mode (for testing/debug)
    if once:
        console.print(f"[cyan]Running single analysis cycle on {log_file}[/cyan]")
        result = daemon.run_once(cfg)
        console.print(f"[green]Analysis complete: {result['events']} events, {result['violations']} violations[/green]")
        raise typer.Exit()

    # Foreground mode (don't daemonize)
    if foreground:
        console.print(f"[cyan]Running in foreground mode (interval: {watch_interval})[/cyan]")
        console.print("[yellow]Press Ctrl+C to stop[/yellow]")

        try:
            while not daemon.daemon_manager.shutdown_requested:
                result = daemon.run_once(cfg)
                console.print(f"[green]{datetime.now().strftime('%H:%M:%S')} - {result['events']} events, {result['violations']} violations[/green]")

                # Sleep until next run
                time.sleep(daemon.interval_seconds)

        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down...[/yellow]")
        raise typer.Exit()

    # Daemon mode
    daemon.daemon_manager.start()

    console.print(f"[green]Watch daemon started[/green]")
    console.print(f"  Monitoring: {log_file}")
    console.print(f"  Interval: {watch_interval}")
    console.print(f"  PID: {os.getpid()}")
    console.print("\n[cyan]Use 'vpsguard watch --status' to check status[/cyan]")
    console.print("[cyan]Use 'vpsguard watch --stop' to stop daemon[/cyan]")

    # Main loop
    while not daemon.daemon_manager.shutdown_requested:
        try:
            daemon.run_once(cfg)
            time.sleep(daemon.interval_seconds)
        except Exception as e:
            logger.error(f"Error in watch loop: {e}")
            time.sleep(60)  # Wait before retry

    # Cleanup
    daemon.daemon_manager.stop()
```

---

**Step 2: Test watch command manually**

```bash
# Start watch in foreground mode
python -m vpsguard.cli watch test.log --foreground --interval 1m

# In another terminal, check status
python -m vpsguard.cli watch test.log --status

# Stop the daemon
python -m vpsguard.cli watch test.log --stop
```

---

**Step 3: Commit**

```bash
git add src/vpsguard/cli.py
git commit -m "feat: add watch CLI command"
```

---

## Task 6: HTML Reporter - Add Interactive Filtering

**Files:**
- Modify: `src/vpsguard/reporters/html.py`

**Step 1: Add JavaScript for filtering**

```python
# Modify src/vpsguard/reporters/html.py - update _generate_css() to include JS

    def _generate_css(self) -> str:
        """Generate embedded CSS styles and JavaScript."""
        return """<style>
    /* ... existing CSS styles ... */

    /* Filter Controls */
    .filter-controls {
        background: rgba(30, 41, 59, 0.8);
        padding: 1rem 1.5rem;
        border-radius: 0.75rem;
        margin-bottom: 2rem;
        border: 1px solid rgba(148, 163, 184, 0.1);
    }

    .filter-controls label {
        color: #cbd5e1;
        margin-right: 1rem;
        font-weight: 500;
    }

    .filter-controls select {
        background: #1e293b;
        color: #e2e8f0;
        border: 1px solid #475569;
        padding: 0.5rem 1rem;
        border-radius: 0.375rem;
        margin-right: 1rem;
    }

    .filter-controls input {
        background: #1e293b;
        color: #e2e8f0;
        border: 1px solid #475569;
        padding: 0.5rem 1rem;
        border-radius: 0.375rem;
        width: 200px;
    }

    .filter-stats {
        color: #94a3b8;
        font-size: 0.875rem;
        margin-left: auto;
    }

    .finding {
        /* Add data attribute for filtering */
        transition: opacity 0.2s;
    }

    .finding.hidden {
        display: none;
    }
</style>
<script>
function filterFindings() {
    const severityFilter = document.getElementById('severity-filter').value;
    const ipFilter = document.getElementById('ip-filter').value.toLowerCase();
    const timeFilter = document.getElementById('time-filter').value;

    const findings = document.querySelectorAll('.finding');
    let visibleCount = 0;

    findings.forEach(finding => {
        const severity = finding.getAttribute('data-severity');
        const ip = finding.getAttribute('data-ip');
        const time = finding.getAttribute('data-time');

        let show = true;

        if (severityFilter && severity !== severityFilter) {
            show = false;
        }

        if (ipFilter && !ip.includes(ipFilter)) {
            show = false;
        }

        if (timeFilter) {
            const findingTime = new Date(time);
            const now = new Date();
            const cutoff = new Date(now - timeFilter * 60 * 60 * 1000);
            if (findingTime < cutoff) {
                show = false;
            }
        }

        if (show) {
            finding.classList.remove('hidden');
            visibleCount++;
        } else {
            finding.classList.add('hidden');
        }
    });

    document.getElementById('visible-count').textContent = visibleCount;
}

// Add event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('severity-filter').addEventListener('change', filterFindings);
    document.getElementById('ip-filter').addEventListener('input', filterFindings);
    document.getElementById('time-filter').addEventListener('change', filterFindings);
});
</script>"""
```

---

**Step 2: Update header to include filter controls**

```python
# Modify src/vpsguard/reporters/html.py - update generate() method

    def generate(self, report: AnalysisReport) -> str:
        """Generate HTML report as string."""
        # ... existing code ...

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPSGuard Security Report - {report.timestamp.strftime('%Y-%m-%d')}</title>
    {self._generate_css()}
</head>
<body>
    <div class="container">
        {self._generate_header(report)}
        {self._generate_filter_controls()}
        {self._generate_summary(report, counts)}
        {self._generate_findings(violations_by_severity)}
        {self._generate_anomalies(report.anomalies)}
        {self._generate_drift_warning(report.baseline_drift)}
        {self._generate_footer(report)}
    </div>
</body>
</html>"""
        return html

    def _generate_filter_controls(self) -> str:
        """Generate filter control panel."""
        return """
        <div class="filter-controls">
            <label for="severity-filter">Severity:</label>
            <select id="severity-filter">
                <option value="">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>

            <label for="ip-filter">IP Address:</label>
            <input type="text" id="ip-filter" placeholder="Filter by IP...">

            <label for="time-filter">Last:</label>
            <select id="time-filter">
                <option value="">All time</option>
                <option value="1">Last 1 hour</option>
                <option value="6">Last 6 hours</option>
                <option value="24">Last 24 hours</option>
                <option value="168">Last 7 days</option>
            </select>

            <span class="filter-stats">
                Showing: <strong id="visible-count">0</strong> findings
            </span>
        </div>"""
```

---

**Step 3: Update findings rendering to include data attributes**

```python
# Modify src/vpsguard/reporters/html.py - update _render_finding()

    def _render_finding(self, violation: RuleViolation) -> str:
        """Render a single finding card."""
        severity_class = violation.severity.value.lower()

        return f"""
        <div class="finding"
             data-severity="{severity_class}"
             data-ip="{violation.ip}"
             data-time="{violation.timestamp.isoformat()}">
            <div class="finding-header {severity_class}">
                <span class="finding-title">{self._escape_html(violation.rule_name)}</span>
                <span class="finding-badge {severity_class}">{violation.severity.value.upper()}</span>
            </div>
            <div class="finding-body">
                {self._render_finding_details(violation)}
            </div>
        </div>"""

    def _render_finding_details(self, violation: RuleViolation) -> str:
        """Extract details rendering for reuse."""
        details_html = f"""
            <div class="finding-detail">
                <span class="label">IP Address:</span>
                <span class="value ip">{self._escape_html(violation.ip)}</span>
            </div>
            <div class="finding-detail">
                <span class="label">Timestamp:</span>
                <span class="value">{violation.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
            <div class="finding-detail">
                <span class="label">Description:</span>
                <span class="value">{self._escape_html(violation.description)}</span>
            </div>"""

        if violation.details:
            for key, value in violation.details.items():
                key_formatted = key.replace('_', ' ').title()
                details_html += f"""
            <div class="finding-detail">
                <span class="label">{self._escape_html(key_formatted)}:</span>
                <span class="value">{self._escape_html(str(value))}</span>
            </div>"""

        return details_html
```

---

**Step 4: Commit**

```bash
git add src/vpsguard/reporters/html.py
git commit -m "feat: add interactive filtering to HTML reporter"
```

---

## Task 7: History Verification Tests

**Files:**
- Modify: `tests/test_history.py`

**Step 1: Add comprehensive history tests**

```python
# Add to tests/test_history.py

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
    assert violations[0]['severity'] == 'CRITICAL'


def test_history_anomalies_persisted(history_db, sample_report):
    """Should persist all anomaly data."""
    run_id = history_db.save_run(sample_report)

    anomalies = history_db.get_run_anomalies(run_id)

    assert len(anomalies) == 1
    assert anomalies[0]['ip'] == '10.0.0.50'
    assert anomalies[0]['score'] > 0


def test_history_cleanup_old_runs(history_db):
    """Should delete runs older than specified days."""
    from datetime import datetime, timedelta, timezone

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
```

---

**Step 2: Run tests**

```bash
python -m pytest tests/test_history.py -v
```

---

**Step 3: Commit**

```bash
git add tests/test_history.py
git commit -m "test: add comprehensive history verification tests"
```

---

## Task 8: Performance Benchmarking

**Files:**
- Create: `tests/benchmark.py`

**Step 1: Create benchmark script**

```python
# tests/benchmark.py
"""Performance benchmarks for VPSGuard."""

import time
import pytest
from pathlib import Path
from vpsguard.parsers import get_parser
from vpsguard.rules.engine import RuleEngine
from vpsguard.config import VPSGuardConfig


def test_parse_100k_lines_performance(tmp_path):
    """Benchmark: Parse 100K log lines in under 10 seconds."""
    # Generate test data
    log_file = tmp_path / "benchmark.log"
    generate_test_logs(log_file, lines=100000)

    config = VPSGuardConfig()
    parser = get_parser(str(log_file))

    start = time.time()

    events = []
    with open(log_file) as f:
        for line in f:
            event = parser.parse_line(line.strip())
            if event:
                events.append(event)

    elapsed = time.time() - start

    print(f"\nParsed {len(events)} events in {elapsed:.2f}s")
    print(f"Rate: {len(events)/elapsed:.0f} events/second")

    assert elapsed < 10.0, f"Parsing took {elapsed:.2f}s, target is <10s"


def test_analysis_100k_lines_performance(tmp_path):
    """Benchmark: Full analysis (parse + rules) on 100K lines in under 10s."""
    log_file = tmp_path / "benchmark.log"
    generate_test_logs(log_file, lines=100000)

    config = VPSGuardConfig()
    parser = get_parser(str(log_file))
    rule_engine = RuleEngine(config.rules, config.whitelist_ips)

    start = time.time()

    violations = []
    with open(log_file) as f:
        for line in f:
            event = parser.parse_line(line.strip())
            if event:
                event_violations = rule_engine.check_event(event)
                violations.extend(event_violations)

    elapsed = time.time() - start

    print(f"\nAnalyzed {len(violations)} violations in {elapsed:.2f}s")
    print(f"Rate: {100000/elapsed:.0f} lines/second")

    assert elapsed < 10.0, f"Analysis took {elapsed:.2f}s, target is <10s"


def generate_test_logs(path: Path, lines: int = 1000):
    """Generate test log entries for benchmarking."""
    from vpsguard.generators import SyntheticLogGenerator, GeneratorConfig

    config = GeneratorConfig(
        total_lines=lines,
        output_format="auth.log",
        seed=42
    )

    generator = SyntheticLogGenerator(config)
    generator.generate(str(path))


if __name__ == "__main__":
    import tempfile
    import sys

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        print("=" * 60)
        print("VPSGuard Performance Benchmarks")
        print("=" * 60)

        print("\n[1/2] Parsing 100K lines...")
        test_parse_100k_lines_performance(tmp_path)

        print("\n[2/2] Analyzing 100K lines (parse + rules)...")
        test_analysis_100k_lines_performance(tmp_path)

        print("\n" + "=" * 60)
        print("All benchmarks passed!")
        print("=" * 60)
```

---

**Step 2: Run benchmarks**

```bash
python tests/benchmark.py
```

Expected output:
```
Parsed 50000 events in 3.45s
Rate: 14492 events/second
Analyzed 234 violations in 5.67s
Rate: 17636 lines/second
All benchmarks passed!
```

---

**Step 3: Commit**

```bash
git add tests/benchmark.py
git commit -m "test: add performance benchmarks for 100K log lines"
```

---

## Task 9: Documentation Updates

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `docs/plans/2024-12-30-vpsguard-design.md`

**Step 1: Update README.md with watch command**

```markdown
# Add to README.md after "Analyze Logs" section

### Watch Logs (Continuous Monitoring)

```bash
# Start watching a log file (daemon mode)
vpsguard watch /var/log/auth.log

# Run in foreground (for testing/debug)
vpsguard watch /var/log/auth.log --foreground

# Run single analysis cycle
vpsguard watch /var/log/auth.log --once

# Check if daemon is running
vpsguard watch /var/log/auth.log --status

# Stop the daemon
vpsguard watch /var/log/auth.log --stop

# Custom interval
vpsguard watch /var/log/auth.log --interval 30m
```

**Watch mode configuration:**

The watch daemon runs scheduled batch analysis at configured intervals:

```toml
[watch.schedule]
# How often to run analysis
interval = "1h"  # 5m, 15m, 30m, 1h, 6h, 12h, 24h

# How many days of history to keep
retention_days = 30

# Alert thresholds
[watch.schedule.alerts]
critical_threshold = 1   # Alert if 1+ new critical findings
high_threshold = 5       # Alert if 5+ new high findings
anomaly_threshold = 3    # Alert if 3+ new anomalies

[watch.output]
directory = "~/.vpsguard/reports"
formats = ["markdown", "json", "html"]
```
```

---

**Step 2: Update CLAUDE.md with watch architecture**

```markdown
# Add to CLAUDE.md under "Architecture" section

## Watch Daemon Architecture

The watch command provides scheduled batch monitoring:

```
vpsguard watch /var/log/auth.log
  │
  ├─► Daemonize (PID file: ~/.vpsguard/watch.pid)
  ├─► Load watch state from SQLite
  │
  └─► [Event Loop]
       │
       ├─► Parse log incrementally (track byte_offset)
       ├─► Detect log rotation (inode change)
       ├─► Run full analysis (rules + ML)
       ├─► Save state to SQLite
       ├─► Check alert thresholds
       ├─► Generate report
       │
       └─► Sleep until next interval
```

**Key files:**
- `src/vpsguard/watch.py` — WatchDaemon class
- `src/vpsguard/daemon.py` — DaemonManager (PID, signals)
- `src/vpsguard/config.py` — WatchScheduleConfig, WatchAlertConfig
- `src/vpsguard/history.py` — WatchState persistence
```

---

**Step 3: Update design doc with Phase 4-5 status**

```markdown
# Update docs/plans/2024-12-30-vpsguard-design.md

## Phase 4-5 Status: ✅ COMPLETE

- [x] nginx parser
- [x] syslog parser
- [x] HTML reporter
- [x] SQLite history
- [x] Watch command (scheduled batch mode)
- [x] Daemon mode (PID file, signals)
- [x] Watch state persistence
- [x] Alert thresholds
- [x] Performance benchmarks
- [x] Documentation

**Removed from scope:**
- ~GeoIP integration~ (decided against)
```

---

**Step 4: Commit documentation**

```bash
git add README.md CLAUDE.md docs/plans/2024-12-30-vpsguard-design.md
git commit -m "docs: update documentation for watch command and Phase 4-5"
```

---

## Task 10: Integration Testing & Final Verification

**Step 1: Run full test suite**

```bash
python -m pytest tests/ -v --cov=vpsguard
```

Expected: All 226+ tests pass, coverage >90%

---

**Step 2: Manual integration test**

```bash
# Generate test data
python -m vpsguard.cli generate --entries 1000 --attack-profile botnet:0.1 --output /tmp/test.log

# Start watch in foreground
python -m vpsguard.cli watch /tmp/test.log --foreground --interval 30s

# In another terminal, append more data
python -m vpsguard.cli generate --entries 500 --attack-profile breach:0.05 >> /tmp/test.log

# Verify watch detects new entries
```

---

**Step 3: Verify git status**

```bash
git status
```

Expected: Clean working tree (all changes committed)

---

**Step 4: Beads sync**

```bash
bd sync
```

---

**Step 5: Close completed beads issues**

```bash
bd close vps-guard-w1f vps-guard-7lc vps-guard-cc3 vps-guard-njb vps-guard-mdq vps-guard-33h vps-guard-6iq
```

---

**Step 6: Final commit and push**

```bash
git pull --rebase
git push
git status  # Should show "up to date with origin"
```

---

## Summary

This plan implements:

1. **Config schema** - WatchScheduleConfig, WatchAlertConfig, WatchOutputConfig
2. **SQLite extensions** - watch_state table for incremental parsing
3. **Daemon manager** - PID file, signal handling (SIGTERM/SIGINT)
4. **Watch daemon** - Core logic: incremental parsing, log rotation detection
5. **CLI command** - `vpsguard watch` with --foreground, --status, --stop
6. **HTML enhancements** - Interactive filtering (severity, IP, time)
7. **History verification** - Tests for state persistence
8. **Benchmarks** - 100K lines target <10s
9. **Documentation** - README, CLAUDE.md, design doc

**Total scope:** ~10 tasks, ~50 steps, following TDD with frequent commits.
