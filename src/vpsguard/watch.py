"""Watch daemon for scheduled batch analysis."""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from vpsguard.daemon import DaemonManager
from vpsguard.history import HistoryDB
from vpsguard.models.events import Severity, WatchState
from vpsguard.parsers import enrich_with_source, get_parser

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


def detect_log_format(log_path: str) -> str:
    """Detect log format from file path.

    Args:
        log_path: Path to log file.

    Returns:
        Format type string for get_parser().
    """
    path = Path(log_path)
    name = path.name.lower()

    if 'auth' in name:
        return 'auth.log'
    elif 'secure' in name:
        return 'secure'
    elif 'nginx' in name or 'access' in name:
        return 'nginx'
    elif 'journal' in name:
        return 'journald'
    else:
        # Default to syslog format
        return 'syslog'


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
        daemon_manager: Optional[DaemonManager] = None,
        log_format: Optional[str] = None,
        model_path: Optional[str] = None,
        with_ml: bool = True,
        score_threshold: float = 0.6,
    ):
        """Initialize watch daemon.

        Args:
            log_path: Path to log file to monitor.
            interval: Schedule interval (e.g., "5m", "1h").
            history_db: HistoryDB instance. Creates default if None.
            daemon_manager: DaemonManager instance. Creates default if None.
            log_format: Log format (e.g., "auth.log", "syslog"). Auto-detected if None.
        """
        self.log_path = Path(log_path)
        self.interval_seconds = parse_interval(interval)
        self.history_db = history_db or HistoryDB()
        self.daemon_manager = daemon_manager or DaemonManager()
        self.log_format = log_format or detect_log_format(log_path)
        self.model_path = model_path
        self.with_ml = with_ml
        self.score_threshold = score_threshold

        self._state: Optional[WatchState] = None

    def get_state(self) -> WatchState:
        """Get current watch state, loading from DB if needed."""
        if self._state is None:
            self._state = self.history_db.get_watch_state(str(self.log_path))
            if self._state is None:
                # Initialize new state
                inode = self._get_inode() if self.log_path.exists() else 0
                self._state = WatchState(
                    log_path=str(self.log_path),
                    inode=inode,
                    byte_offset=0,
                    last_run_time=datetime.now(timezone.utc),
                    run_count=0,
                    last_findings_counts={}
                )
        return self._state

    def _get_inode(self) -> int:
        """Get file inode to detect log rotation.

        On Unix, uses the actual inode.
        On Windows, uses file creation time as a proxy (stable across appends).
        """
        if os.name == 'nt':  # Windows
            # Use file creation time as proxy for inode
            # This is stable across appends but changes on file recreation
            stat = self.log_path.stat()
            return hash(stat.st_ctime)
        else:
            return self.log_path.stat().st_ino

    def _detect_inode_change(self) -> bool:
        """Check if log file was rotated.

        Detects rotation via:
        - Inode change (Unix)
        - Creation time change (Windows)
        - File size smaller than saved offset (fallback for all platforms)

        Returns:
            True if inode changed (log rotated), False otherwise.
        """
        if not self.log_path.exists():
            return False

        current_inode = self._get_inode()
        current_size = self.log_path.stat().st_size
        state = self.get_state()

        rotated = False

        # Check if file was rotated (inode/creation time changed)
        if current_inode != state.inode:
            logger.info(f"Log rotation detected (inode {state.inode} -> {current_inode})")
            rotated = True

        # Also detect if file is smaller than our offset (truncated/rotated)
        if current_size < state.byte_offset:
            logger.info(f"Log rotation detected (file size {current_size} < offset {state.byte_offset})")
            rotated = True

        if rotated:
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

        parser = get_parser(self.log_format)

        with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(state.byte_offset)
            new_content = f.read()
            new_offset = f.tell()

        # Parse the new content
        if new_content.strip():
            parsed = parser.parse(new_content)
            enrich_with_source(parsed, source=str(self.log_path))
            events = parsed.events
        else:
            events = []

        # Update offset
        state.byte_offset = new_offset

        return events

    @staticmethod
    def should_alert(
        current_findings: list,
        last_counts: dict,
        thresholds: dict,
        anomaly_count: int = 0,
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
            if current_counts.get('critical', 0) >= thresholds['critical_threshold']:
                return True

        # Check high threshold
        if thresholds.get('high_threshold', 0) > 0:
            if current_counts.get('high', 0) >= thresholds['high_threshold']:
                return True

        # Check anomaly threshold
        if thresholds.get('anomaly_threshold', 0) > 0:
            if anomaly_count >= thresholds['anomaly_threshold']:
                return True

        return False

    def run_once(self, config) -> dict:
        """Run single analysis cycle.

        Args:
            config: VPSGuardConfig instance.

        Returns:
            Dict with run results (events count, findings count, etc.)
        """
        from vpsguard.rules.engine import RuleEngine

        # Parse log
        events = self.parse_log()

        if not events:
            return {
                "events": 0,
                "violations": 0,
                "anomalies": 0,
                "findings_counts": {},
                "alert_triggered": False,
                "reports_written": [],
            }

        # Optional GeoIP lookups for geo-velocity detection
        geo_data = None
        if config.geoip.enabled:
            try:
                from vpsguard.geo import GeoIPReader, get_database_info

                db_path = Path(config.geoip.database_path).expanduser()
                db_info = get_database_info(db_path)
                if db_info.exists:
                    ips = {event.ip for event in events if event.ip}
                    if ips:
                        with GeoIPReader(db_info.path) as reader:
                            geo_data = {ip: reader.lookup(ip) for ip in ips}
            except Exception as e:
                logger.debug(f"GeoIP lookup skipped: {e}")

        # Run rules
        rule_engine = RuleEngine(config)
        output = rule_engine.evaluate(events, geo_data=geo_data)
        violations = output.violations
        clean_events = output.clean_events

        # Run ML if model available (optional)
        anomalies = []
        baseline_drift = None
        try:
            if self.with_ml and self.model_path and Path(self.model_path).exists():
                from vpsguard.ml.engine import MLEngine
                ml_engine = MLEngine()
                ml_engine.load(Path(self.model_path))
                anomalies = ml_engine.detect(clean_events, score_threshold=self.score_threshold)
                baseline_drift = ml_engine.detect_drift(clean_events, threshold=2.0)
        except Exception as e:
            logger.debug(f"ML analysis skipped: {e}")

        # Generate report if thresholds are met
        state = self.get_state()
        alert_triggered = self.should_alert(
            violations,
            state.last_findings_counts,
            config.watch_schedule.alerts,
            anomaly_count=len(anomalies),
        )
        reports_written: list[str] = []

        if alert_triggered:
            from vpsguard.models.events import AnalysisReport
            from vpsguard.reporters import get_reporter

            report = AnalysisReport(
                timestamp=datetime.now(timezone.utc),
                log_source=str(self.log_path),
                total_events=len(events),
                rule_violations=violations,
                anomalies=anomalies,
                baseline_drift=baseline_drift,
                summary=None,
                geo_data=geo_data,
            )

            output_dir = Path(config.watch_output.directory).expanduser()
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            stem = self.log_path.stem

            ext_map = {
                "terminal": "txt",
                "markdown": "md",
                "json": "json",
                "html": "html",
            }

            for fmt in config.watch_output.formats:
                reporter = get_reporter(fmt)
                ext = ext_map.get(fmt, "txt")
                file_name = f"vpsguard-{stem}-{timestamp}.{ext}"
                output_path = output_dir / file_name
                reporter.generate_to_file(report, str(output_path))
                reports_written.append(str(output_path))

        # Save state
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
            "findings_counts": state.last_findings_counts,
            "alert_triggered": alert_triggered,
            "reports_written": reports_written,
        }
