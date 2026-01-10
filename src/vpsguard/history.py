"""SQLite-based history storage for VPSGuard analysis runs."""

import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from dataclasses import asdict

from vpsguard.models.events import AnalysisReport, RuleViolation, AnomalyResult, Severity, Confidence, WatchState


def validate_db_path(path: Path) -> Path:
    """Validate that a database path is safe to use.

    Prevents path traversal attacks by ensuring paths are within safe directories.

    Args:
        path: The path to validate.

    Returns:
        Validated Path object.

    Raises:
        ValueError: If the path uses traversal or is in a restricted location.
    """
    # Check for path traversal attempts
    if '..' in path.parts:
        raise ValueError(
            f"Path traversal not allowed: {path}. "
            "Use direct paths without '..' components."
        )

    # Get the resolved absolute path
    try:
        resolved = path.resolve()
    except (OSError, ValueError) as e:
        raise ValueError(f"Invalid path: {path} - {e}")

    # Define safe base directories
    cwd = Path.cwd().resolve()
    home = Path.home().resolve()
    vpsguard_dir = (home / ".vpsguard").resolve()

    # For relative paths, they resolve relative to cwd (safe)
    if not path.is_absolute():
        return resolved

    # For absolute paths, check against safe directories
    safe_bases = [cwd, home, vpsguard_dir]
    for safe_base in safe_bases:
        try:
            resolved.relative_to(safe_base)
            return resolved
        except ValueError:
            continue

    raise ValueError(
        f"Database path must be within current directory, home, or ~/.vpsguard: {path}"
    )


class HistoryDB:
    """SQLite database for storing analysis history.

    Stores:
    - Run history (timestamp, files analyzed, findings)
    - Violation details for trend analysis
    - Anomaly history for tracking IPs over time
    """

    DEFAULT_PATH = Path.home() / ".vpsguard" / "history.db"

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize the history database.

        Args:
            db_path: Path to the SQLite database file.
                     Defaults to ~/.vpsguard/history.db

        Raises:
            ValueError: If db_path uses path traversal or is in a restricted location.
        """
        # Validate path if provided (DEFAULT_PATH is always safe)
        if db_path is not None:
            self.db_path = validate_db_path(db_path)
        else:
            self.db_path = self.DEFAULT_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    log_source TEXT NOT NULL,
                    total_events INTEGER NOT NULL,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    anomaly_count INTEGER DEFAULT 0,
                    drift_detected INTEGER DEFAULT 0
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS violations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    description TEXT,
                    timestamp TEXT NOT NULL,
                    details TEXT,
                    FOREIGN KEY (run_id) REFERENCES runs(id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    score REAL NOT NULL,
                    confidence TEXT NOT NULL,
                    explanation TEXT,
                    FOREIGN KEY (run_id) REFERENCES runs(id)
                )
            """)

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

            # Create indexes for common queries
            conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON runs(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_violations_ip ON violations(ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_violations_severity ON violations(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_ip ON anomalies(ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_watch_state_path ON watch_state(log_path)")

            conn.commit()

    def save_run(self, report: AnalysisReport) -> int:
        """Save an analysis run to the database.

        Args:
            report: The AnalysisReport to save.

        Returns:
            The run ID of the saved record.
        """
        # Count violations by severity
        critical = sum(1 for v in report.rule_violations if v.severity == Severity.CRITICAL)
        high = sum(1 for v in report.rule_violations if v.severity == Severity.HIGH)
        medium = sum(1 for v in report.rule_violations if v.severity == Severity.MEDIUM)
        low = sum(1 for v in report.rule_violations if v.severity == Severity.LOW)
        anomaly_count = len(report.anomalies) if report.anomalies else 0
        drift = 1 if report.baseline_drift and report.baseline_drift.get('drift_detected') else 0

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO runs (
                    timestamp, log_source, total_events,
                    critical_count, high_count, medium_count, low_count,
                    anomaly_count, drift_detected
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.timestamp.isoformat(),
                report.log_source,
                report.total_events,
                critical, high, medium, low,
                anomaly_count, drift
            ))

            run_id = cursor.lastrowid

            # Save violations
            for violation in report.rule_violations:
                details_json = json.dumps(violation.details) if violation.details else None
                conn.execute("""
                    INSERT INTO violations (
                        run_id, rule_name, severity, ip, description, timestamp, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    run_id,
                    violation.rule_name,
                    violation.severity.value,
                    violation.ip,
                    violation.description,
                    violation.timestamp.isoformat(),
                    details_json
                ))

            # Save anomalies
            if report.anomalies:
                for anomaly in report.anomalies:
                    explanation_json = json.dumps(anomaly.explanation)
                    conn.execute("""
                        INSERT INTO anomalies (
                            run_id, ip, score, confidence, explanation
                        ) VALUES (?, ?, ?, ?, ?)
                    """, (
                        run_id,
                        anomaly.ip,
                        anomaly.score,
                        anomaly.confidence.value,
                        explanation_json
                    ))

            conn.commit()
            return run_id

    def save_watch_state(self, state: 'WatchState') -> int:
        """Save or update watch daemon state.

        Args:
            state: WatchState instance to persist.

        Returns:
            The row ID of the saved/updated record.
        """
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

    def get_watch_state(self, log_path: str) -> Optional['WatchState']:
        """Get watch state for a specific log path.

        Args:
            log_path: Path to the log file.

        Returns:
            WatchState instance or None if not found.
        """
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

    def get_recent_runs(self, limit: int = 10) -> list[dict]:
        """Get recent analysis runs.

        Args:
            limit: Maximum number of runs to return.

        Returns:
            List of run dictionaries.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM runs
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    def get_run(self, run_id: int) -> Optional[dict]:
        """Get a specific run by ID.

        Args:
            run_id: The run ID to retrieve.

        Returns:
            Run dictionary or None if not found.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_run_violations(self, run_id: int) -> list[dict]:
        """Get violations for a specific run.

        Args:
            run_id: The run ID.

        Returns:
            List of violation dictionaries.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM violations
                WHERE run_id = ?
                ORDER BY severity, timestamp
            """, (run_id,))

            return [dict(row) for row in cursor.fetchall()]

    def get_run_anomalies(self, run_id: int) -> list[dict]:
        """Get anomalies for a specific run.

        Args:
            run_id: The run ID.

        Returns:
            List of anomaly dictionaries.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM anomalies
                WHERE run_id = ?
                ORDER BY score DESC
            """, (run_id,))

            return [dict(row) for row in cursor.fetchall()]

    def get_ip_history(self, ip: str, days: int = 30) -> dict:
        """Get history for a specific IP address.

        Args:
            ip: The IP address to look up.
            days: Number of days to look back.

        Returns:
            Dictionary with violation and anomaly counts.
        """
        with sqlite3.connect(self.db_path) as conn:
            # Get violation counts
            cursor = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM violations
                WHERE ip = ?
                AND timestamp >= datetime('now', ?)
                GROUP BY severity
            """, (ip, f'-{days} days'))

            violation_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # Get anomaly history
            cursor = conn.execute("""
                SELECT COUNT(*) as count, AVG(score) as avg_score
                FROM anomalies a
                JOIN runs r ON a.run_id = r.id
                WHERE a.ip = ?
                AND r.timestamp >= datetime('now', ?)
            """, (ip, f'-{days} days'))

            anomaly_row = cursor.fetchone()

            return {
                "ip": ip,
                "days": days,
                "violations": violation_counts,
                "total_violations": sum(violation_counts.values()),
                "anomaly_count": anomaly_row[0] if anomaly_row else 0,
                "avg_anomaly_score": anomaly_row[1] if anomaly_row and anomaly_row[1] else 0.0,
            }

    def get_top_offenders(self, days: int = 30, limit: int = 10) -> list[dict]:
        """Get IPs with the most violations.

        Args:
            days: Number of days to look back.
            limit: Maximum number of IPs to return.

        Returns:
            List of IP dictionaries with violation counts.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT
                    ip,
                    COUNT(*) as total,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
                FROM violations
                WHERE timestamp >= datetime('now', ?)
                GROUP BY ip
                ORDER BY total DESC
                LIMIT ?
            """, (f'-{days} days', limit))

            return [
                {
                    "ip": row[0],
                    "total": row[1],
                    "critical": row[2],
                    "high": row[3],
                    "medium": row[4],
                    "low": row[5],
                }
                for row in cursor.fetchall()
            ]

    def compare_runs(self, run_id_old: int, run_id_new: int) -> dict:
        """Compare two runs to show changes.

        Args:
            run_id_old: The older run ID.
            run_id_new: The newer run ID.

        Returns:
            Dictionary with comparison data.
        """
        old_run = self.get_run(run_id_old)
        new_run = self.get_run(run_id_new)

        if not old_run or not new_run:
            return {"error": "Run not found"}

        old_violations = self.get_run_violations(run_id_old)
        new_violations = self.get_run_violations(run_id_new)

        old_ips = {v['ip'] for v in old_violations}
        new_ips = {v['ip'] for v in new_violations}

        return {
            "old_run": old_run,
            "new_run": new_run,
            "events_delta": new_run['total_events'] - old_run['total_events'],
            "critical_delta": new_run['critical_count'] - old_run['critical_count'],
            "high_delta": new_run['high_count'] - old_run['high_count'],
            "medium_delta": new_run['medium_count'] - old_run['medium_count'],
            "low_delta": new_run['low_count'] - old_run['low_count'],
            "new_ips": list(new_ips - old_ips),
            "gone_ips": list(old_ips - new_ips),
            "persistent_ips": list(old_ips & new_ips),
        }

    def get_trend(self, days: int = 7) -> list[dict]:
        """Get daily trend of findings.

        Args:
            days: Number of days to include.

        Returns:
            List of daily summaries.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT
                    date(timestamp) as day,
                    SUM(critical_count) as critical,
                    SUM(high_count) as high,
                    SUM(medium_count) as medium,
                    SUM(low_count) as low,
                    SUM(anomaly_count) as anomalies,
                    COUNT(*) as runs
                FROM runs
                WHERE timestamp >= datetime('now', ?)
                GROUP BY date(timestamp)
                ORDER BY day DESC
            """, (f'-{days} days',))

            return [
                {
                    "date": row[0],
                    "critical": row[1],
                    "high": row[2],
                    "medium": row[3],
                    "low": row[4],
                    "anomalies": row[5],
                    "runs": row[6],
                }
                for row in cursor.fetchall()
            ]

    def cleanup_old_runs(self, days: int = 90) -> int:
        """Delete runs older than specified days.

        Args:
            days: Delete runs older than this many days.

        Returns:
            Number of runs deleted.
        """
        with sqlite3.connect(self.db_path) as conn:
            # Get IDs of old runs
            cursor = conn.execute("""
                SELECT id FROM runs
                WHERE timestamp < datetime('now', ?)
            """, (f'-{days} days',))

            old_ids = [row[0] for row in cursor.fetchall()]

            if old_ids:
                placeholders = ','.join('?' * len(old_ids))

                # Delete violations
                conn.execute(f"DELETE FROM violations WHERE run_id IN ({placeholders})", old_ids)

                # Delete anomalies
                conn.execute(f"DELETE FROM anomalies WHERE run_id IN ({placeholders})", old_ids)

                # Delete runs
                conn.execute(f"DELETE FROM runs WHERE id IN ({placeholders})", old_ids)

                conn.commit()

            return len(old_ids)
