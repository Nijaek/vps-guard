"""JSON reporter for machine-readable output."""

import json
from pathlib import Path

from vpsguard.models.events import AnalysisReport, RuleViolation, Severity


class JSONReporter:
    """JSON reporter for machine consumption.

    Outputs complete report as JSON for:
    - API integrations
    - Automated processing
    - Data pipelines
    - Storage in databases
    """

    name = "json"

    def __init__(self, indent: int = 2):
        """Initialize JSON reporter.

        Args:
            indent: Number of spaces for JSON indentation (None for compact).
        """
        self.indent = indent

    def generate(self, report: AnalysisReport) -> str:
        """Generate JSON report as string.

        Args:
            report: AnalysisReport containing violations and metadata.

        Returns:
            JSON-formatted report as a string.
        """
        data = self._serialize_report(report)
        return json.dumps(data, indent=self.indent)

    def generate_to_file(self, report: AnalysisReport, path: str) -> None:
        """Generate report and write to file.

        Args:
            report: AnalysisReport containing violations and metadata.
            path: File path to write the report to.
        """
        output = self.generate(report)
        Path(path).write_text(output, encoding="utf-8")

    def _serialize_report(self, report: AnalysisReport) -> dict:
        """Convert AnalysisReport to JSON-serializable dict.

        Args:
            report: AnalysisReport to serialize.

        Returns:
            Dictionary ready for JSON serialization.
        """
        # Count violations by severity
        severity_counts = {}
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = sum(1 for v in report.rule_violations if v.severity == severity)
            severity_counts[severity.value] = count

        return {
            "metadata": {
                "timestamp": report.timestamp.isoformat(),
                "log_source": report.log_source,
                "total_events": report.total_events,
                "report_version": "1.0",
            },
            "summary": {
                "total_violations": len(report.rule_violations),
                "total_anomalies": len(report.anomalies),
                "severity_counts": severity_counts,
            },
            "rule_violations": [
                self._serialize_violation(v) for v in report.rule_violations
            ],
            "anomalies": [
                self._serialize_anomaly(a) for a in report.anomalies
            ],
            "baseline_drift": report.baseline_drift,
        }

    def _serialize_violation(self, violation: RuleViolation) -> dict:
        """Convert RuleViolation to JSON-serializable dict.

        Args:
            violation: RuleViolation to serialize.

        Returns:
            Dictionary ready for JSON serialization.
        """
        return {
            "rule_name": violation.rule_name,
            "severity": violation.severity.value,
            "ip": violation.ip,
            "timestamp": violation.timestamp.isoformat(),
            "description": violation.description,
            "details": violation.details,
            "affected_events_count": len(violation.affected_events),
        }

    def _serialize_anomaly(self, anomaly) -> dict:
        """Convert AnomalyResult to JSON-serializable dict.

        Args:
            anomaly: AnomalyResult to serialize.

        Returns:
            Dictionary ready for JSON serialization.
        """
        return {
            "ip": anomaly.ip,
            "score": anomaly.score,
            "confidence": anomaly.confidence.value,
            "explanation": anomaly.explanation,
            "features": anomaly.features,
        }
