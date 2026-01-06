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

        result = {
            "metadata": {
                "timestamp": report.timestamp.isoformat(),
                "log_source": report.log_source,
                "total_events": report.total_events,
                "report_version": "1.0",
                "geoip_enabled": report.geo_data is not None,
            },
            "summary": {
                "total_violations": len(report.rule_violations),
                "total_anomalies": len(report.anomalies),
                "severity_counts": severity_counts,
            },
            "rule_violations": [
                self._serialize_violation(v, report.geo_data) for v in report.rule_violations
            ],
            "anomalies": [
                self._serialize_anomaly(a, report.geo_data) for a in report.anomalies
            ],
            "baseline_drift": report.baseline_drift,
        }

        # Add geo_data section if available
        if report.geo_data:
            result["geo_data"] = {
                ip: self._serialize_geo(geo) for ip, geo in report.geo_data.items()
            }

        return result

    def _serialize_violation(self, violation: RuleViolation, geo_data: dict | None = None) -> dict:
        """Convert RuleViolation to JSON-serializable dict.

        Args:
            violation: RuleViolation to serialize.
            geo_data: Optional dict mapping IP to GeoLocation.

        Returns:
            Dictionary ready for JSON serialization.
        """
        result = {
            "rule_name": violation.rule_name,
            "severity": violation.severity.value,
            "ip": violation.ip,
            "timestamp": violation.timestamp.isoformat(),
            "description": violation.description,
            "details": violation.details,
            "affected_events_count": len(violation.affected_events),
        }

        # Add geo info if available
        if geo_data and violation.ip in geo_data:
            geo = geo_data[violation.ip]
            if geo.is_known:
                result["location"] = str(geo)

        return result

    def _serialize_anomaly(self, anomaly, geo_data: dict | None = None) -> dict:
        """Convert AnomalyResult to JSON-serializable dict.

        Args:
            anomaly: AnomalyResult to serialize.
            geo_data: Optional dict mapping IP to GeoLocation.

        Returns:
            Dictionary ready for JSON serialization.
        """
        result = {
            "ip": anomaly.ip,
            "score": anomaly.score,
            "confidence": anomaly.confidence.value,
            "explanation": anomaly.explanation,
            "features": anomaly.features,
        }

        # Add geo info if available
        if geo_data and anomaly.ip in geo_data:
            geo = geo_data[anomaly.ip]
            if geo.is_known:
                result["location"] = str(geo)

        return result

    def _serialize_geo(self, geo) -> dict:
        """Convert GeoLocation to JSON-serializable dict.

        Args:
            geo: GeoLocation to serialize.

        Returns:
            Dictionary ready for JSON serialization.
        """
        return {
            "country_code": geo.country_code,
            "country_name": geo.country_name,
            "city": geo.city,
            "latitude": geo.latitude,
            "longitude": geo.longitude,
        }
