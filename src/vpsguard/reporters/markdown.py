"""Markdown reporter for generating documentation-ready reports."""

from pathlib import Path
from collections import defaultdict

from vpsguard.models.events import AnalysisReport, RuleViolation, Severity


class MarkdownReporter:
    """Markdown reporter for documentation and sharing.

    Generates clean markdown reports that can be:
    - Committed to version control
    - Shared in documentation
    - Converted to HTML/PDF
    - Read in any text editor
    """

    name = "markdown"

    def generate(self, report: AnalysisReport) -> str:
        """Generate markdown report as string.

        Args:
            report: AnalysisReport containing violations and metadata.

        Returns:
            Markdown-formatted report as a string.
        """
        lines = []

        # Header
        lines.append("# VPSGuard Security Report")
        lines.append("")
        lines.append(f"**Generated:** {report.timestamp.strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"**Log Source:** {report.log_source}")
        lines.append(f"**Events Scanned:** {report.total_events:,}")
        lines.append("")

        # Summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")

        # Count violations by severity
        counts = defaultdict(int)
        for violation in report.rule_violations:
            counts[violation.severity] += 1

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = counts.get(severity, 0)
            lines.append(f"| {severity.value.title()} | {count} |")

        lines.append("")

        # Group violations by severity
        violations_by_severity = self._group_by_severity(report.rule_violations)

        # Render each severity level
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

        for severity in severity_order:
            violations = violations_by_severity.get(severity, [])
            if violations:
                lines.extend(self._render_severity_section(severity, violations, report.geo_data))

        # If no violations
        if not report.rule_violations:
            lines.append("## Findings")
            lines.append("")
            lines.append("No security violations detected.")
            lines.append("")

        return "\n".join(lines)

    def generate_to_file(self, report: AnalysisReport, path: str) -> None:
        """Generate report and write to file.

        Args:
            report: AnalysisReport containing violations and metadata.
            path: File path to write the report to.
        """
        output = self.generate(report)
        Path(path).write_text(output, encoding="utf-8")

    def _group_by_severity(self, violations: list[RuleViolation]) -> dict[Severity, list[RuleViolation]]:
        """Group violations by severity level.

        Args:
            violations: List of rule violations.

        Returns:
            Dictionary mapping severity to list of violations.
        """
        grouped = defaultdict(list)
        for violation in violations:
            grouped[violation.severity].append(violation)
        return grouped

    def _render_severity_section(
        self,
        severity: Severity,
        violations: list[RuleViolation],
        geo_data: dict | None = None
    ) -> list[str]:
        """Render markdown section for a specific severity level.

        Args:
            severity: Severity level.
            violations: List of violations at this severity.
            geo_data: Optional dict mapping IP to GeoLocation.

        Returns:
            List of markdown lines.
        """
        lines = []

        # Section header
        lines.append(f"## {severity.value.title()} Findings")
        lines.append("")

        # Render each violation
        for violation in violations:
            lines.extend(self._render_violation(violation, geo_data))

        return lines

    def _render_violation(self, violation: RuleViolation, geo_data: dict | None = None) -> list[str]:
        """Render a single violation in markdown.

        Args:
            violation: RuleViolation to render.
            geo_data: Optional dict mapping IP to GeoLocation.

        Returns:
            List of markdown lines.
        """
        lines = []

        # Violation header
        lines.append(f"### {violation.rule_name}")
        lines.append("")

        # Basic info - include geo location if available
        ip_line = f"- **IP:** {violation.ip}"
        if geo_data and violation.ip in geo_data:
            geo = geo_data[violation.ip]
            if geo.is_known:
                ip_line += f" ({geo})"
        lines.append(ip_line)

        lines.append(f"- **Time:** {violation.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- **Severity:** {violation.severity.value.upper()}")

        # Show log sources if multiple (multi-log correlation)
        sources = violation.log_sources
        if len(sources) > 1:
            lines.append(f"- **Log Sources:** {', '.join(sources)}")

        lines.append(f"- **Description:** {violation.description}")

        # Additional details
        if violation.details:
            for key, value in violation.details.items():
                # Format key nicely
                key_formatted = key.replace('_', ' ').title()
                lines.append(f"- **{key_formatted}:** {value}")

        lines.append("")

        return lines
