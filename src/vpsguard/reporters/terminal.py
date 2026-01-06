"""Terminal reporter using Rich for beautiful console output."""

from pathlib import Path
from collections import defaultdict
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vpsguard.models.events import AnalysisReport, RuleViolation, Severity


class TerminalReporter:
    """Terminal reporter with Rich formatting.

    Displays severity-first hierarchy with beautiful formatting:
    - Summary header with counts by severity
    - Groups violations by severity (CRITICAL first)
    - Rich formatting with panels and colors
    """

    name = "terminal"

    def __init__(self, max_per_severity: int = 10):
        """Initialize terminal reporter.

        Args:
            max_per_severity: Maximum violations to show per severity level.
        """
        self.max_per_severity = max_per_severity
        self.console = Console()

    def generate(self, report: AnalysisReport) -> str:
        """Generate terminal report as string.

        Args:
            report: AnalysisReport containing violations and metadata.

        Returns:
            Rich-formatted report as a string.
        """
        # Use Console to capture output as string
        console = Console(record=True, width=80)
        self._render_report(report, console)
        return console.export_text()

    def generate_to_file(self, report: AnalysisReport, path: str) -> None:
        """Generate report and write to file.

        Args:
            report: AnalysisReport containing violations and metadata.
            path: File path to write the report to.
        """
        output = self.generate(report)
        Path(path).write_text(output, encoding="utf-8")

    def display(self, report: AnalysisReport) -> None:
        """Display report directly to console.

        Args:
            report: AnalysisReport containing violations and metadata.
        """
        self._render_report(report, self.console)

    def _render_report(self, report: AnalysisReport, console: Console) -> None:
        """Render report to console.

        Args:
            report: AnalysisReport containing violations and metadata.
            console: Rich Console to render to.
        """
        # Generate header
        self._render_header(report, console)

        # Group violations by severity
        violations_by_severity = self._group_by_severity(report.rule_violations)

        # Render each severity level
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

        for severity in severity_order:
            violations = violations_by_severity.get(severity, [])
            if violations:
                self._render_severity_section(severity, violations, console, report.geo_data)

        # If no violations found
        if not report.rule_violations:
            console.print("\n[green]No security violations detected![/green]\n")

    def _render_header(self, report: AnalysisReport, console: Console) -> None:
        """Render report header with summary.

        Args:
            report: AnalysisReport containing violations and metadata.
            console: Rich Console to render to.
        """
        # Count violations by severity
        counts = defaultdict(int)
        for violation in report.rule_violations:
            counts[violation.severity] += 1

        # Build header text
        header_text = Text()
        header_text.append("VPSGUARD SECURITY REPORT\n", style="bold white")
        header_text.append(f"{report.timestamp.strftime('%Y-%m-%d %H:%M UTC')}\n\n", style="dim")

        # Severity counts with colors
        severity_styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "bold yellow",
            Severity.MEDIUM: "bold cyan",
            Severity.LOW: "bold white",
        }

        parts = []
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = counts.get(severity, 0)
            if count > 0 or severity in [Severity.CRITICAL, Severity.HIGH]:
                # Always show CRITICAL and HIGH even if 0
                parts.append(f"{severity.value.upper()}: {count}")

        header_text.append("  ".join(parts), style="bold")
        header_text.append(f"    Scanned: {report.total_events:,}", style="dim")

        # Create panel
        panel = Panel(
            header_text,
            border_style="blue",
            padding=(1, 2),
        )
        console.print(panel)

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
        console: Console,
        geo_data: dict | None = None
    ) -> None:
        """Render section for a specific severity level.

        Args:
            severity: Severity level.
            violations: List of violations at this severity.
            console: Rich Console to render to.
            geo_data: Optional dict mapping IP to GeoLocation.
        """
        # Severity colors
        severity_colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "yellow",
            Severity.MEDIUM: "cyan",
            Severity.LOW: "white",
        }
        color = severity_colors.get(severity, "white")

        # Section header
        console.print(f"\n[bold {color}]{severity.value.upper()} FINDINGS[/bold {color}]\n")

        # Show violations (limited by max_per_severity)
        for i, violation in enumerate(violations[:self.max_per_severity]):
            self._render_violation(violation, console, color, geo_data)

        # Show count if we have more
        remaining = len(violations) - self.max_per_severity
        if remaining > 0:
            console.print(f"[dim]... and {remaining} more {severity.value} findings[/dim]\n")

    def _render_violation(
        self,
        violation: RuleViolation,
        console: Console,
        color: str,
        geo_data: dict | None = None
    ) -> None:
        """Render a single violation as a panel.

        Args:
            violation: RuleViolation to render.
            console: Rich Console to render to.
            color: Color for the panel border.
            geo_data: Optional dict mapping IP to GeoLocation.
        """
        # Build violation details
        details_text = Text()

        # Basic info
        details_text.append(f"IP: ", style="bold")
        details_text.append(f"{violation.ip}", style=color)

        # Add geo location if available
        if geo_data and violation.ip in geo_data:
            geo = geo_data[violation.ip]
            if geo.is_known:
                details_text.append(f" ({geo})", style="dim cyan")
        details_text.append("\n")

        details_text.append(f"Time: ", style="bold")
        details_text.append(f"{violation.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n", style="white")

        details_text.append(f"Severity: ", style="bold")
        details_text.append(f"{violation.severity.value.upper()}\n", style=color)

        # Show log sources if multiple (multi-log correlation)
        sources = violation.log_sources
        if len(sources) > 1:
            details_text.append(f"Sources: ", style="bold")
            details_text.append(f"{', '.join(sources)}\n", style="magenta")

        # Description
        details_text.append(f"\n{violation.description}\n", style="white")

        # Additional details from the details dict
        if violation.details:
            details_text.append("\nDetails:\n", style="bold")
            for key, value in violation.details.items():
                details_text.append(f"  {key}: ", style="dim")
                details_text.append(f"{value}\n", style="white")

        # Create panel
        panel = Panel(
            details_text,
            title=f"[bold]{violation.rule_name}[/bold]",
            border_style=color,
            padding=(0, 1),
        )
        console.print(panel)
