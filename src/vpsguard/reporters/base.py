"""Reporter protocol for generating security reports."""

from typing import Protocol
from vpsguard.models.events import AnalysisReport


class Reporter(Protocol):
    """Protocol for report generators.

    All reporters must implement this interface to generate
    reports in different formats (terminal, markdown, JSON, etc.).
    """

    name: str

    def generate(self, report: AnalysisReport) -> str:
        """Generate report as string.

        Args:
            report: AnalysisReport containing violations and metadata.

        Returns:
            Formatted report as a string.
        """
        ...

    def generate_to_file(self, report: AnalysisReport, path: str) -> None:
        """Generate report and write to file.

        Args:
            report: AnalysisReport containing violations and metadata.
            path: File path to write the report to.
        """
        ...
