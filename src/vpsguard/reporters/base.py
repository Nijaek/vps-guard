"""Reporter protocol for generating security reports."""

import tempfile
from pathlib import Path
from typing import Protocol

from vpsguard.models.events import AnalysisReport


def validate_report_path(path: str) -> Path:
    """Validate that a report output path is safe to write to.

    Prevents path traversal attacks by ensuring paths are within safe directories.

    Args:
        path: The path to validate.

    Returns:
        Validated Path object.

    Raises:
        ValueError: If the path uses traversal or is in a restricted location.
    """
    output_path = Path(path)

    # Check for path traversal attempts
    if '..' in output_path.parts:
        raise ValueError(
            f"Path traversal not allowed: {path}. "
            "Use direct paths without '..' components."
        )

    # Get the resolved absolute path
    try:
        resolved = output_path.resolve()
    except (OSError, ValueError) as e:
        raise ValueError(f"Invalid path: {path} - {e}")

    # Define safe base directories
    cwd = Path.cwd().resolve()
    home = Path.home().resolve()
    vpsguard_dir = (home / ".vpsguard").resolve()
    temp_dir = Path(tempfile.gettempdir()).resolve()

    # For relative paths, they resolve relative to cwd (safe)
    if not output_path.is_absolute():
        return resolved

    # For absolute paths, check against safe directories
    safe_bases = [cwd, home, vpsguard_dir, temp_dir]
    for safe_base in safe_bases:
        try:
            resolved.relative_to(safe_base)
            return resolved
        except ValueError:
            continue

    raise ValueError(
        f"Output path must be within current directory, home, or ~/.vpsguard: {path}"
    )


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

        Note:
            Implementations should validate paths using validate_report_path()
            to prevent path traversal attacks.
        """
        ...
