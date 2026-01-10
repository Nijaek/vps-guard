"""Base parser protocol and utilities."""

from pathlib import Path
from typing import Protocol, TextIO
from vpsguard.models.events import ParsedLog


# Maximum file size for parsing (100 MB by default)
# This prevents memory exhaustion attacks with very large log files
MAX_LOG_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


class FileTooLargeError(Exception):
    """Raised when a log file exceeds the maximum allowed size."""
    pass


def validate_file_size(path: str, max_size: int = MAX_LOG_FILE_SIZE) -> int:
    """Validate that a file is within acceptable size limits.

    Args:
        path: Path to the file to validate.
        max_size: Maximum allowed file size in bytes.

    Returns:
        The file size in bytes.

    Raises:
        FileTooLargeError: If file exceeds max_size.
        FileNotFoundError: If file doesn't exist.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    file_size = file_path.stat().st_size
    if file_size > max_size:
        raise FileTooLargeError(
            f"Log file too large: {file_size / 1024 / 1024:.1f} MB "
            f"(max {max_size / 1024 / 1024:.0f} MB). "
            "Consider splitting the file or using streaming analysis."
        )
    return file_size


class Parser(Protocol):
    """Protocol for log parsers.

    All parsers must implement this protocol to ensure consistent
    interface across different log formats (auth.log, secure, journald, etc.).
    """

    name: str  # e.g., "auth.log", "secure", "journald"

    def parse(self, content: str) -> ParsedLog:
        """Parse log content string and return structured events.

        Args:
            content: Raw log content as a string

        Returns:
            ParsedLog containing events, errors, and metadata
        """
        ...

    def parse_file(self, path: str) -> ParsedLog:
        """Parse log file and return structured events.

        Args:
            path: Path to the log file

        Returns:
            ParsedLog containing events, errors, and metadata
        """
        ...

    def parse_stream(self, stream: TextIO) -> ParsedLog:
        """Parse from a file-like stream (for stdin support).

        Args:
            stream: File-like object (e.g., sys.stdin, open file)

        Returns:
            ParsedLog containing events, errors, and metadata
        """
        ...
