"""Base parser protocol and utilities."""

from typing import Protocol, TextIO
from vpsguard.models.events import ParsedLog


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
