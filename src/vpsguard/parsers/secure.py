"""Parser for RHEL/CentOS /var/log/secure format."""

from typing import TextIO
from vpsguard.parsers.auth import AuthLogParser
from vpsguard.models.events import ParsedLog


class SecureLogParser(AuthLogParser):
    """Parser for RHEL/CentOS /var/log/secure format.

    The secure log format is essentially identical to auth.log,
    so we inherit all parsing logic from AuthLogParser and just
    change the name identifier.
    """

    name = "secure"

    def parse_file(self, path: str) -> ParsedLog:
        """Parse log file and return structured events.

        Args:
            path: Path to the log file

        Returns:
            ParsedLog containing events, errors, and metadata
        """
        # Use parent's parse logic
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        result = self.parse(content)
        # Update source_file and format_type
        return ParsedLog(
            events=result.events,
            source_file=path,
            format_type=self.name,  # Use "secure" instead of "auth.log"
            parse_errors=result.parse_errors,
        )

    def parse(self, content: str) -> ParsedLog:
        """Parse log content string and return structured events.

        Args:
            content: Raw log content as a string

        Returns:
            ParsedLog containing events, errors, and metadata
        """
        # Use parent's parse logic but override format_type
        result = super().parse(content)
        return ParsedLog(
            events=result.events,
            source_file=result.source_file,
            format_type=self.name,  # Use "secure" instead of "auth.log"
            parse_errors=result.parse_errors,
        )
