"""Base parser protocol and utilities."""

import ipaddress
import logging
from pathlib import Path
from typing import Protocol, TextIO, Optional
from vpsguard.models.events import ParsedLog

logger = logging.getLogger(__name__)

# Maximum file size for parsing (100 MB by default)
# This prevents memory exhaustion attacks with very large log files
MAX_LOG_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

# Valid ranges for network values
MIN_PORT = 1
MAX_PORT = 65535
MIN_PID = 1
MAX_PID = 4194304  # Linux default max PID


class FileTooLargeError(Exception):
    """Raised when a log file exceeds the maximum allowed size."""
    pass


def validate_ip(ip_str: str) -> Optional[str]:
    """Validate and normalize an IP address string.

    Args:
        ip_str: IP address string to validate (IPv4 or IPv6).

    Returns:
        Normalized IP address string, or None if invalid.

    Note:
        This function accepts both IPv4 and IPv6 addresses. Private and
        reserved addresses are valid for security analysis purposes.
    """
    if not ip_str:
        return None

    try:
        # Parse and normalize the IP address
        ip = ipaddress.ip_address(ip_str.strip())
        return str(ip)
    except (ValueError, AttributeError):
        logger.debug(f"Invalid IP address: {ip_str!r}")
        return None


def safe_int(value: str, min_val: int, max_val: int, default: Optional[int] = None) -> Optional[int]:
    """Parse an integer string with bounds validation.

    Args:
        value: String to parse as integer.
        min_val: Minimum allowed value (inclusive).
        max_val: Maximum allowed value (inclusive).
        default: Value to return if parsing fails or out of bounds.

    Returns:
        Parsed integer if valid and within bounds, otherwise default.

    Example:
        >>> safe_int("22", MIN_PORT, MAX_PORT)
        22
        >>> safe_int("99999", MIN_PORT, MAX_PORT)
        None
        >>> safe_int("invalid", 0, 100, default=0)
        0
    """
    if not value:
        return default

    try:
        num = int(value)
        if min_val <= num <= max_val:
            return num
        logger.debug(f"Integer out of bounds: {num} not in [{min_val}, {max_val}]")
        return default
    except (ValueError, OverflowError):
        logger.debug(f"Invalid integer: {value!r}")
        return default


def safe_port(value: str) -> Optional[int]:
    """Parse a port number with validation.

    Args:
        value: Port number string.

    Returns:
        Port number if valid (1-65535), otherwise None.
    """
    return safe_int(value, MIN_PORT, MAX_PORT)


def safe_pid(value: str) -> Optional[int]:
    """Parse a process ID with validation.

    Args:
        value: PID string.

    Returns:
        PID if valid, otherwise None.
    """
    return safe_int(value, MIN_PID, MAX_PID)


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
