"""Log parsers for different formats (auth.log, secure, journald, nginx, syslog)."""

from pathlib import Path

from .base import (
    Parser,
    FileTooLargeError,
    MAX_LOG_FILE_SIZE,
    validate_file_size,
    validate_ip,
    safe_int,
    safe_port,
    safe_pid,
    MIN_PORT,
    MAX_PORT,
    MIN_PID,
    MAX_PID,
)
from .auth import AuthLogParser
from .secure import SecureLogParser
from .journald import JournaldParser
from .nginx import NginxAccessLogParser
from .syslog import SyslogParser
from vpsguard.models.events import ParsedLog


def enrich_with_source(parsed: ParsedLog, source: str | None = None) -> ParsedLog:
    """Enrich parsed log events with their source for multi-log correlation.

    Args:
        parsed: ParsedLog with events to enrich
        source: Optional custom source name. If None, uses source_file or format_type.

    Returns:
        ParsedLog with all events having log_source set
    """
    # Determine the source name
    if source:
        source_name = source
    elif parsed.source_file:
        # Use filename for readability
        source_name = Path(parsed.source_file).name
    else:
        source_name = parsed.format_type

    # Set log_source on all events
    for event in parsed.events:
        event.log_source = source_name

    return parsed


def get_parser(format_type: str) -> Parser:
    """Get parser by format type.

    Args:
        format_type: One of "auth.log", "secure", "journald", "nginx", or "syslog"

    Returns:
        Parser instance for the specified format

    Raises:
        ValueError: If format_type is not recognized
    """
    parsers = {
        "auth.log": AuthLogParser(),
        "secure": SecureLogParser(),
        "journald": JournaldParser(),
        "nginx": NginxAccessLogParser(),
        "syslog": SyslogParser(),
    }
    if format_type not in parsers:
        raise ValueError(
            f"Unknown format: {format_type}. "
            f"Valid formats: {', '.join(parsers.keys())}"
        )
    return parsers[format_type]


__all__ = [
    "Parser",
    "AuthLogParser",
    "SecureLogParser",
    "JournaldParser",
    "NginxAccessLogParser",
    "SyslogParser",
    "FileTooLargeError",
    "MAX_LOG_FILE_SIZE",
    "validate_file_size",
    "validate_ip",
    "safe_int",
    "safe_port",
    "safe_pid",
    "MIN_PORT",
    "MAX_PORT",
    "MIN_PID",
    "MAX_PID",
    "get_parser",
    "enrich_with_source",
]
