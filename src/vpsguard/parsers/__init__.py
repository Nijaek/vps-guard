"""Log parsers for different formats (auth.log, secure, journald, nginx, syslog)."""

from .base import Parser
from .auth import AuthLogParser
from .secure import SecureLogParser
from .journald import JournaldParser
from .nginx import NginxAccessLogParser
from .syslog import SyslogParser


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
    "get_parser",
]
