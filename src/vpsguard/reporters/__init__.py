"""Reporter module for generating security reports in multiple formats."""

from .base import Reporter
from .html import HTMLReporter
from .json import JSONReporter
from .markdown import MarkdownReporter
from .terminal import TerminalReporter


def get_reporter(format: str) -> Reporter:
    """Get reporter instance by format name.

    Args:
        format: Reporter format ("terminal", "markdown", "json", "html").

    Returns:
        Reporter instance for the specified format.
        Defaults to TerminalReporter if format is unknown.
    """
    reporters = {
        "terminal": TerminalReporter(),
        "markdown": MarkdownReporter(),
        "json": JSONReporter(),
        "html": HTMLReporter(),
    }
    return reporters.get(format, TerminalReporter())


__all__ = [
    "Reporter",
    "TerminalReporter",
    "MarkdownReporter",
    "JSONReporter",
    "HTMLReporter",
    "get_reporter",
]
