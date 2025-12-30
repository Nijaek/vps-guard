"""Reporter module for generating security reports in multiple formats."""

from .base import Reporter
from .terminal import TerminalReporter
from .markdown import MarkdownReporter
from .json import JSONReporter


def get_reporter(format: str) -> Reporter:
    """Get reporter instance by format name.

    Args:
        format: Reporter format ("terminal", "markdown", "json").

    Returns:
        Reporter instance for the specified format.
        Defaults to TerminalReporter if format is unknown.
    """
    reporters = {
        "terminal": TerminalReporter(),
        "markdown": MarkdownReporter(),
        "json": JSONReporter(),
    }
    return reporters.get(format, TerminalReporter())


__all__ = [
    "Reporter",
    "TerminalReporter",
    "MarkdownReporter",
    "JSONReporter",
    "get_reporter",
]
