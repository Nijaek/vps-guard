"""Parser for Debian/Ubuntu auth.log format."""

import re
from datetime import datetime, timedelta
from typing import TextIO, Optional
from vpsguard.models.events import AuthEvent, EventType, ParsedLog
from vpsguard.parsers.base import validate_file_size, validate_ip, safe_port, safe_pid


class AuthLogParser:
    """Parser for Debian/Ubuntu auth.log format.

    Handles common SSH authentication patterns:
    - Failed password attempts
    - Successful logins (password and publickey)
    - Invalid user attempts
    - Sudo usage
    - Connection closed/disconnect events
    """

    name = "auth.log"

    # Regex patterns for different event types
    # Timestamp: Month Day HH:MM:SS
    TIMESTAMP_PATTERN = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

    # Failed password for existing user
    FAILED_PASSWORD = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
        r"(\S+)\s+"  # hostname
        r"sshd\[(\d+)\]:\s+"  # service[pid]
        r"Failed password for\s+"
        r"(?!invalid user\s+)"  # negative lookahead for invalid user
        r"(\S+)\s+"  # username
        r"from\s+(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Failed password for invalid user
    FAILED_PASSWORD_INVALID = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
        r"(\S+)\s+"  # hostname
        r"sshd\[(\d+)\]:\s+"  # service[pid]
        r"Failed password for invalid user\s+"
        r"(\S+)\s+"  # username
        r"from\s+(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Invalid user (before password attempt)
    INVALID_USER = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
        r"(\S+)\s+"  # hostname
        r"sshd\[(\d+)\]:\s+"  # service[pid]
        r"Invalid user\s+"
        r"(\S+)\s+"  # username
        r"from\s+(\S+)\s+"  # IP
        r"(?:port\s+(\d+))?"  # optional port
    )

    # Accepted password
    ACCEPTED_PASSWORD = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
        r"(\S+)\s+"  # hostname
        r"sshd\[(\d+)\]:\s+"  # service[pid]
        r"Accepted password for\s+"
        r"(\S+)\s+"  # username
        r"from\s+(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Accepted publickey
    ACCEPTED_PUBLICKEY = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
        r"(\S+)\s+"  # hostname
        r"sshd\[(\d+)\]:\s+"  # service[pid]
        r"Accepted publickey for\s+"
        r"(\S+)\s+"  # username
        r"from\s+(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Connection closed
    CONNECTION_CLOSED = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
        r"(\S+)\s+"  # hostname
        r"sshd\[(\d+)\]:\s+"  # service[pid]
        r"Connection closed by\s+"
        r"(?:authenticating user\s+\S+\s+)?"  # optional authenticating user
        r"(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Disconnected from
    DISCONNECTED = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
        r"(\S+)\s+"  # hostname
        r"sshd\[(\d+)\]:\s+"  # service[pid]
        r"Disconnected from\s+"
        r"(?:authenticating user\s+\S+\s+|invalid user\s+\S+\s+|user\s+\S+\s+)?"  # optional user info
        r"(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Sudo command
    SUDO_COMMAND = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
        r"(\S+)\s+"  # hostname
        r"sudo(?:\[\d+\])?:\s+"  # sudo[pid] or sudo:
        r"(\S+)\s+:\s+"  # username
        r"TTY=(\S+)\s+;\s+"  # TTY
        r"PWD=(\S+)\s+;\s+"  # PWD
        r"USER=(\S+)\s+;\s+"  # target user
        r"COMMAND=(.+)"  # command
    )

    def __init__(self, base_year: Optional[int] = None):
        """Initialize the auth.log parser.

        Args:
            base_year: Year to use for timestamps (syslog format lacks year).
                      If None, uses current year with rollover detection.
                      Set explicitly when parsing archived logs from previous years.
        """
        self.base_year = base_year
        self.current_year = datetime.now().year
        self._last_timestamp: Optional[datetime] = None

    def parse(self, content: str) -> ParsedLog:
        """Parse log content string and return structured events.

        Args:
            content: Raw log content as a string

        Returns:
            ParsedLog containing events, errors, and metadata
        """
        events = []
        parse_errors = []

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line:
                continue

            try:
                event = self._parse_line(line)
                if event:
                    events.append(event)
                else:
                    # Line didn't match any known pattern
                    parse_errors.append(f"Line {line_num}: No pattern matched: {line[:100]}")
            except Exception as e:
                parse_errors.append(f"Line {line_num}: Parse error: {e} - {line[:100]}")

        return ParsedLog(
            events=events,
            source_file=None,
            format_type=self.name,
            parse_errors=parse_errors,
        )

    def parse_file(self, path: str) -> ParsedLog:
        """Parse log file and return structured events.

        Args:
            path: Path to the log file

        Returns:
            ParsedLog containing events, errors, and metadata

        Raises:
            FileTooLargeError: If file exceeds maximum size limit.
            FileNotFoundError: If file doesn't exist.
        """
        # Validate file size before reading to prevent memory exhaustion
        validate_file_size(path)

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        result = self.parse(content)
        # Update source_file in the result
        return ParsedLog(
            events=result.events,
            source_file=path,
            format_type=result.format_type,
            parse_errors=result.parse_errors,
        )

    def parse_stream(self, stream: TextIO) -> ParsedLog:
        """Parse from a file-like stream (for stdin support).

        Args:
            stream: File-like object (e.g., sys.stdin, open file)

        Returns:
            ParsedLog containing events, errors, and metadata
        """
        content = stream.read()
        return self.parse(content)

    def _parse_line(self, line: str) -> Optional[AuthEvent]:
        """Parse a single log line into an AuthEvent.

        Args:
            line: Raw log line

        Returns:
            AuthEvent if line matches a known pattern, None otherwise

        Note:
            IP addresses and port/PID numbers are validated. Events with
            invalid IPs are skipped. Invalid ports/PIDs are set to None.
        """
        # Try failed password for invalid user
        match = self.FAILED_PASSWORD_INVALID.match(line)
        if match:
            timestamp_str, hostname, pid, username, ip, port = match.groups()
            validated_ip = validate_ip(ip)
            if not validated_ip:
                return None  # Skip events with invalid IPs
            return AuthEvent(
                timestamp=self._parse_timestamp(timestamp_str),
                event_type=EventType.FAILED_LOGIN,
                ip=validated_ip,
                username=username,
                success=False,
                raw_line=line,
                port=safe_port(port),
                pid=safe_pid(pid),
                service="sshd",
            )

        # Try failed password for existing user
        match = self.FAILED_PASSWORD.match(line)
        if match:
            timestamp_str, hostname, pid, username, ip, port = match.groups()
            validated_ip = validate_ip(ip)
            if not validated_ip:
                return None
            return AuthEvent(
                timestamp=self._parse_timestamp(timestamp_str),
                event_type=EventType.FAILED_LOGIN,
                ip=validated_ip,
                username=username,
                success=False,
                raw_line=line,
                port=safe_port(port),
                pid=safe_pid(pid),
                service="sshd",
            )

        # Try invalid user
        match = self.INVALID_USER.match(line)
        if match:
            timestamp_str, hostname, pid, username, ip, port = match.groups()
            validated_ip = validate_ip(ip)
            if not validated_ip:
                return None
            return AuthEvent(
                timestamp=self._parse_timestamp(timestamp_str),
                event_type=EventType.INVALID_USER,
                ip=validated_ip,
                username=username,
                success=False,
                raw_line=line,
                port=safe_port(port) if port else None,
                pid=safe_pid(pid),
                service="sshd",
            )

        # Try accepted password
        match = self.ACCEPTED_PASSWORD.match(line)
        if match:
            timestamp_str, hostname, pid, username, ip, port = match.groups()
            validated_ip = validate_ip(ip)
            if not validated_ip:
                return None
            return AuthEvent(
                timestamp=self._parse_timestamp(timestamp_str),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip=validated_ip,
                username=username,
                success=True,
                raw_line=line,
                port=safe_port(port),
                pid=safe_pid(pid),
                service="sshd",
            )

        # Try accepted publickey
        match = self.ACCEPTED_PUBLICKEY.match(line)
        if match:
            timestamp_str, hostname, pid, username, ip, port = match.groups()
            validated_ip = validate_ip(ip)
            if not validated_ip:
                return None
            return AuthEvent(
                timestamp=self._parse_timestamp(timestamp_str),
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip=validated_ip,
                username=username,
                success=True,
                raw_line=line,
                port=safe_port(port),
                pid=safe_pid(pid),
                service="sshd",
            )

        # Try connection closed
        match = self.CONNECTION_CLOSED.match(line)
        if match:
            timestamp_str, hostname, pid, ip, port = match.groups()
            validated_ip = validate_ip(ip)
            if not validated_ip:
                return None
            return AuthEvent(
                timestamp=self._parse_timestamp(timestamp_str),
                event_type=EventType.DISCONNECT,
                ip=validated_ip,
                username=None,
                success=False,
                raw_line=line,
                port=safe_port(port),
                pid=safe_pid(pid),
                service="sshd",
            )

        # Try disconnected
        match = self.DISCONNECTED.match(line)
        if match:
            timestamp_str, hostname, pid, ip, port = match.groups()
            validated_ip = validate_ip(ip)
            if not validated_ip:
                return None
            return AuthEvent(
                timestamp=self._parse_timestamp(timestamp_str),
                event_type=EventType.DISCONNECT,
                ip=validated_ip,
                username=None,
                success=False,
                raw_line=line,
                port=safe_port(port),
                pid=safe_pid(pid),
                service="sshd",
            )

        # Try sudo command
        match = self.SUDO_COMMAND.match(line)
        if match:
            timestamp_str, hostname, username, tty, pwd, target_user, command = match.groups()
            return AuthEvent(
                timestamp=self._parse_timestamp(timestamp_str),
                event_type=EventType.SUDO,
                ip=None,  # sudo events don't have IP in the log
                username=username,
                success=True,  # if logged, sudo succeeded
                raw_line=line,
                port=None,
                pid=None,
                service="sudo",
            )

        # No pattern matched
        return None

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse syslog timestamp format (no year).

        Handles year rollover by assuming current year, but adjusts if
        timestamp is in the future (indicates previous year).

        Args:
            timestamp_str: Timestamp string like "Jan 15 03:12:47"

        Returns:
            datetime object
        """
        # Parse timestamp with current year
        timestamp = datetime.strptime(
            f"{self.current_year} {timestamp_str}",
            "%Y %b %d %H:%M:%S"
        )

        # If timestamp is in the future, it's from previous year
        now = datetime.now()
        if timestamp > now:
            timestamp = timestamp.replace(year=self.current_year - 1)

        return timestamp
