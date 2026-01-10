"""Parser for systemd journald JSON format."""

import json
import re
from datetime import datetime
from typing import TextIO, Optional
from vpsguard.models.events import AuthEvent, EventType, ParsedLog
from vpsguard.parsers.base import validate_file_size, validate_ip, safe_port, safe_pid


class JournaldParser:
    """Parser for journald JSON output (journalctl --output=json).

    Each line is a JSON object containing:
    - __REALTIME_TIMESTAMP: Microseconds since epoch
    - _PID: Process ID
    - SYSLOG_IDENTIFIER: Service name (sshd, sudo, etc.)
    - MESSAGE: The actual log message (parsed with syslog regex)
    - _HOSTNAME: Server hostname
    """

    name = "journald"

    # Reuse regex patterns from auth.log parser
    # These match the MESSAGE field content

    # Failed password for existing user
    FAILED_PASSWORD = re.compile(
        r"Failed password for\s+"
        r"(?!invalid user\s+)"  # negative lookahead for invalid user
        r"(\S+)\s+"  # username
        r"from\s+(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Failed password for invalid user
    FAILED_PASSWORD_INVALID = re.compile(
        r"Failed password for invalid user\s+"
        r"(\S+)\s+"  # username
        r"from\s+(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Invalid user (before password attempt)
    INVALID_USER = re.compile(
        r"Invalid user\s+"
        r"(\S+)\s+"  # username
        r"from\s+(\S+)\s+"  # IP
        r"(?:port\s+(\d+))?"  # optional port
    )

    # Accepted password
    ACCEPTED_PASSWORD = re.compile(
        r"Accepted password for\s+"
        r"(\S+)\s+"  # username
        r"from\s+(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Accepted publickey
    ACCEPTED_PUBLICKEY = re.compile(
        r"Accepted publickey for\s+"
        r"(\S+)\s+"  # username
        r"from\s+(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Connection closed
    CONNECTION_CLOSED = re.compile(
        r"Connection closed by\s+"
        r"(?:authenticating user\s+\S+\s+)?"  # optional authenticating user
        r"(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Disconnected from
    DISCONNECTED = re.compile(
        r"Disconnected from\s+"
        r"(?:authenticating user\s+\S+\s+|invalid user\s+\S+\s+|user\s+\S+\s+)?"  # optional user info
        r"(\S+)\s+"  # IP
        r"port\s+(\d+)"  # port
    )

    # Sudo command (matches the pattern in MESSAGE)
    SUDO_COMMAND = re.compile(
        r"(\S+)\s+:\s+"  # username
        r"TTY=(\S+)\s+;\s+"  # TTY
        r"PWD=(\S+)\s+;\s+"  # PWD
        r"USER=(\S+)\s+;\s+"  # target user
        r"COMMAND=(.+)"  # command
    )

    def parse(self, content: str) -> ParsedLog:
        """Parse journald JSON content and return structured events.

        Args:
            content: Raw JSON log content (one JSON object per line)

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
                # Parse JSON
                log_entry = json.loads(line)

                # Extract relevant fields
                timestamp = self._parse_timestamp(log_entry.get("__REALTIME_TIMESTAMP"))
                pid = log_entry.get("_PID")
                service = log_entry.get("SYSLOG_IDENTIFIER", "unknown")
                message = log_entry.get("MESSAGE", "")

                # Parse the message content
                event = self._parse_message(message, timestamp, pid, service, line)
                if event:
                    events.append(event)
                else:
                    # Message didn't match any known pattern
                    parse_errors.append(
                        f"Line {line_num}: No pattern matched for service {service}: {message[:100]}"
                    )

            except json.JSONDecodeError as e:
                parse_errors.append(f"Line {line_num}: JSON decode error: {e} - {line[:100]}")
            except Exception as e:
                parse_errors.append(f"Line {line_num}: Parse error: {e} - {line[:100]}")

        return ParsedLog(
            events=events,
            source_file=None,
            format_type=self.name,
            parse_errors=parse_errors,
        )

    def parse_file(self, path: str) -> ParsedLog:
        """Parse journald JSON file and return structured events.

        Args:
            path: Path to the JSON log file

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

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> datetime:
        """Parse journald timestamp (microseconds since epoch).

        Args:
            timestamp_str: Timestamp string in microseconds

        Returns:
            datetime object
        """
        if not timestamp_str:
            return datetime.now()

        # Convert microseconds to seconds
        timestamp_microseconds = int(timestamp_str)
        timestamp_seconds = timestamp_microseconds / 1_000_000
        return datetime.fromtimestamp(timestamp_seconds)

    def _parse_message(
        self,
        message: str,
        timestamp: datetime,
        pid: Optional[str],
        service: str,
        raw_line: str,
    ) -> Optional[AuthEvent]:
        """Parse message content into an AuthEvent.

        Args:
            message: The MESSAGE field from journald
            timestamp: Parsed timestamp
            pid: Process ID
            service: Service identifier (sshd, sudo, etc.)
            raw_line: Original JSON line

        Returns:
            AuthEvent if message matches a known pattern, None otherwise
        """
        # Only process sshd and sudo messages
        if service not in ("sshd", "sudo"):
            return None

        pid_int = safe_pid(pid) if pid else None

        # Handle sshd messages
        if service == "sshd":
            # Try failed password for invalid user
            match = self.FAILED_PASSWORD_INVALID.search(message)
            if match:
                username, ip, port = match.groups()
                validated_ip = validate_ip(ip)
                if not validated_ip:
                    return None  # Skip events with invalid IPs
                return AuthEvent(
                    timestamp=timestamp,
                    event_type=EventType.FAILED_LOGIN,
                    ip=validated_ip,
                    username=username,
                    success=False,
                    raw_line=raw_line,
                    port=safe_port(port),
                    pid=pid_int,
                    service=service,
                )

            # Try failed password for existing user
            match = self.FAILED_PASSWORD.search(message)
            if match:
                username, ip, port = match.groups()
                validated_ip = validate_ip(ip)
                if not validated_ip:
                    return None
                return AuthEvent(
                    timestamp=timestamp,
                    event_type=EventType.FAILED_LOGIN,
                    ip=validated_ip,
                    username=username,
                    success=False,
                    raw_line=raw_line,
                    port=safe_port(port),
                    pid=pid_int,
                    service=service,
                )

            # Try invalid user
            match = self.INVALID_USER.search(message)
            if match:
                username, ip, port = match.groups()
                validated_ip = validate_ip(ip)
                if not validated_ip:
                    return None
                return AuthEvent(
                    timestamp=timestamp,
                    event_type=EventType.INVALID_USER,
                    ip=validated_ip,
                    username=username,
                    success=False,
                    raw_line=raw_line,
                    port=safe_port(port) if port else None,
                    pid=pid_int,
                    service=service,
                )

            # Try accepted password
            match = self.ACCEPTED_PASSWORD.search(message)
            if match:
                username, ip, port = match.groups()
                validated_ip = validate_ip(ip)
                if not validated_ip:
                    return None
                return AuthEvent(
                    timestamp=timestamp,
                    event_type=EventType.SUCCESSFUL_LOGIN,
                    ip=validated_ip,
                    username=username,
                    success=True,
                    raw_line=raw_line,
                    port=safe_port(port),
                    pid=pid_int,
                    service=service,
                )

            # Try accepted publickey
            match = self.ACCEPTED_PUBLICKEY.search(message)
            if match:
                username, ip, port = match.groups()
                validated_ip = validate_ip(ip)
                if not validated_ip:
                    return None
                return AuthEvent(
                    timestamp=timestamp,
                    event_type=EventType.SUCCESSFUL_LOGIN,
                    ip=validated_ip,
                    username=username,
                    success=True,
                    raw_line=raw_line,
                    port=safe_port(port),
                    pid=pid_int,
                    service=service,
                )

            # Try connection closed
            match = self.CONNECTION_CLOSED.search(message)
            if match:
                ip, port = match.groups()
                validated_ip = validate_ip(ip)
                if not validated_ip:
                    return None
                return AuthEvent(
                    timestamp=timestamp,
                    event_type=EventType.DISCONNECT,
                    ip=validated_ip,
                    username=None,
                    success=False,
                    raw_line=raw_line,
                    port=safe_port(port),
                    pid=pid_int,
                    service=service,
                )

            # Try disconnected
            match = self.DISCONNECTED.search(message)
            if match:
                ip, port = match.groups()
                validated_ip = validate_ip(ip)
                if not validated_ip:
                    return None
                return AuthEvent(
                    timestamp=timestamp,
                    event_type=EventType.DISCONNECT,
                    ip=validated_ip,
                    username=None,
                    success=False,
                    raw_line=raw_line,
                    port=safe_port(port),
                    pid=pid_int,
                    service=service,
                )

        # Handle sudo messages
        elif service == "sudo":
            match = self.SUDO_COMMAND.search(message)
            if match:
                username, tty, pwd, target_user, command = match.groups()
                return AuthEvent(
                    timestamp=timestamp,
                    event_type=EventType.SUDO,
                    ip=None,  # sudo events don't have IP
                    username=username,
                    success=True,
                    raw_line=raw_line,
                    port=None,
                    pid=pid_int,
                    service=service,
                )

        # No pattern matched
        return None
