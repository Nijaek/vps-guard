"""Parser for generic syslog format."""

import re
from datetime import datetime
from typing import TextIO, Optional
from vpsguard.models.events import AuthEvent, EventType, ParsedLog


class SyslogParser:
    """Parser for generic syslog format (RFC 3164 / BSD syslog).

    Handles common syslog patterns from various services:
    - Authentication events from PAM
    - Cron job executions
    - System service events
    - Kernel messages
    - General daemon logs

    Standard syslog format:
    <priority>timestamp hostname process[pid]: message
    or BSD format:
    timestamp hostname process[pid]: message

    Examples:
    Jan 15 03:12:47 server sshd[12345]: Accepted password for user from 192.168.1.1 port 22
    Jan 15 03:12:47 server CRON[12346]: (root) CMD (/usr/bin/script)
    Jan 15 03:12:47 server kernel: [12345.678] USB device connected
    """

    name = "syslog"

    # Base syslog timestamp pattern (BSD format)
    TIMESTAMP_PATTERN = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

    # Generic syslog line pattern
    # Groups: timestamp, hostname, process, pid (optional), message
    SYSLOG_PATTERN = re.compile(
        r'^(?:<\d+>)?'                          # Optional priority
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
        r'(\S+)\s+'                              # hostname
        r'(\S+?)'                                # process name
        r'(?:\[(\d+)\])?'                        # optional PID in brackets
        r':\s*'                                  # colon separator
        r'(.*)$'                                 # message
    )

    # ISO timestamp syslog pattern (RFC 5424)
    SYSLOG_RFC5424_PATTERN = re.compile(
        r'^(?:<\d+>)?'                           # Optional priority
        r'(\d+)?\s*'                             # Optional version
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+'  # ISO timestamp
        r'(\S+)\s+'                              # hostname
        r'(\S+)\s+'                              # app-name
        r'(\S+)\s+'                              # procid
        r'(\S+)\s+'                              # msgid
        r'(?:\[.*?\]\s*)*'                       # structured data
        r'(.*)$'                                 # message
    )

    # SSH patterns (delegate to auth parser patterns)
    SSH_FAILED_PASSWORD = re.compile(
        r"Failed password for\s+"
        r"(?:invalid user\s+)?"
        r"(\S+)\s+"
        r"from\s+(\S+)\s+"
        r"port\s+(\d+)"
    )

    SSH_ACCEPTED = re.compile(
        r"Accepted (?:password|publickey) for\s+"
        r"(\S+)\s+"
        r"from\s+(\S+)\s+"
        r"port\s+(\d+)"
    )

    SSH_INVALID_USER = re.compile(
        r"Invalid user\s+"
        r"(\S+)\s+"
        r"from\s+(\S+)"
    )

    # PAM authentication patterns
    PAM_AUTH_FAILURE = re.compile(
        r"pam_unix\(\S+:auth\):\s*authentication failure.*"
        r"(?:user=(\S+))?.*"
        r"(?:rhost=(\S+))?"
    )

    PAM_SESSION_OPEN = re.compile(
        r"pam_unix\(\S+:session\):\s*session opened for user\s+(\S+)"
    )

    PAM_SESSION_CLOSE = re.compile(
        r"pam_unix\(\S+:session\):\s*session closed for user\s+(\S+)"
    )

    # Sudo patterns
    SUDO_COMMAND = re.compile(
        r"(\S+)\s+:\s+"
        r"(?:TTY=\S+\s*;\s*)?"
        r"(?:PWD=\S+\s*;\s*)?"
        r"USER=(\S+)\s*;\s*"
        r"COMMAND=(.+)"
    )

    SUDO_AUTH_FAILURE = re.compile(
        r"(\S+)\s+:\s+.*authentication failure"
    )

    # Cron patterns
    CRON_CMD = re.compile(
        r"\((\S+)\)\s+CMD\s+\((.+)\)"
    )

    def __init__(self):
        """Initialize the syslog parser."""
        self.current_year = datetime.now().year

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
        """
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        result = self.parse(content)
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
        """
        # Try RFC 5424 format first
        match = self.SYSLOG_RFC5424_PATTERN.match(line)
        if match:
            version, timestamp_str, hostname, app_name, procid, msgid, message = match.groups()
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                timestamp = timestamp.replace(tzinfo=None)
            except ValueError:
                return None
            process = app_name
            pid = int(procid) if procid and procid != '-' else None
        else:
            # Try BSD syslog format
            match = self.SYSLOG_PATTERN.match(line)
            if not match:
                return None
            timestamp_str, hostname, process, pid_str, message = match.groups()
            timestamp = self._parse_timestamp(timestamp_str)
            pid = int(pid_str) if pid_str else None

        # Analyze message to determine event type
        return self._analyze_message(message, timestamp, process, pid, line)

    def _analyze_message(
        self,
        message: str,
        timestamp: datetime,
        process: str,
        pid: Optional[int],
        raw_line: str
    ) -> Optional[AuthEvent]:
        """Analyze the message part of the syslog line.

        Args:
            message: The message portion of the syslog line
            timestamp: Parsed timestamp
            process: Process name
            pid: Process ID (if available)
            raw_line: Original log line

        Returns:
            AuthEvent if message matches a known pattern, None otherwise
        """
        process_lower = process.lower()

        # SSH messages
        if 'sshd' in process_lower:
            return self._parse_ssh_message(message, timestamp, pid, raw_line)

        # Sudo messages
        if 'sudo' in process_lower:
            return self._parse_sudo_message(message, timestamp, pid, raw_line)

        # PAM messages (can appear in various processes)
        if 'pam' in message.lower():
            return self._parse_pam_message(message, timestamp, process, pid, raw_line)

        # CRON messages
        if 'cron' in process_lower:
            return self._parse_cron_message(message, timestamp, pid, raw_line)

        # Other messages - return as OTHER type
        return AuthEvent(
            timestamp=timestamp,
            event_type=EventType.OTHER,
            ip=None,
            username=None,
            success=True,
            raw_line=raw_line,
            port=None,
            pid=pid,
            service=process,
        )

    def _parse_ssh_message(
        self, message: str, timestamp: datetime, pid: Optional[int], raw_line: str
    ) -> Optional[AuthEvent]:
        """Parse SSH-related syslog messages."""
        # Failed password
        match = self.SSH_FAILED_PASSWORD.search(message)
        if match:
            username, ip, port = match.groups()
            return AuthEvent(
                timestamp=timestamp,
                event_type=EventType.FAILED_LOGIN,
                ip=ip,
                username=username,
                success=False,
                raw_line=raw_line,
                port=int(port),
                pid=pid,
                service="sshd",
            )

        # Accepted login
        match = self.SSH_ACCEPTED.search(message)
        if match:
            username, ip, port = match.groups()
            return AuthEvent(
                timestamp=timestamp,
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip=ip,
                username=username,
                success=True,
                raw_line=raw_line,
                port=int(port),
                pid=pid,
                service="sshd",
            )

        # Invalid user
        match = self.SSH_INVALID_USER.search(message)
        if match:
            username, ip = match.groups()
            return AuthEvent(
                timestamp=timestamp,
                event_type=EventType.INVALID_USER,
                ip=ip,
                username=username,
                success=False,
                raw_line=raw_line,
                port=None,
                pid=pid,
                service="sshd",
            )

        # Other SSH message
        return AuthEvent(
            timestamp=timestamp,
            event_type=EventType.OTHER,
            ip=None,
            username=None,
            success=True,
            raw_line=raw_line,
            port=None,
            pid=pid,
            service="sshd",
        )

    def _parse_sudo_message(
        self, message: str, timestamp: datetime, pid: Optional[int], raw_line: str
    ) -> Optional[AuthEvent]:
        """Parse sudo-related syslog messages."""
        # Sudo command execution
        match = self.SUDO_COMMAND.search(message)
        if match:
            username, target_user, command = match.groups()
            return AuthEvent(
                timestamp=timestamp,
                event_type=EventType.SUDO,
                ip=None,
                username=username,
                success=True,
                raw_line=raw_line,
                port=None,
                pid=pid,
                service="sudo",
            )

        # Sudo auth failure
        match = self.SUDO_AUTH_FAILURE.search(message)
        if match:
            username = match.group(1)
            return AuthEvent(
                timestamp=timestamp,
                event_type=EventType.FAILED_LOGIN,
                ip=None,
                username=username,
                success=False,
                raw_line=raw_line,
                port=None,
                pid=pid,
                service="sudo",
            )

        # Other sudo message
        return AuthEvent(
            timestamp=timestamp,
            event_type=EventType.OTHER,
            ip=None,
            username=None,
            success=True,
            raw_line=raw_line,
            port=None,
            pid=pid,
            service="sudo",
        )

    def _parse_pam_message(
        self, message: str, timestamp: datetime, process: str, pid: Optional[int], raw_line: str
    ) -> Optional[AuthEvent]:
        """Parse PAM-related syslog messages."""
        # PAM auth failure
        match = self.PAM_AUTH_FAILURE.search(message)
        if match:
            username, rhost = match.groups()
            return AuthEvent(
                timestamp=timestamp,
                event_type=EventType.FAILED_LOGIN,
                ip=rhost,
                username=username,
                success=False,
                raw_line=raw_line,
                port=None,
                pid=pid,
                service=process,
            )

        # PAM session open
        match = self.PAM_SESSION_OPEN.search(message)
        if match:
            username = match.group(1)
            return AuthEvent(
                timestamp=timestamp,
                event_type=EventType.SUCCESSFUL_LOGIN,
                ip=None,
                username=username,
                success=True,
                raw_line=raw_line,
                port=None,
                pid=pid,
                service=process,
            )

        # PAM session close
        match = self.PAM_SESSION_CLOSE.search(message)
        if match:
            username = match.group(1)
            return AuthEvent(
                timestamp=timestamp,
                event_type=EventType.DISCONNECT,
                ip=None,
                username=username,
                success=True,
                raw_line=raw_line,
                port=None,
                pid=pid,
                service=process,
            )

        # Other PAM message
        return AuthEvent(
            timestamp=timestamp,
            event_type=EventType.OTHER,
            ip=None,
            username=None,
            success=True,
            raw_line=raw_line,
            port=None,
            pid=pid,
            service=process,
        )

    def _parse_cron_message(
        self, message: str, timestamp: datetime, pid: Optional[int], raw_line: str
    ) -> Optional[AuthEvent]:
        """Parse CRON-related syslog messages."""
        match = self.CRON_CMD.search(message)
        if match:
            username, command = match.groups()
            return AuthEvent(
                timestamp=timestamp,
                event_type=EventType.SUDO,  # Using SUDO for scheduled commands
                ip=None,
                username=username,
                success=True,
                raw_line=raw_line,
                port=None,
                pid=pid,
                service="cron",
            )

        # Other cron message
        return AuthEvent(
            timestamp=timestamp,
            event_type=EventType.OTHER,
            ip=None,
            username=None,
            success=True,
            raw_line=raw_line,
            port=None,
            pid=pid,
            service="cron",
        )

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
