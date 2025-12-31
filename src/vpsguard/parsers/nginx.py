"""Parser for Nginx access log format."""

import re
from datetime import datetime
from typing import TextIO, Optional
from vpsguard.models.events import AuthEvent, EventType, ParsedLog


class NginxAccessLogParser:
    """Parser for Nginx access log format (combined format).

    Handles common Nginx access log patterns and detects:
    - Unusual status codes (403, 404 spikes)
    - Path traversal attempts (../, etc.)
    - Suspicious user agents (scanners, bots)
    - Admin panel access attempts
    - SQL injection patterns
    - Common attack paths (/wp-admin, /phpmyadmin, etc.)

    Default combined log format:
    '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'

    Example:
    192.168.1.1 - - [31/Dec/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0..."
    """

    name = "nginx"

    # Nginx combined log format regex
    # Groups: ip, ident, user, timestamp, request, status, bytes, referer, user_agent
    ACCESS_LOG_PATTERN = re.compile(
        r'^(\S+)\s+'           # IP address
        r'(\S+)\s+'            # ident (usually -)
        r'(\S+)\s+'            # remote_user (usually -)
        r'\[([^\]]+)\]\s+'     # timestamp in brackets
        r'"([^"]*)"\s+'        # request
        r'(\d{3})\s+'          # status code
        r'(\d+|-)\s*'          # bytes sent (may be - for no body)
        r'(?:"([^"]*)"\s*)?'   # referer (optional)
        r'(?:"([^"]*)")?'      # user agent (optional)
    )

    # Suspicious patterns
    PATH_TRAVERSAL = re.compile(r'\.\./', re.IGNORECASE)
    SQL_INJECTION = re.compile(
        r"(?:union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|"
        r"delete\s+from|drop\s+table|or\s+1\s*=\s*1|'\s*or\s*'|;\s*--|"
        r"exec\s*\(|execute\s*\()",
        re.IGNORECASE
    )
    XSS_PATTERN = re.compile(
        r"<script|javascript:|onerror\s*=|onload\s*=|onclick\s*=",
        re.IGNORECASE
    )
    COMMAND_INJECTION = re.compile(
        r";\s*(?:ls|cat|whoami|id|pwd|wget|curl|bash|sh|nc|netcat)|"
        r"\|\s*(?:ls|cat|whoami|id|pwd|wget|curl|bash|sh|nc|netcat)|"
        r"\$\(|`",
        re.IGNORECASE
    )

    # Suspicious paths that indicate reconnaissance or attacks
    SUSPICIOUS_PATHS = [
        '/wp-admin', '/wp-login.php', '/wp-content/uploads',
        '/phpmyadmin', '/pma', '/myadmin',
        '/admin', '/administrator', '/admin.php',
        '/.env', '/.git', '/.htaccess', '/.htpasswd',
        '/config.php', '/configuration.php', '/wp-config.php',
        '/backup', '/db', '/database', '/sql',
        '/shell', '/cmd', '/command', '/exec',
        '/cgi-bin', '/scripts',
        '/.aws/credentials', '/.ssh/id_rsa',
    ]

    # Suspicious user agents
    SUSPICIOUS_USER_AGENTS = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
        'gobuster', 'dirbuster', 'ffuf', 'wfuzz',
        'hydra', 'medusa', 'nessus', 'openvas',
        'python-requests', 'curl/', 'wget/',  # Not always bad, but worth noting
    ]

    def __init__(self):
        """Initialize the Nginx access log parser."""
        pass

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
        match = self.ACCESS_LOG_PATTERN.match(line)
        if not match:
            return None

        ip, ident, user, timestamp_str, request, status, bytes_sent, referer, user_agent = match.groups()

        # Parse timestamp: 31/Dec/2024:10:00:00 +0000
        try:
            timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
            # Convert to naive datetime for consistency with other parsers
            timestamp = timestamp.replace(tzinfo=None)
        except ValueError:
            # Try without timezone
            try:
                timestamp = datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None

        # Parse status code
        status_code = int(status)

        # Determine event type based on request analysis
        event_type, is_suspicious = self._classify_request(
            request, status_code, user_agent or ""
        )

        # Clean up user
        username = user if user != "-" else None

        return AuthEvent(
            timestamp=timestamp,
            event_type=event_type,
            ip=ip,
            username=username,
            success=(200 <= status_code < 400),
            raw_line=line,
            port=None,
            pid=None,
            service="nginx",
        )

    def _classify_request(self, request: str, status_code: int, user_agent: str) -> tuple[EventType, bool]:
        """Classify a request as normal or suspicious.

        Args:
            request: The HTTP request string (e.g., "GET /index.html HTTP/1.1")
            status_code: HTTP status code
            user_agent: User agent string

        Returns:
            Tuple of (EventType, is_suspicious)
        """
        request_lower = request.lower()
        user_agent_lower = user_agent.lower()

        # Check for path traversal
        if self.PATH_TRAVERSAL.search(request):
            return EventType.INVALID_USER, True  # Using INVALID_USER for suspicious activity

        # Check for SQL injection
        if self.SQL_INJECTION.search(request):
            return EventType.INVALID_USER, True

        # Check for XSS
        if self.XSS_PATTERN.search(request):
            return EventType.INVALID_USER, True

        # Check for command injection
        if self.COMMAND_INJECTION.search(request):
            return EventType.INVALID_USER, True

        # Check for suspicious paths
        for path in self.SUSPICIOUS_PATHS:
            if path.lower() in request_lower:
                return EventType.INVALID_USER, True

        # Check for suspicious user agents
        for agent in self.SUSPICIOUS_USER_AGENTS:
            if agent.lower() in user_agent_lower:
                return EventType.INVALID_USER, True

        # Check for authentication failures (401, 403)
        if status_code == 401:
            return EventType.FAILED_LOGIN, True
        elif status_code == 403:
            return EventType.FAILED_LOGIN, True

        # Successful authentication
        if status_code in [200, 201, 204]:
            return EventType.SUCCESSFUL_LOGIN, False

        # Other status codes
        return EventType.OTHER, False
