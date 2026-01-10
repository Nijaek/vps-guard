"""HTML reporter for generating shareable single-file reports."""

from collections import defaultdict

from vpsguard.models.events import AnalysisReport, Confidence, RuleViolation, Severity
from vpsguard.reporters.base import validate_report_path


class HTMLReporter:
    """HTML reporter for generating shareable single-file reports.

    Generates a self-contained HTML file with:
    - Embedded CSS (no external dependencies)
    - Professional styling
    - Interactive sections
    - Severity-color coding
    - Mobile-responsive layout
    """

    name = "html"

    # Color scheme for severities
    SEVERITY_COLORS = {
        Severity.CRITICAL: {"bg": "#dc2626", "border": "#b91c1c", "text": "#fef2f2"},
        Severity.HIGH: {"bg": "#ea580c", "border": "#c2410c", "text": "#fff7ed"},
        Severity.MEDIUM: {"bg": "#ca8a04", "border": "#a16207", "text": "#fefce8"},
        Severity.LOW: {"bg": "#2563eb", "border": "#1d4ed8", "text": "#eff6ff"},
    }

    CONFIDENCE_COLORS = {
        Confidence.HIGH: "#dc2626",
        Confidence.MEDIUM: "#ca8a04",
        Confidence.LOW: "#2563eb",
    }

    def generate(self, report: AnalysisReport) -> str:
        """Generate HTML report as string.

        Args:
            report: AnalysisReport containing violations and metadata.

        Returns:
            HTML-formatted report as a string.
        """
        # Count violations by severity
        counts = defaultdict(int)
        for violation in report.rule_violations:
            counts[violation.severity] += 1

        # Group violations by severity
        violations_by_severity = self._group_by_severity(report.rule_violations)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPSGuard Security Report - {report.timestamp.strftime('%Y-%m-%d')}</title>
    {self._generate_css()}
</head>
<body>
    <div class="container">
        {self._generate_header(report)}
        {self._generate_filter_controls()}
        {self._generate_summary(report, counts)}
        {self._generate_findings(violations_by_severity, report.geo_data)}
        {self._generate_anomalies(report.anomalies, report.geo_data)}
        {self._generate_drift_warning(report.baseline_drift)}
        {self._generate_footer(report)}
    </div>
</body>
</html>"""
        return html

    def generate_to_file(self, report: AnalysisReport, path: str) -> None:
        """Generate report and write to file.

        Args:
            report: AnalysisReport containing violations and metadata.
            path: File path to write the report to.

        Raises:
            ValueError: If path is outside allowed directories or uses traversal.
        """
        validated_path = validate_report_path(path)
        output = self.generate(report)
        validated_path.write_text(output, encoding="utf-8")

    def _generate_css(self) -> str:
        """Generate embedded CSS styles."""
        return """<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        min-height: 100vh;
        color: #e2e8f0;
        line-height: 1.6;
    }

    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 2rem;
    }

    /* Header */
    .header {
        text-align: center;
        margin-bottom: 2rem;
        padding: 2rem;
        background: rgba(30, 41, 59, 0.8);
        border-radius: 1rem;
        border: 1px solid rgba(148, 163, 184, 0.1);
    }

    .header h1 {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #60a5fa, #a78bfa);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        margin-bottom: 0.5rem;
    }

    .header .subtitle {
        color: #94a3b8;
        font-size: 1.1rem;
    }

    .header .meta {
        display: flex;
        justify-content: center;
        gap: 2rem;
        margin-top: 1rem;
        flex-wrap: wrap;
    }

    .header .meta-item {
        color: #cbd5e1;
    }

    .header .meta-item strong {
        color: #60a5fa;
    }

    /* Summary Cards */
    .summary {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
        margin-bottom: 2rem;
    }

    .summary-card {
        padding: 1.5rem;
        border-radius: 0.75rem;
        text-align: center;
        transition: transform 0.2s;
    }

    .summary-card:hover {
        transform: translateY(-2px);
    }

    .summary-card .count {
        font-size: 2.5rem;
        font-weight: 700;
    }

    .summary-card .label {
        font-size: 0.875rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        opacity: 0.9;
    }

    .summary-card.critical { background: linear-gradient(135deg, #dc2626, #b91c1c); }
    .summary-card.high { background: linear-gradient(135deg, #ea580c, #c2410c); }
    .summary-card.medium { background: linear-gradient(135deg, #ca8a04, #a16207); }
    .summary-card.low { background: linear-gradient(135deg, #2563eb, #1d4ed8); }
    .summary-card.total { background: linear-gradient(135deg, #475569, #334155); }

    /* Section Styling */
    .section {
        margin-bottom: 2rem;
    }

    .section-title {
        font-size: 1.5rem;
        font-weight: 600;
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid rgba(148, 163, 184, 0.2);
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .section-title .icon {
        font-size: 1.25rem;
    }

    /* Finding Cards */
    .finding {
        background: rgba(30, 41, 59, 0.6);
        border-radius: 0.75rem;
        margin-bottom: 1rem;
        overflow: hidden;
        border: 1px solid rgba(148, 163, 184, 0.1);
    }

    .finding-header {
        padding: 1rem 1.5rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 0.5rem;
    }

    .finding-header.critical { background: rgba(220, 38, 38, 0.2); border-left: 4px solid #dc2626; }
    .finding-header.high { background: rgba(234, 88, 12, 0.2); border-left: 4px solid #ea580c; }
    .finding-header.medium { background: rgba(202, 138, 4, 0.2); border-left: 4px solid #ca8a04; }
    .finding-header.low { background: rgba(37, 99, 235, 0.2); border-left: 4px solid #2563eb; }

    .finding-title {
        font-weight: 600;
        font-size: 1.1rem;
    }

    .finding-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
    }

    .finding-badge.critical { background: #dc2626; color: white; }
    .finding-badge.high { background: #ea580c; color: white; }
    .finding-badge.medium { background: #ca8a04; color: white; }
    .finding-badge.low { background: #2563eb; color: white; }

    .finding-body {
        padding: 1rem 1.5rem;
    }

    .finding-detail {
        display: grid;
        grid-template-columns: 120px 1fr;
        gap: 0.5rem;
        margin-bottom: 0.5rem;
    }

    .finding-detail .label {
        color: #94a3b8;
        font-weight: 500;
    }

    .finding-detail .value {
        color: #e2e8f0;
        word-break: break-all;
    }

    .finding-detail .value.ip {
        font-family: 'Consolas', 'Monaco', monospace;
        color: #60a5fa;
    }

    /* Anomalies Section */
    .anomaly {
        background: rgba(30, 41, 59, 0.6);
        border-radius: 0.75rem;
        margin-bottom: 1rem;
        padding: 1rem 1.5rem;
        border: 1px solid rgba(148, 163, 184, 0.1);
    }

    .anomaly-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.75rem;
    }

    .anomaly-ip {
        font-family: 'Consolas', 'Monaco', monospace;
        font-weight: 600;
        color: #60a5fa;
    }

    .anomaly-score {
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.875rem;
        font-weight: 600;
    }

    .anomaly-explanations {
        list-style: none;
        padding-left: 0;
    }

    .anomaly-explanations li {
        padding: 0.25rem 0;
        color: #cbd5e1;
        font-size: 0.9rem;
    }

    .anomaly-explanations li::before {
        content: "→ ";
        color: #60a5fa;
    }

    /* Drift Warning */
    .drift-warning {
        background: rgba(202, 138, 4, 0.1);
        border: 1px solid #ca8a04;
        border-radius: 0.75rem;
        padding: 1.5rem;
        margin-bottom: 2rem;
    }

    .drift-warning h3 {
        color: #fbbf24;
        margin-bottom: 0.5rem;
    }

    /* No Findings */
    .no-findings {
        text-align: center;
        padding: 3rem;
        background: rgba(30, 41, 59, 0.6);
        border-radius: 0.75rem;
        color: #94a3b8;
    }

    .no-findings .icon {
        font-size: 3rem;
        margin-bottom: 1rem;
    }

    /* Footer */
    .footer {
        text-align: center;
        padding: 2rem;
        color: #64748b;
        font-size: 0.875rem;
    }

    .footer a {
        color: #60a5fa;
        text-decoration: none;
    }

    /* Filter Controls */
    .filter-controls {
        background: rgba(30, 41, 59, 0.8);
        padding: 1rem 1.5rem;
        border-radius: 0.75rem;
        margin-bottom: 2rem;
        border: 1px solid rgba(148, 163, 184, 0.1);
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 1rem;
    }

    .filter-controls label {
        color: #cbd5e1;
        font-weight: 500;
    }

    .filter-controls select {
        background: #1e293b;
        color: #e2e8f0;
        border: 1px solid #475569;
        padding: 0.5rem 1rem;
        border-radius: 0.375rem;
    }

    .filter-controls input {
        background: #1e293b;
        color: #e2e8f0;
        border: 1px solid #475569;
        padding: 0.5rem 1rem;
        border-radius: 0.375rem;
        width: 180px;
    }

    .filter-controls input::placeholder {
        color: #64748b;
    }

    .filter-stats {
        color: #94a3b8;
        font-size: 0.875rem;
        margin-left: auto;
    }

    .filter-stats strong {
        color: #60a5fa;
    }

    .finding {
        transition: opacity 0.2s;
    }

    .finding.hidden {
        display: none;
    }

    /* Responsive */
    @media (max-width: 768px) {
        .container {
            padding: 1rem;
        }

        .header h1 {
            font-size: 1.75rem;
        }

        .finding-detail {
            grid-template-columns: 1fr;
        }

        .finding-detail .label {
            margin-bottom: -0.25rem;
        }

        .filter-controls {
            flex-direction: column;
            align-items: stretch;
        }

        .filter-controls input {
            width: 100%;
        }

        .filter-stats {
            margin-left: 0;
            text-align: center;
        }
    }
</style>
<script>
function filterFindings() {
    const severityFilter = document.getElementById('severity-filter').value;
    const ipFilter = document.getElementById('ip-filter').value.toLowerCase();
    const timeFilter = document.getElementById('time-filter').value;

    const findings = document.querySelectorAll('.finding');
    let visibleCount = 0;

    findings.forEach(finding => {
        const severity = finding.getAttribute('data-severity');
        const ip = (finding.getAttribute('data-ip') || '').toLowerCase();
        const time = finding.getAttribute('data-time');

        let show = true;

        if (severityFilter && severity !== severityFilter) {
            show = false;
        }

        if (ipFilter && !ip.includes(ipFilter)) {
            show = false;
        }

        if (timeFilter && time) {
            const findingTime = new Date(time);
            const now = new Date();
            const cutoff = new Date(now - timeFilter * 60 * 60 * 1000);
            if (findingTime < cutoff) {
                show = false;
            }
        }

        if (show) {
            finding.classList.remove('hidden');
            visibleCount++;
        } else {
            finding.classList.add('hidden');
        }
    });

    document.getElementById('visible-count').textContent = visibleCount;
}

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('severity-filter').addEventListener('change', filterFindings);
    document.getElementById('ip-filter').addEventListener('input', filterFindings);
    document.getElementById('time-filter').addEventListener('change', filterFindings);
    filterFindings();
});
</script>"""

    def _generate_header(self, report: AnalysisReport) -> str:
        """Generate the report header."""
        return f"""
        <div class="header">
            <h1>VPSGuard Security Report</h1>
            <p class="subtitle">Automated Security Analysis</p>
            <div class="meta">
                <span class="meta-item"><strong>Generated:</strong> {report.timestamp.strftime('%Y-%m-%d %H:%M UTC')}</span>
                <span class="meta-item"><strong>Source:</strong> {self._escape_html(report.log_source)}</span>
                <span class="meta-item"><strong>Events Scanned:</strong> {report.total_events:,}</span>
            </div>
        </div>"""

    def _generate_filter_controls(self) -> str:
        """Generate filter control panel."""
        return """
        <div class="filter-controls">
            <label for="severity-filter">Severity:</label>
            <select id="severity-filter">
                <option value="">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>

            <label for="ip-filter">IP Address:</label>
            <input type="text" id="ip-filter" placeholder="Filter by IP...">

            <label for="time-filter">Last:</label>
            <select id="time-filter">
                <option value="">All time</option>
                <option value="1">Last 1 hour</option>
                <option value="6">Last 6 hours</option>
                <option value="24">Last 24 hours</option>
                <option value="168">Last 7 days</option>
            </select>

            <span class="filter-stats">
                Showing: <strong id="visible-count">0</strong> findings
            </span>
        </div>"""

    def _generate_summary(self, report: AnalysisReport, counts: dict) -> str:
        """Generate the summary cards."""
        critical = counts.get(Severity.CRITICAL, 0)
        high = counts.get(Severity.HIGH, 0)
        medium = counts.get(Severity.MEDIUM, 0)
        low = counts.get(Severity.LOW, 0)
        total = len(report.rule_violations)
        anomaly_count = len(report.anomalies) if report.anomalies else 0

        return f"""
        <div class="summary">
            <div class="summary-card critical">
                <div class="count">{critical}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{high}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{medium}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{low}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card total">
                <div class="count">{total + anomaly_count}</div>
                <div class="label">Total Findings</div>
            </div>
        </div>"""

    def _generate_findings(self, violations_by_severity: dict, geo_data: dict | None = None) -> str:
        """Generate the findings sections."""
        if not any(violations_by_severity.values()):
            return """
            <div class="section">
                <div class="no-findings">
                    <div class="icon">&#10003;</div>
                    <h3>No Rule Violations Detected</h3>
                    <p>No security violations were detected in the analyzed logs.</p>
                </div>
            </div>"""

        sections = []
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        severity_icons = {
            Severity.CRITICAL: "&#9888;",  # Warning sign
            Severity.HIGH: "&#9888;",
            Severity.MEDIUM: "&#9679;",  # Circle
            Severity.LOW: "&#8505;",  # Info
        }

        for severity in severity_order:
            violations = violations_by_severity.get(severity, [])
            if violations:
                findings_html = ""
                for v in violations:
                    findings_html += self._render_finding(v, geo_data)

                sections.append(f"""
                <div class="section">
                    <h2 class="section-title">
                        <span class="icon">{severity_icons[severity]}</span>
                        {severity.value.title()} Findings ({len(violations)})
                    </h2>
                    {findings_html}
                </div>""")

        return "\n".join(sections)

    def _render_finding(self, violation: RuleViolation, geo_data: dict | None = None) -> str:
        """Render a single finding card."""
        severity_class = violation.severity.value.lower()

        # IP address with optional geo location
        ip_display = self._escape_html(violation.ip)
        location_html = ""
        if geo_data and violation.ip in geo_data:
            geo = geo_data[violation.ip]
            if geo.is_known:
                location_html = f"""
            <div class="finding-detail">
                <span class="label">Location:</span>
                <span class="value">{self._escape_html(str(geo))}</span>
            </div>"""

        # Show log sources if multiple (multi-log correlation)
        sources = violation.log_sources
        sources_html = ""
        if len(sources) > 1:
            sources_html = f"""
            <div class="finding-detail">
                <span class="label">Log Sources:</span>
                <span class="value" style="color: #a78bfa;">{self._escape_html(', '.join(sources))}</span>
            </div>"""

        details_html = f"""
            <div class="finding-detail">
                <span class="label">IP Address:</span>
                <span class="value ip">{ip_display}</span>
            </div>{location_html}{sources_html}
            <div class="finding-detail">
                <span class="label">Timestamp:</span>
                <span class="value">{violation.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
            <div class="finding-detail">
                <span class="label">Description:</span>
                <span class="value">{self._escape_html(violation.description)}</span>
            </div>"""

        # Add additional details
        if violation.details:
            for key, value in violation.details.items():
                key_formatted = key.replace('_', ' ').title()
                details_html += f"""
            <div class="finding-detail">
                <span class="label">{self._escape_html(key_formatted)}:</span>
                <span class="value">{self._escape_html(str(value))}</span>
            </div>"""

        return f"""
        <div class="finding"
             data-severity="{severity_class}"
             data-ip="{self._escape_html(violation.ip)}"
             data-time="{violation.timestamp.isoformat()}">
            <div class="finding-header {severity_class}">
                <span class="finding-title">{self._escape_html(violation.rule_name)}</span>
                <span class="finding-badge {severity_class}">{violation.severity.value.upper()}</span>
            </div>
            <div class="finding-body">
                {details_html}
            </div>
        </div>"""

    def _generate_anomalies(self, anomalies: list, geo_data: dict | None = None) -> str:
        """Generate the ML anomalies section."""
        if not anomalies:
            return ""

        anomalies_html = ""
        for anomaly in anomalies:
            confidence_color = self.CONFIDENCE_COLORS.get(anomaly.confidence, "#64748b")
            score_percent = int(anomaly.score * 100)

            # Add geo location if available
            ip_display = self._escape_html(anomaly.ip)
            if geo_data and anomaly.ip in geo_data:
                geo = geo_data[anomaly.ip]
                if geo.is_known:
                    ip_display += f" <span style='color: #94a3b8;'>({self._escape_html(str(geo))})</span>"

            explanations_html = ""
            for exp in anomaly.explanation:
                explanations_html += f"<li>{self._escape_html(exp)}</li>"

            anomalies_html += f"""
            <div class="anomaly">
                <div class="anomaly-header">
                    <span class="anomaly-ip">{ip_display}</span>
                    <span class="anomaly-score" style="background: {confidence_color}; color: white;">
                        Score: {score_percent}% ({anomaly.confidence.value.upper()})
                    </span>
                </div>
                <ul class="anomaly-explanations">
                    {explanations_html}
                </ul>
            </div>"""

        return f"""
        <div class="section">
            <h2 class="section-title">
                <span class="icon">&#128202;</span>
                ML Anomalies Detected ({len(anomalies)})
            </h2>
            {anomalies_html}
        </div>"""

    def _generate_drift_warning(self, baseline_drift: dict) -> str:
        """Generate baseline drift warning if detected."""
        if not baseline_drift or not baseline_drift.get('drift_detected'):
            return ""

        drifted = baseline_drift.get('drifted_features', [])
        features_html = ", ".join(drifted) if drifted else "Unknown features"

        return f"""
        <div class="drift-warning">
            <h3>&#9888; Baseline Drift Detected</h3>
            <p>The current data shows significant deviation from the trained baseline in the following features:</p>
            <p><strong>{self._escape_html(features_html)}</strong></p>
            <p>Consider retraining the model with recent data for more accurate detection.</p>
        </div>"""

    def _generate_footer(self, report: AnalysisReport) -> str:
        """Generate the report footer."""
        return f"""
        <div class="footer">
            <p>Generated by <strong>VPSGuard</strong> - ML-first VPS Log Security Analyzer</p>
            <p>Report generated on {report.timestamp.strftime('%Y-%m-%d at %H:%M:%S UTC')}</p>
        </div>"""

    def _group_by_severity(self, violations: list[RuleViolation]) -> dict[Severity, list[RuleViolation]]:
        """Group violations by severity level."""
        grouped = defaultdict(list)
        for violation in violations:
            grouped[violation.severity].append(violation)
        return grouped

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not isinstance(text, str):
            text = str(text)
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))
