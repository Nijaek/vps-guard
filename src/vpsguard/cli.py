"""CLI interface for VPSGuard."""

import sys
import json
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from vpsguard.parsers import get_parser
from vpsguard.generators import SyntheticLogGenerator, GeneratorConfig, AttackConfig, AttackProfile
from vpsguard.models.events import EventType

app = typer.Typer(
    name="vpsguard",
    help="ML-first VPS log security analyzer",
    add_completion=False,
)
console = Console()


def _auto_detect_format(content: str, filename: Optional[str] = None) -> str:
    """Auto-detect log format from content or filename.

    Args:
        content: First few lines of log content
        filename: Optional filename to check extension

    Returns:
        Detected format type
    """
    # Check filename first
    if filename:
        filename_lower = filename.lower()
        if "auth.log" in filename_lower:
            return "auth.log"
        elif "secure" in filename_lower:
            return "secure"
        elif filename_lower.endswith(".json"):
            return "journald"

    # Check content
    lines = content.strip().split('\n')
    if not lines:
        return "auth.log"  # Default

    first_line = lines[0]

    # Journald format is JSON
    if first_line.startswith('{'):
        try:
            json.loads(first_line)
            return "journald"
        except json.JSONDecodeError:
            pass

    # Both auth.log and secure use syslog format
    # Default to auth.log (they're compatible anyway)
    return "auth.log"


def _display_events_table(events, stats: bool = False):
    """Display events in a rich table.

    Args:
        events: List of AuthEvent objects
        stats: Whether to show statistics
    """
    if not events:
        console.print("[yellow]No events found.[/yellow]")
        return

    # Show statistics if requested
    if stats:
        _display_stats(events)
        console.print()  # Empty line

    # Create events table
    table = Table(title="Parsed Events", show_lines=False)
    table.add_column("Timestamp", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Username", style="green")
    table.add_column("IP", style="yellow")
    table.add_column("Port", style="blue")
    table.add_column("Success", style="white")

    for event in events[:50]:  # Limit to first 50 for display
        table.add_row(
            event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            event.event_type.value,
            event.username or "N/A",
            event.ip or "N/A",
            str(event.port) if event.port else "N/A",
            "Y" if event.success else "N"
        )

    if len(events) > 50:
        console.print(table)
        console.print(f"[dim]... and {len(events) - 50} more events[/dim]")
    else:
        console.print(table)


def _display_stats(events):
    """Display statistics about parsed events.

    Args:
        events: List of AuthEvent objects
    """
    total = len(events)

    # Count by event type
    event_counts = {}
    for event in events:
        event_type = event.event_type.value
        event_counts[event_type] = event_counts.get(event_type, 0) + 1

    # Count unique IPs and usernames
    unique_ips = len(set(e.ip for e in events if e.ip))
    unique_users = len(set(e.username for e in events if e.username))

    # Count successes and failures
    successes = sum(1 for e in events if e.success)
    failures = total - successes

    # Create stats panel
    stats_text = Text()
    stats_text.append(f"Total Events: ", style="bold")
    stats_text.append(f"{total}\n", style="cyan")
    stats_text.append(f"Unique IPs: ", style="bold")
    stats_text.append(f"{unique_ips}\n", style="yellow")
    stats_text.append(f"Unique Users: ", style="bold")
    stats_text.append(f"{unique_users}\n", style="green")
    stats_text.append(f"Successes: ", style="bold")
    stats_text.append(f"{successes}\n", style="green")
    stats_text.append(f"Failures: ", style="bold")
    stats_text.append(f"{failures}\n", style="red")
    stats_text.append("\nEvent Types:\n", style="bold underline")

    for event_type, count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True):
        stats_text.append(f"  {event_type}: ", style="bold")
        stats_text.append(f"{count}\n", style="cyan")

    console.print(Panel(stats_text, title="Statistics", border_style="blue"))


@app.command()
def parse(
    file_path: str = typer.Argument(..., help="Path to log file or '-' for stdin"),
    input_format: Optional[str] = typer.Option(None, "--input-format", help="Input format: auth.log, secure, journald"),
    format: str = typer.Option("table", "--format", help="Output format: table, json"),
    stats: bool = typer.Option(False, "--stats", help="Show summary statistics"),
):
    """Parse log files and display structured events."""
    try:
        # Read input
        if file_path == "-":
            content = sys.stdin.read()
            filename = None
        else:
            path = Path(file_path)
            if not path.exists():
                console.print(f"[red]Error: File not found: {file_path}[/red]")
                raise typer.Exit(1)
            content = path.read_text(encoding="utf-8")
            filename = path.name

        # Auto-detect format if not specified
        if input_format is None:
            input_format = _auto_detect_format(content, filename)
            if format != "json":  # Don't print to console if JSON output
                console.print(f"[dim]Auto-detected format: {input_format}[/dim]")

        # Get parser
        try:
            parser = get_parser(input_format)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Parse content
        result = parser.parse(content)

        # Show parse errors if any
        if result.parse_errors:
            console.print(f"[yellow]Parse errors ({len(result.parse_errors)}):[/yellow]")
            for error in result.parse_errors[:10]:  # Show first 10 errors
                console.print(f"  [dim]{error}[/dim]")
            if len(result.parse_errors) > 10:
                console.print(f"  [dim]... and {len(result.parse_errors) - 10} more errors[/dim]")
            console.print()

        # Output results
        if format == "json":
            # Convert events to JSON-serializable format
            events_data = []
            for event in result.events:
                events_data.append({
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type.value,
                    "ip": event.ip,
                    "username": event.username,
                    "port": event.port,
                    "pid": event.pid,
                    "service": event.service,
                    "success": event.success,
                    "raw_line": event.raw_line,
                })

            output = {
                "total_events": len(result.events),
                "format_type": result.format_type,
                "parse_errors": len(result.parse_errors),
                "events": events_data,
            }

            if stats:
                # Add statistics to JSON output
                event_counts = {}
                for event in result.events:
                    event_type = event.event_type.value
                    event_counts[event_type] = event_counts.get(event_type, 0) + 1

                output["statistics"] = {
                    "unique_ips": len(set(e.ip for e in result.events if e.ip)),
                    "unique_users": len(set(e.username for e in result.events if e.username)),
                    "successes": sum(1 for e in result.events if e.success),
                    "failures": sum(1 for e in result.events if not e.success),
                    "event_counts": event_counts,
                }

            console.print_json(json.dumps(output, indent=2))
        else:
            # Table format
            _display_events_table(result.events, stats=stats)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def generate(
    entries: int = typer.Option(..., "--entries", help="Number of log entries to generate"),
    output: Optional[str] = typer.Option(None, "--output", help="Output file path (stdout if not specified)"),
    attack_profile: List[str] = typer.Option([], "--attack-profile", help="Attack profile in format 'profile:ratio' (e.g., 'botnet:0.1')"),
    format: str = typer.Option("auth.log", "--format", help="Output format: auth.log, secure, journald"),
    seed: Optional[int] = typer.Option(None, "--seed", help="Random seed for reproducibility"),
):
    """Generate synthetic log files for testing."""
    try:
        # Parse attack profiles
        attack_configs = []
        for profile_str in attack_profile:
            if ":" not in profile_str:
                console.print(f"[red]Error: Invalid attack profile format: {profile_str}[/red]")
                console.print("[yellow]Expected format: 'profile:ratio' (e.g., 'botnet:0.1')[/yellow]")
                raise typer.Exit(1)

            profile_name, ratio_str = profile_str.split(":", 1)

            # Map profile names to AttackProfile enum
            profile_map = {
                "brute": AttackProfile.BRUTE_FORCE,
                "brute_force": AttackProfile.BRUTE_FORCE,
                "botnet": AttackProfile.BOTNET,
                "stuffing": AttackProfile.CREDENTIAL_STUFFING,
                "credential_stuffing": AttackProfile.CREDENTIAL_STUFFING,
                "low-slow": AttackProfile.LOW_AND_SLOW,
                "low_and_slow": AttackProfile.LOW_AND_SLOW,
                "breach": AttackProfile.BREACH,
                "recon": AttackProfile.RECON,
            }

            if profile_name not in profile_map:
                console.print(f"[red]Error: Unknown attack profile: {profile_name}[/red]")
                console.print(f"[yellow]Available profiles: {', '.join(profile_map.keys())}[/yellow]")
                raise typer.Exit(1)

            try:
                ratio = float(ratio_str)
            except ValueError:
                console.print(f"[red]Error: Invalid ratio: {ratio_str}[/red]")
                raise typer.Exit(1)

            # Create attack config with sensible defaults
            attack_configs.append(AttackConfig(
                profile=profile_map[profile_name],
                ratio=ratio,
            ))

        # Create generator config
        config = GeneratorConfig(
            entries=entries,
            attack_profiles=attack_configs,
            seed=seed,
        )

        # Generate logs
        generator = SyntheticLogGenerator(config)
        content = generator.generate(format_type=format)

        # Output
        if output:
            output_path = Path(output)
            output_path.write_text(content, encoding="utf-8")
            console.print(f"[green]Generated {entries} log entries to {output}[/green]")
        else:
            # Write to stdout
            print(content)

    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def init(
    output: str = typer.Option("vpsguard.toml", "--output", help="Output config file path"),
    force: bool = typer.Option(False, "--force", help="Force overwrite existing file"),
):
    """Initialize a default configuration file."""
    try:
        output_path = Path(output)

        # Check if file exists
        if output_path.exists() and not force:
            console.print(f"[yellow]Config file already exists: {output}[/yellow]")
            console.print("[yellow]Use --force to overwrite[/yellow]")
            raise typer.Exit(1)

        # Default configuration
        config_content = """# VPSGuard Configuration

[rules.brute_force]
enabled = true
threshold = 10
window_minutes = 60
severity = "high"

[rules.breach_detection]
enabled = true
failures_before_success = 5
severity = "critical"

[rules.quiet_hours]
enabled = true
start = 23
end = 6
timezone = "UTC"
severity = "medium"

[whitelist]
ips = []

[output]
format = "terminal"
verbosity = 1
"""

        output_path.write_text(config_content, encoding="utf-8")
        console.print(f"[green]Created configuration file: {output}[/green]")
        console.print("\n[cyan]Next steps:[/cyan]")
        console.print(f"  1. Edit {output} to customize your rules")
        console.print(f"  2. Run 'vpsguard parse <logfile>' to analyze logs")
        console.print(f"  3. Run 'vpsguard generate --entries 1000' to create test data")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def train(
    file_path: str = typer.Argument(..., help="Path to log file to train on"),
    model: str = typer.Option("vpsguard_model.pkl", "--model", help="Path to save model file"),
    config: Optional[str] = typer.Option(None, "--config", help="Path to TOML config file"),
    input_format: Optional[str] = typer.Option(None, "--input-format", help="Input format: auth.log, secure, journald"),
    check: bool = typer.Option(False, "--check", help="Check and display baseline stats (no training)"),
):
    """Train ML model on log file using clean events."""
    try:
        from pathlib import Path
        from vpsguard.config import load_config
        from vpsguard.rules.engine import RuleEngine
        from vpsguard.ml.engine import MLEngine
        from vpsguard.ml.baseline import load_baseline
        from datetime import datetime

        model_path = Path(model)

        # If --check, just display baseline info
        if check:
            baseline_path = model_path.with_suffix('.json')

            if not baseline_path.exists():
                console.print(f"[red]No baseline found at: {baseline_path}[/red]")
                console.print(f"[yellow]Train a model first with: vpsguard train <logfile> --model {model}[/yellow]")
                raise typer.Exit(1)

            try:
                baseline = load_baseline(baseline_path)

                # Display baseline info
                console.print(Panel("[bold cyan]Baseline Statistics[/bold cyan]", border_style="cyan"))
                console.print(f"[bold]Trained at:[/bold] {baseline['trained_at']}")
                console.print(f"[bold]Event count:[/bold] {baseline['event_count']}")
                console.print(f"[bold]Model path:[/bold] {baseline.get('model_path', 'N/A')}")
                console.print("\n[bold cyan]Feature Means:[/bold cyan]")

                for name, mean in baseline['feature_means'].items():
                    std = baseline['feature_stds'][name]
                    console.print(f"  {name}: {mean:.2f} (±{std:.2f})")

                return

            except Exception as e:
                console.print(f"[red]Error loading baseline: {e}[/red]")
                raise typer.Exit(1)

        # Load configuration
        try:
            vps_config = load_config(config)
            if config:
                console.print(f"[dim]Loaded config from: {config}[/dim]")
            else:
                console.print(f"[dim]Using default configuration[/dim]")
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Read and parse log file
        path = Path(file_path)
        if not path.exists():
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            raise typer.Exit(1)

        console.print(f"[dim]Reading log file: {file_path}[/dim]")
        content = path.read_text(encoding="utf-8")

        # Auto-detect format
        if input_format is None:
            input_format = _auto_detect_format(content, path.name)
            console.print(f"[dim]Auto-detected format: {input_format}[/dim]")

        # Parse logs
        parser = get_parser(input_format)
        console.print(f"[dim]Parsing logs...[/dim]")
        parsed = parser.parse(content)
        console.print(f"[green]Parsed {len(parsed.events)} events[/green]")

        # Run rule engine to get clean events
        console.print(f"[dim]Running rule engine to filter attacks...[/dim]")
        engine = RuleEngine(vps_config)
        rule_output = engine.evaluate(parsed.events)

        console.print(f"[yellow]Found {len(rule_output.violations)} rule violations[/yellow]")
        console.print(f"[green]Clean events for training: {len(rule_output.clean_events)}[/green]")

        if len(rule_output.clean_events) < 10:
            console.print(f"[red]Error: Not enough clean events for training (need at least 10)[/red]")
            console.print(f"[yellow]This usually means your log file is mostly attacks.[/yellow]")
            raise typer.Exit(1)

        # Train ML model
        console.print(f"[dim]Training ML model...[/dim]")
        ml_engine = MLEngine()
        baseline = ml_engine.train(rule_output.clean_events)

        # Save model
        console.print(f"[dim]Saving model to: {model_path}[/dim]")
        ml_engine.save(model_path)

        # Display success
        console.print(Panel(
            f"[bold green]Training Complete![/bold green]\n\n"
            f"Model saved to: {model_path}\n"
            f"Baseline saved to: {model_path.with_suffix('.json')}\n"
            f"Trained on {baseline['event_count']} clean events\n"
            f"Trained at: {baseline['trained_at']}",
            border_style="green"
        ))

        console.print("\n[cyan]Next steps:[/cyan]")
        console.print(f"  1. Check baseline: vpsguard train --check --model {model}")
        console.print(f"  2. Analyze logs: vpsguard analyze <logfile> --with-ml --model {model}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)


@app.command()
def analyze(
    file_path: str = typer.Argument(..., help="Path to log file or '-' for stdin"),
    config: Optional[str] = typer.Option(None, "--config", help="Path to TOML config file"),
    input_format: Optional[str] = typer.Option(None, "--input-format", help="Input format: auth.log, secure, journald"),
    rules_only: bool = typer.Option(True, "--rules-only/--with-ml", help="Only run rule-based detection (skip ML)"),
    model: str = typer.Option("vpsguard_model.pkl", "--model", help="Path to ML model file"),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="Verbosity level (0=critical/high, 1=+medium, 2=all)"),
    format: str = typer.Option("terminal", "--format", help="Output format: terminal, markdown, json"),
    output: Optional[str] = typer.Option(None, "--output", help="Output file path (stdout if not specified)"),
):
    """Analyze log files for security threats."""
    try:
        from datetime import datetime, timezone
        from pathlib import Path
        from vpsguard.config import load_config
        from vpsguard.rules.engine import RuleEngine
        from vpsguard.reporters import get_reporter
        from vpsguard.models.events import AnalysisReport, Severity

        # Load configuration
        try:
            vps_config = load_config(config)
            if format != "json":
                if config:
                    console.print(f"[dim]Loaded config from: {config}[/dim]")
                else:
                    console.print(f"[dim]Using default configuration[/dim]")
        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Read input
        if file_path == "-":
            content = sys.stdin.read()
            filename = None
            log_source = "stdin"
        else:
            path = Path(file_path)
            if not path.exists():
                console.print(f"[red]Error: File not found: {file_path}[/red]")
                raise typer.Exit(1)
            content = path.read_text(encoding="utf-8")
            filename = path.name
            log_source = str(path)

        # Auto-detect format if not specified
        if input_format is None:
            input_format = _auto_detect_format(content, filename)
            if format != "json":
                console.print(f"[dim]Auto-detected format: {input_format}[/dim]")

        # Get parser
        try:
            parser = get_parser(input_format)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Parse content
        if format != "json":
            console.print(f"[dim]Parsing log file...[/dim]")
        parsed = parser.parse(content)

        # Show parse errors if any
        if parsed.parse_errors and format != "json":
            console.print(f"[yellow]Parse errors: {len(parsed.parse_errors)}[/yellow]")

        # Run rule engine
        if format != "json":
            console.print(f"[dim]Running rule engine...[/dim]")

        engine = RuleEngine(vps_config)
        rule_output = engine.evaluate(parsed.events)

        # Filter violations by verbosity level
        filtered_violations = []
        for violation in rule_output.violations:
            if verbose == 0:
                # Only CRITICAL and HIGH
                if violation.severity in [Severity.CRITICAL, Severity.HIGH]:
                    filtered_violations.append(violation)
            elif verbose == 1:
                # CRITICAL, HIGH, and MEDIUM
                if violation.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                    filtered_violations.append(violation)
            else:
                # All severities (verbose >= 2)
                filtered_violations.append(violation)

        # Run ML detection if requested
        anomalies = []
        baseline_drift = None

        if not rules_only:
            from vpsguard.ml.engine import MLEngine

            model_path = Path(model)
            baseline_path = model_path.with_suffix('.json')

            if not model_path.exists():
                if format != "json":
                    console.print(f"[yellow]Warning: ML model not found at {model_path}[/yellow]")
                    console.print(f"[yellow]Train a model first with: vpsguard train <logfile> --model {model}[/yellow]")
                    console.print(f"[yellow]Continuing with rule-based detection only...[/yellow]")
            else:
                try:
                    if format != "json":
                        console.print(f"[dim]Loading ML model from {model_path}...[/dim]")

                    ml_engine = MLEngine()
                    ml_engine.load(model_path)

                    if format != "json":
                        console.print(f"[dim]Running ML anomaly detection...[/dim]")

                    # Detect anomalies
                    anomalies = ml_engine.detect(parsed.events, score_threshold=0.6)

                    # Check for drift
                    baseline_drift = ml_engine.detect_drift(parsed.events, threshold=2.0)

                    if format != "json":
                        console.print(f"[green]ML detected {len(anomalies)} anomalous IPs[/green]")
                        if baseline_drift and baseline_drift['drift_detected']:
                            console.print(f"[yellow]Warning: Data drift detected in {len(baseline_drift['drifted_features'])} features[/yellow]")

                except Exception as e:
                    if format != "json":
                        console.print(f"[yellow]Warning: ML detection failed: {e}[/yellow]")
                        console.print(f"[yellow]Continuing with rule-based detection only...[/yellow]")

        # Build analysis report
        analysis_report = AnalysisReport(
            timestamp=datetime.now(timezone.utc),
            log_source=log_source,
            total_events=len(parsed.events),
            rule_violations=filtered_violations,
            anomalies=anomalies,
            baseline_drift=baseline_drift,
            summary=None,
        )

        # Generate report
        reporter = get_reporter(format)

        if output:
            # Write to file
            reporter.generate_to_file(analysis_report, output)
            if format != "json":
                console.print(f"[green]Report written to: {output}[/green]")
        else:
            # Output to console
            if format == "terminal":
                # Use display method for terminal reporter
                from vpsguard.reporters.terminal import TerminalReporter
                if isinstance(reporter, TerminalReporter):
                    reporter.display(analysis_report)
                else:
                    print(reporter.generate(analysis_report))
            else:
                # For markdown and json, just print
                print(reporter.generate(analysis_report))

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)


@app.callback()
def main():
    """ML-first VPS log security analyzer."""
    pass


if __name__ == "__main__":
    app()
