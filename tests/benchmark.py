"""Performance benchmarks for VPSGuard."""

import time
from pathlib import Path

import pytest

from vpsguard.config import VPSGuardConfig
from vpsguard.parsers import get_parser
from vpsguard.rules.engine import RuleEngine


def generate_test_logs(path: Path, lines: int = 1000):
    """Generate test log entries for benchmarking."""
    from vpsguard.generators import GeneratorConfig, SyntheticLogGenerator

    config = GeneratorConfig(
        entries=lines,
        seed=42
    )

    generator = SyntheticLogGenerator(config)
    output = generator.generate(format_type="auth.log")
    path.write_text(output)


@pytest.mark.benchmark
def test_parse_100k_lines_performance(tmp_path):
    """Benchmark: Parse 100K log lines in under 10 seconds."""
    # Generate test data
    log_file = tmp_path / "benchmark.log"
    generate_test_logs(log_file, lines=100000)

    parser = get_parser("auth.log")

    start = time.time()

    content = log_file.read_text()
    result = parser.parse(content)
    events = result.events

    elapsed = time.time() - start

    print(f"\nParsed {len(events)} events in {elapsed:.2f}s")
    print(f"Rate: {len(events)/elapsed:.0f} events/second")

    assert elapsed < 10.0, f"Parsing took {elapsed:.2f}s, target is <10s"


@pytest.mark.benchmark
def test_analysis_100k_lines_performance(tmp_path):
    """Benchmark: Full analysis (parse + rules) on 100K lines in under 10s."""
    log_file = tmp_path / "benchmark.log"
    generate_test_logs(log_file, lines=100000)

    config = VPSGuardConfig()
    parser = get_parser("auth.log")
    rule_engine = RuleEngine(config)

    start = time.time()

    content = log_file.read_text()
    result = parser.parse(content)
    events = result.events

    output = rule_engine.evaluate(events)
    violations = output.violations

    elapsed = time.time() - start

    print(f"\nAnalyzed with {len(violations)} violations in {elapsed:.2f}s")
    print(f"Rate: {len(events)/elapsed:.0f} events/second")

    assert elapsed < 10.0, f"Analysis took {elapsed:.2f}s, target is <10s"


@pytest.mark.benchmark
def test_incremental_parsing_performance(tmp_path):
    """Benchmark: Incremental parsing should be faster than full re-parse."""
    from vpsguard.history import HistoryDB
    from vpsguard.watch import WatchDaemon

    log_file = tmp_path / "benchmark.log"
    generate_test_logs(log_file, lines=10000)

    history_db = HistoryDB(db_path=tmp_path / "history.db")
    daemon = WatchDaemon(
        log_path=str(log_file),
        interval="1h",
        history_db=history_db
    )

    # First parse - full file
    start = time.time()
    events1 = daemon.parse_log()
    full_parse_time = time.time() - start

    # Append more content
    with open(log_file, 'a') as f:
        f.write("Jan  1 12:00:00 server sshd[1234]: Failed password for user from 192.168.1.1 port 22 ssh2\n" * 100)

    # Second parse - incremental (only new lines)
    start = time.time()
    events2 = daemon.parse_log()
    incremental_time = time.time() - start

    print(f"\nFull parse: {len(events1)} events in {full_parse_time:.3f}s")
    print(f"Incremental: {len(events2)} events in {incremental_time:.3f}s")
    print(f"Speedup: {full_parse_time/max(incremental_time, 0.001):.1f}x")

    # Incremental should be much faster since it only parses new content
    assert incremental_time < full_parse_time, "Incremental should be faster than full parse"


if __name__ == "__main__":
    import sys
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        print("=" * 60)
        print("VPSGuard Performance Benchmarks")
        print("=" * 60)

        print("\n[1/3] Parsing 100K lines...")
        try:
            test_parse_100k_lines_performance(tmp_path)
            print("[PASSED]")
        except AssertionError as e:
            print(f"[FAILED]: {e}")
            sys.exit(1)

        print("\n[2/3] Analyzing 100K lines (parse + rules)...")
        try:
            test_analysis_100k_lines_performance(tmp_path)
            print("[PASSED]")
        except AssertionError as e:
            print(f"[FAILED]: {e}")
            sys.exit(1)

        print("\n[3/3] Incremental parsing performance...")
        try:
            test_incremental_parsing_performance(tmp_path)
            print("[PASSED]")
        except AssertionError as e:
            print(f"[FAILED]: {e}")
            sys.exit(1)

        print("\n" + "=" * 60)
        print("All benchmarks PASSED")
        print("=" * 60)
