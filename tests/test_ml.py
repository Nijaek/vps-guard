"""Tests for ML-based anomaly detection."""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pytest

from vpsguard.ml.baseline import (
    compute_baseline_stats,
    detect_drift,
    format_drift_report,
    load_baseline,
    save_baseline,
)
from vpsguard.ml.detector import IsolationForestDetector
from vpsguard.ml.engine import MLEngine
from vpsguard.ml.explain import explain_anomaly, format_anomaly_summary
from vpsguard.ml.features import FeatureExtractor
from vpsguard.models.events import AuthEvent, Confidence, EventType


def create_normal_events(ip: str, count: int, start_time: datetime) -> list[AuthEvent]:
    """Create normal login events for testing."""
    events = []
    for i in range(count):
        events.append(AuthEvent(
            timestamp=start_time + timedelta(minutes=i * 30),
            event_type=EventType.SUCCESSFUL_LOGIN,
            ip=ip,
            username=f"user{i % 3}",  # Small set of users
            success=True,
            raw_line=f"test line {i}",
        ))
    return events


def create_attack_events(ip: str, count: int, start_time: datetime) -> list[AuthEvent]:
    """Create attack-like events for testing."""
    events = []
    for i in range(count):
        events.append(AuthEvent(
            timestamp=start_time + timedelta(seconds=i * 5),  # Fast attempts
            event_type=EventType.FAILED_LOGIN,
            ip=ip,
            username=f"random_user_{i}",  # Many different users
            success=False,
            raw_line=f"attack line {i}",
        ))
    return events


def create_botnet_events(num_ips: int, attempts_per_ip: int, start_time: datetime) -> list[AuthEvent]:
    """Create coordinated botnet attack events."""
    events = []
    target_users = ["admin", "root", "postgres"]

    for ip_idx in range(num_ips):
        ip = f"10.0.{ip_idx // 256}.{ip_idx % 256}"

        for attempt in range(attempts_per_ip):
            # All IPs target the same users around the same time
            events.append(AuthEvent(
                timestamp=start_time + timedelta(seconds=attempt * 10 + ip_idx),
                event_type=EventType.FAILED_LOGIN,
                ip=ip,
                username=target_users[attempt % len(target_users)],
                success=False,
                raw_line=f"botnet attack from {ip}",
            ))

    return events


class TestFeatureExtractor:
    """Test feature extraction."""

    def test_extract_basic(self):
        """Test basic feature extraction."""
        extractor = FeatureExtractor()
        events = create_normal_events("192.168.1.1", 10, datetime.now())

        feature_sets = extractor.extract(events)

        assert len(feature_sets) == 1
        assert feature_sets[0].ip == "192.168.1.1"
        assert len(feature_sets[0].features) == len(extractor.FEATURE_NAMES)
        assert feature_sets[0].feature_names == extractor.FEATURE_NAMES

    def test_extract_multiple_ips(self):
        """Test extraction for multiple IPs."""
        extractor = FeatureExtractor()
        start_time = datetime.now()

        events = []
        events.extend(create_normal_events("192.168.1.1", 5, start_time))
        events.extend(create_normal_events("192.168.1.2", 5, start_time))
        events.extend(create_attack_events("192.168.1.3", 20, start_time))

        feature_sets = extractor.extract(events)

        assert len(feature_sets) == 3
        ips = {fs.ip for fs in feature_sets}
        assert ips == {"192.168.1.1", "192.168.1.2", "192.168.1.3"}

    def test_extract_array(self):
        """Test extract_array method."""
        extractor = FeatureExtractor()
        events = create_normal_events("192.168.1.1", 10, datetime.now())

        features, ips = extractor.extract_array(events)

        assert isinstance(features, np.ndarray)
        assert features.shape == (1, len(extractor.FEATURE_NAMES))
        assert ips == ["192.168.1.1"]

    def test_failure_ratio_feature(self):
        """Test that failure ratio is calculated correctly."""
        extractor = FeatureExtractor()
        start_time = datetime.now()

        # Create events with known failure ratio
        events = []
        for i in range(10):
            events.append(AuthEvent(
                timestamp=start_time + timedelta(seconds=i),
                event_type=EventType.FAILED_LOGIN if i < 7 else EventType.SUCCESSFUL_LOGIN,
                ip="192.168.1.1",
                username="user1",
                success=i >= 7,
                raw_line=f"line {i}",
            ))

        feature_sets = extractor.extract(events)
        features = feature_sets[0].features
        failure_ratio_idx = extractor.FEATURE_NAMES.index("failure_ratio")

        assert abs(features[failure_ratio_idx] - 0.7) < 0.01

    def test_clustering_feature(self):
        """Test clustering detection (coordinated attack)."""
        extractor = FeatureExtractor()
        start_time = datetime.now()

        # Create coordinated attack
        events = create_botnet_events(5, 3, start_time)

        feature_sets = extractor.extract(events)

        # Each IP should have high clustering score
        clustering_idx = extractor.FEATURE_NAMES.index("same_target_ips_5min")
        for fs in feature_sets:
            # Should detect other IPs targeting same users
            assert fs.features[clustering_idx] > 0

    def test_username_entropy(self):
        """Test username entropy feature."""
        extractor = FeatureExtractor()
        start_time = datetime.now()

        # High entropy: random usernames
        random_events = []
        for i in range(20):
            random_events.append(AuthEvent(
                timestamp=start_time + timedelta(seconds=i),
                event_type=EventType.FAILED_LOGIN,
                ip="192.168.1.1",
                username=f"xyz{i}abc{i*2}def",
                success=False,
                raw_line=f"line {i}",
            ))

        # Low entropy: same username
        targeted_events = []
        for i in range(20):
            targeted_events.append(AuthEvent(
                timestamp=start_time + timedelta(seconds=i),
                event_type=EventType.FAILED_LOGIN,
                ip="192.168.1.2",
                username="admin",
                success=False,
                raw_line=f"line {i}",
            ))

        all_events = random_events + targeted_events
        feature_sets = extractor.extract(all_events)

        entropy_idx = extractor.FEATURE_NAMES.index("username_entropy")

        # Find the feature sets
        random_fs = next(fs for fs in feature_sets if fs.ip == "192.168.1.1")
        targeted_fs = next(fs for fs in feature_sets if fs.ip == "192.168.1.2")

        # Random usernames should have higher entropy
        assert random_fs.features[entropy_idx] > targeted_fs.features[entropy_idx]

    def test_attack_vectors_feature(self):
        """Test attack_vectors feature (multi-log correlation)."""
        extractor = FeatureExtractor()
        start_time = datetime.now()

        # IP 1 appears in multiple log sources
        multi_source_events = []
        for source in ["auth.log", "nginx.log", "secure"]:
            for i in range(3):
                multi_source_events.append(AuthEvent(
                    timestamp=start_time + timedelta(seconds=i),
                    event_type=EventType.FAILED_LOGIN,
                    ip="192.168.1.1",
                    username="admin",
                    success=False,
                    raw_line=f"line {i}",
                    log_source=source
                ))

        # IP 2 appears in only one log source
        single_source_events = []
        for i in range(10):
            single_source_events.append(AuthEvent(
                timestamp=start_time + timedelta(seconds=i),
                event_type=EventType.FAILED_LOGIN,
                ip="192.168.1.2",
                username="admin",
                success=False,
                raw_line=f"line {i}",
                log_source="auth.log"
            ))

        # IP 3 has no log_source set
        no_source_events = []
        for i in range(5):
            no_source_events.append(AuthEvent(
                timestamp=start_time + timedelta(seconds=i),
                event_type=EventType.FAILED_LOGIN,
                ip="192.168.1.3",
                username="admin",
                success=False,
                raw_line=f"line {i}",
                log_source=None
            ))

        all_events = multi_source_events + single_source_events + no_source_events
        feature_sets = extractor.extract(all_events)

        attack_vectors_idx = extractor.FEATURE_NAMES.index("attack_vectors")

        # Find feature sets by IP
        multi_fs = next(fs for fs in feature_sets if fs.ip == "192.168.1.1")
        single_fs = next(fs for fs in feature_sets if fs.ip == "192.168.1.2")
        no_source_fs = next(fs for fs in feature_sets if fs.ip == "192.168.1.3")

        # Multi-source IP should have attack_vectors = 3
        assert multi_fs.features[attack_vectors_idx] == 3.0

        # Single source IP should have attack_vectors = 1
        assert single_fs.features[attack_vectors_idx] == 1.0

        # IP without log_source should have attack_vectors = 0
        assert no_source_fs.features[attack_vectors_idx] == 0.0


class TestIsolationForestDetector:
    """Test Isolation Forest detector."""

    def test_train_and_detect(self):
        """Test basic training and detection."""
        detector = IsolationForestDetector(contamination=0.1, random_state=42)

        # Generate training data (normal behavior)
        np.random.seed(42)
        normal_data = np.random.randn(100, 5) * 0.5

        # Train
        detector.train(normal_data)
        assert detector.is_trained

        # Detect on normal data
        scores = detector.detect(normal_data[:10])
        assert len(scores) == 10
        assert all(0 <= s <= 1 for s in scores)

    def test_detect_anomalies(self):
        """Test that anomalies get higher scores."""
        detector = IsolationForestDetector(contamination=0.1, random_state=42)

        # Train on normal data
        np.random.seed(42)
        normal_data = np.random.randn(100, 5) * 0.5
        detector.train(normal_data)

        # Create anomalous data (far from normal)
        anomalous_data = np.random.randn(10, 5) * 5 + 10

        # Detect
        normal_scores = detector.detect(normal_data[:10])
        anomalous_scores = detector.detect(anomalous_data)

        # Anomalies should have higher scores on average
        assert np.mean(anomalous_scores) > np.mean(normal_scores)

    def test_save_and_load(self):
        """Test model persistence."""
        detector = IsolationForestDetector(contamination=0.1, random_state=42)

        # Train
        np.random.seed(42)
        data = np.random.randn(100, 5)
        detector.train(data)

        # Save
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "test_model.pkl"
            detector.save(model_path)

            # Load into new detector
            new_detector = IsolationForestDetector()
            new_detector.load(model_path)

            assert new_detector.is_trained

            # Should produce same results
            scores1 = detector.detect(data[:10])
            scores2 = new_detector.detect(data[:10])

            np.testing.assert_array_almost_equal(scores1, scores2, decimal=6)

    def test_error_on_untrained(self):
        """Test that detection fails on untrained model."""
        detector = IsolationForestDetector()
        data = np.random.randn(10, 5)

        with pytest.raises(RuntimeError, match="must be trained"):
            detector.detect(data)


class TestBaseline:
    """Test baseline statistics and drift detection."""

    def test_compute_baseline_stats(self):
        """Test baseline statistics computation."""
        features = np.array([
            [1.0, 2.0, 3.0],
            [2.0, 3.0, 4.0],
            [1.5, 2.5, 3.5],
        ])
        feature_names = ["f1", "f2", "f3"]

        baseline = compute_baseline_stats(features, feature_names)

        assert "trained_at" in baseline
        assert baseline["event_count"] == 3
        assert set(baseline["feature_means"].keys()) == {"f1", "f2", "f3"}
        assert abs(baseline["feature_means"]["f1"] - 1.5) < 0.01

    def test_detect_drift(self):
        """Test drift detection."""
        # Baseline
        baseline_features = np.random.randn(100, 3) * 0.5
        feature_names = ["f1", "f2", "f3"]
        baseline = compute_baseline_stats(baseline_features, feature_names)

        # Current data - no drift
        current_normal = np.random.randn(50, 3) * 0.5
        drift_result = detect_drift(current_normal, feature_names, baseline, threshold=2.0)

        assert not drift_result["drift_detected"]
        assert len(drift_result["drifted_features"]) == 0

        # Current data - with drift
        current_drifted = np.random.randn(50, 3) * 0.5 + 5  # Shifted mean
        drift_result = detect_drift(current_drifted, feature_names, baseline, threshold=2.0)

        assert drift_result["drift_detected"]
        assert len(drift_result["drifted_features"]) > 0

    def test_save_and_load_baseline(self):
        """Test baseline persistence."""
        features = np.random.randn(100, 3)
        feature_names = ["f1", "f2", "f3"]
        baseline = compute_baseline_stats(features, feature_names)

        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = Path(tmpdir) / "baseline.json"

            save_baseline(baseline, baseline_path)
            assert baseline_path.exists()

            loaded_baseline = load_baseline(baseline_path)

            assert loaded_baseline["event_count"] == baseline["event_count"]
            assert loaded_baseline["feature_means"] == baseline["feature_means"]

    def test_format_drift_report(self):
        """Test drift report formatting."""
        drift_result = {
            "drift_detected": True,
            "drifted_features": ["f1", "f2"],
            "drift_details": {
                "f1": {
                    "z_score": 3.5,
                    "current_mean": 10.0,
                    "baseline_mean": 2.0,
                    "direction": "above",
                },
                "f2": {
                    "z_score": -2.8,
                    "current_mean": 1.0,
                    "baseline_mean": 5.0,
                    "direction": "below",
                },
            },
        }

        report = format_drift_report(drift_result)

        assert "drift detected" in report.lower()
        assert "f1" in report
        assert "f2" in report


class TestExplain:
    """Test explainability."""

    def test_explain_anomaly(self):
        """Test anomaly explanation generation."""
        features = np.array([50.0, 10.0, 0.95, 12.0, 2.0, 20.0, 1.0, 5.0, 4.5, 3.0])
        feature_names = FeatureExtractor.FEATURE_NAMES

        baseline = {
            "feature_means": {name: 5.0 for name in feature_names},
            "feature_stds": {name: 2.0 for name in feature_names},
        }

        explanations = explain_anomaly(features, feature_names, baseline, threshold=2.0)

        # Should have explanations for features far from baseline
        assert len(explanations) > 0
        assert any("attempts_per_hour" in exp for exp in explanations)

    def test_format_anomaly_summary(self):
        """Test anomaly summary formatting."""
        explanations = [
            "attempts_per_hour: 50.00 (3.2σ above baseline)",
            "failure_ratio: 0.95 (2.8σ above baseline)",
        ]

        summary = format_anomaly_summary("192.168.1.1", 0.85, explanations)

        assert "192.168.1.1" in summary
        assert "0.85" in summary or "0.850" in summary
        assert "attempts_per_hour" in summary


class TestMLEngine:
    """Test ML engine integration."""

    def test_train_and_detect(self):
        """Test complete training and detection workflow."""
        engine = MLEngine()

        # Create training data (normal)
        start_time = datetime.now()
        training_events = []
        for i in range(5):
            ip = f"192.168.1.{i+1}"
            training_events.extend(create_normal_events(ip, 10, start_time))

        # Train
        baseline = engine.train(training_events)

        assert baseline is not None
        assert engine.is_trained()

        # Create test data (mix of normal and attack)
        test_events = []
        test_events.extend(create_normal_events("192.168.1.100", 10, start_time))
        test_events.extend(create_attack_events("192.168.1.200", 50, start_time))

        # Detect with low threshold to get both
        results = engine.detect(test_events, score_threshold=0.3)

        assert len(results) > 0

        # Attack IP should have more explanations than normal
        # (Features deviating more from baseline)
        attack_result = next((r for r in results if r.ip == "192.168.1.200"), None)
        normal_result = next((r for r in results if r.ip == "192.168.1.100"), None)

        assert attack_result is not None, "Attack IP should be detected"

        # Attack should have more feature deviations
        if normal_result:
            assert len(attack_result.explanation) > len(normal_result.explanation)
        else:
            # If normal wasn't detected, that's fine - attack should have explanations
            assert len(attack_result.explanation) > 0

    def test_save_and_load(self):
        """Test engine persistence."""
        engine = MLEngine()

        # Train
        start_time = datetime.now()
        training_events = create_normal_events("192.168.1.1", 20, start_time)
        engine.train(training_events)

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "model.pkl"

            # Save
            engine.save(model_path)
            assert model_path.exists()
            assert model_path.with_suffix('.json').exists()

            # Load into new engine
            new_engine = MLEngine()
            new_engine.load(model_path)

            assert new_engine.is_trained()

            # Should produce same results
            test_events = create_normal_events("192.168.1.100", 10, start_time)
            results1 = engine.detect(test_events, score_threshold=0.5)
            results2 = new_engine.detect(test_events, score_threshold=0.5)

            assert len(results1) == len(results2)

    def test_detect_drift(self):
        """Test drift detection in engine."""
        engine = MLEngine()

        # Train on normal data
        start_time = datetime.now()
        training_events = create_normal_events("192.168.1.1", 50, start_time)
        engine.train(training_events)

        # Test with similar data (no drift)
        normal_events = create_normal_events("192.168.1.2", 30, start_time)
        drift_result = engine.detect_drift(normal_events, threshold=2.0)

        # Might or might not drift, but should not error
        assert drift_result is not None

    def test_confidence_levels(self):
        """Test that confidence levels are assigned correctly."""
        engine = MLEngine()

        # Train
        start_time = datetime.now()
        training_events = create_normal_events("192.168.1.1", 30, start_time)
        engine.train(training_events)

        # Detect
        test_events = create_attack_events("192.168.1.200", 50, start_time)
        results = engine.detect(test_events, score_threshold=0.0)

        # Check confidence levels
        for result in results:
            if result.score > 0.8:
                assert result.confidence == Confidence.HIGH
            elif result.score > 0.6:
                assert result.confidence == Confidence.MEDIUM
            else:
                assert result.confidence == Confidence.LOW


class TestBotnetDetection:
    """Critical test: Can ML detect botnet attacks that rules might miss?"""

    def test_botnet_detection(self):
        """
        Test that ML can detect coordinated botnet attacks.

        This is the key differentiator - botnets spread attacks across
        many IPs to avoid rate-based rules, but ML can detect the
        coordinated pattern.
        """
        engine = MLEngine()

        # Train on normal, diverse traffic
        start_time = datetime.now()
        training_events = []

        for i in range(20):
            ip = f"10.0.0.{i}"
            # Normal users login successfully with occasional failures
            for j in range(5):
                training_events.append(AuthEvent(
                    timestamp=start_time + timedelta(hours=i, minutes=j * 30),
                    event_type=EventType.SUCCESSFUL_LOGIN if j < 4 else EventType.FAILED_LOGIN,
                    ip=ip,
                    username=f"user{j % 3}",
                    success=j < 4,
                    raw_line=f"normal traffic {i}",
                ))

        engine.train(training_events)

        # Create botnet attack: 20 IPs, each making only 5 attempts
        # (Too low to trigger brute force rules individually)
        botnet_start = start_time + timedelta(days=1)
        botnet_events = create_botnet_events(
            num_ips=20,
            attempts_per_ip=5,
            start_time=botnet_start
        )

        # Detect with moderate threshold
        results = engine.detect(botnet_events, score_threshold=0.3)

        # ML should detect anomalous IPs from the botnet
        # Because of:
        # 1. High failure ratio (all failures vs normal mix)
        # 2. Temporal patterns different from training
        # 3. Potentially clustering if multiple IPs detected
        assert len(results) > 0, "ML should detect botnet IPs"

        # Check that botnet IPs are flagged with high failure ratio
        failure_ratio_detected = False
        for result in results:
            for explanation in result.explanation:
                if "failure_ratio" in explanation.lower():
                    failure_ratio_detected = True
                    break

        # This is the critical assertion - ML detects what rules miss
        # Botnets with low per-IP rates evade brute force rules, but ML
        # still catches them due to feature anomalies
        assert failure_ratio_detected or len(results) >= 3, (
            "ML should detect botnet IPs based on feature anomalies. "
            "This is the key differentiator from rule-based detection."
        )
