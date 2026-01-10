"""ML Engine - orchestrates ML-based anomaly detection."""

from pathlib import Path
from typing import Optional

import numpy as np

from vpsguard.ml.baseline import compute_baseline_stats, detect_drift, load_baseline, save_baseline
from vpsguard.ml.detector import Detector, IsolationForestDetector
from vpsguard.ml.explain import explain_anomaly
from vpsguard.ml.features import FeatureExtractor
from vpsguard.models.events import AnomalyResult, AuthEvent, Confidence


class MLEngine:
    """Orchestrates ML-based anomaly detection.

    This engine brings together all ML components:
    - Feature extraction from events
    - Model training on clean data
    - Anomaly detection with explanations
    - Baseline tracking and drift detection

    Typical workflow:
        1. Train: engine.train(clean_events) -> creates baseline
        2. Save: engine.save(model_path)
        3. Load: engine.load(model_path)
        4. Detect: engine.detect(new_events) -> AnomalyResults
    """

    def __init__(
        self,
        detector: Optional[Detector] = None,
        baseline: Optional[dict] = None
    ):
        """Initialize ML engine.

        Args:
            detector: Anomaly detector (defaults to IsolationForestDetector).
            baseline: Baseline statistics dict (optional, loaded from training).
        """
        self.detector = detector if detector is not None else IsolationForestDetector()
        self.baseline = baseline
        self.feature_extractor = FeatureExtractor()

    def train(self, events: list[AuthEvent]) -> dict:
        """Train model on clean events (from rule engine).

        This is the critical integration point between rule-based and ML detection.
        The rule engine filters out obvious attacks, leaving clean events for
        training the ML model on "normal" behavior.

        Args:
            events: Clean authentication events (not flagged by rules).

        Returns:
            Baseline statistics dictionary.

        Raises:
            ValueError: If events is empty or feature extraction fails.
        """
        if not events:
            raise ValueError("Cannot train on empty event list")

        # Extract features from clean events
        features, ips = self.feature_extractor.extract_array(events)

        if features.size == 0:
            raise ValueError("Feature extraction produced no features")

        # Train the detector
        self.detector.train(features)

        # Compute baseline statistics
        self.baseline = compute_baseline_stats(
            features=features,
            feature_names=self.feature_extractor.FEATURE_NAMES,
            model_path=None  # Will be set when saving
        )

        return self.baseline

    def detect(
        self,
        events: list[AuthEvent],
        score_threshold: float = 0.6
    ) -> list[AnomalyResult]:
        """Detect anomalies in events.

        Args:
            events: Authentication events to analyze.
            score_threshold: Minimum anomaly score to report (0.0 to 1.0).
                           Default 0.6 filters out low-confidence detections.

        Returns:
            List of AnomalyResult objects for IPs with scores >= threshold.

        Raises:
            RuntimeError: If model hasn't been trained yet.
        """
        if self.baseline is None:
            raise RuntimeError("Model must be trained before detection")

        if not events:
            return []

        # Extract features
        feature_sets = self.feature_extractor.extract(events)

        if not feature_sets:
            return []

        # Prepare features for detection
        features_array = np.vstack([fs.features for fs in feature_sets])

        # Get anomaly scores
        scores = self.detector.detect(features_array)

        # Build anomaly results
        results = []

        for i, feature_set in enumerate(feature_sets):
            score = float(scores[i])

            # Filter by threshold
            if score < score_threshold:
                continue

            # Determine confidence level
            confidence = self._score_to_confidence(score)

            # Generate explanations
            explanations = explain_anomaly(
                features=feature_set.features,
                feature_names=feature_set.feature_names,
                baseline=self.baseline,
                threshold=2.0
            )

            # Build feature dict for result
            feature_dict = {
                name: float(value)
                for name, value in zip(feature_set.feature_names, feature_set.features)
            }

            results.append(AnomalyResult(
                ip=feature_set.ip,
                score=score,
                confidence=confidence,
                explanation=explanations,
                features=feature_dict
            ))

        # Sort by score (highest first)
        results.sort(key=lambda r: r.score, reverse=True)

        return results

    def detect_drift(self, events: list[AuthEvent], threshold: float = 2.0) -> Optional[dict]:
        """Detect if current data has drifted from baseline.

        Args:
            events: Current authentication events to check for drift.
            threshold: Z-score threshold for drift detection.

        Returns:
            Drift detection result dict, or None if no baseline or events.
        """
        if self.baseline is None or not events:
            return None

        # Extract features
        features, ips = self.feature_extractor.extract_array(events)

        if features.size == 0:
            return None

        # Detect drift
        drift_result = detect_drift(
            current_features=features,
            feature_names=self.feature_extractor.FEATURE_NAMES,
            baseline=self.baseline,
            threshold=threshold
        )

        return drift_result

    def save(self, model_path: Path, baseline_path: Optional[Path] = None) -> None:
        """Save trained model and baseline to disk.

        Args:
            model_path: Path to save the model file (.pkl).
            baseline_path: Optional path to save baseline stats (.json).
                         If not provided, uses model_path with .json extension.

        Raises:
            RuntimeError: If model hasn't been trained yet.
        """
        if self.baseline is None:
            raise RuntimeError("Cannot save untrained model")

        # Save detector model
        self.detector.save(model_path)

        # Update baseline with model path
        self.baseline['model_path'] = str(model_path)

        # Determine baseline path
        if baseline_path is None:
            baseline_path = model_path.with_suffix('.json')

        # Save baseline stats
        save_baseline(self.baseline, baseline_path)

    def load(self, model_path: Path, baseline_path: Optional[Path] = None) -> None:
        """Load trained model and baseline from disk.

        Args:
            model_path: Path to load the model file from (.pkl).
            baseline_path: Optional path to load baseline stats from (.json).
                         If not provided, uses model_path with .json extension.

        Raises:
            FileNotFoundError: If model or baseline file doesn't exist.
        """
        # Determine baseline path
        if baseline_path is None:
            baseline_path = model_path.with_suffix('.json')

        # Load detector model
        self.detector.load(model_path)

        # Load baseline stats
        self.baseline = load_baseline(baseline_path)

    def _score_to_confidence(self, score: float) -> Confidence:
        """Convert anomaly score to confidence level.

        Args:
            score: Anomaly score from 0.0 to 1.0.

        Returns:
            Confidence enum value.
        """
        if score > 0.8:
            return Confidence.HIGH
        elif score > 0.6:
            return Confidence.MEDIUM
        else:
            return Confidence.LOW

    def is_trained(self) -> bool:
        """Check if the engine has been trained.

        Returns:
            True if model is trained and ready for detection.
        """
        return self.baseline is not None and hasattr(self.detector, 'is_trained') and self.detector.is_trained
