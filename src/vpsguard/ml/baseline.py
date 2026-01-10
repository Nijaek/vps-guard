"""Baseline statistics and drift detection for ML models."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np

# Maximum Z-score value for drift detection (used instead of infinity)
# This represents "extremely high" drift that's practically infinite
MAX_Z_SCORE = 1e6


def compute_baseline_stats(
    features: np.ndarray,
    feature_names: list[str],
    model_path: Optional[str] = None
) -> dict:
    """Compute baseline statistics from training data.

    Args:
        features: Feature array of shape (n_samples, n_features).
        feature_names: List of feature names (must match features columns).
        model_path: Optional path where the model is/will be saved.

    Returns:
        Dictionary containing:
        - trained_at: ISO timestamp of when baseline was computed
        - event_count: Number of samples in baseline
        - feature_means: Dict mapping feature names to mean values
        - feature_stds: Dict mapping feature names to std values
        - model_path: Path to associated model file

    Raises:
        ValueError: If features and feature_names don't match.
    """
    if features.shape[1] != len(feature_names):
        raise ValueError(
            f"Feature count mismatch: got {features.shape[1]} features "
            f"but {len(feature_names)} names"
        )

    # Compute statistics
    means = np.mean(features, axis=0)
    stds = np.std(features, axis=0)

    # Build dictionaries
    feature_means = {name: float(mean) for name, mean in zip(feature_names, means)}
    feature_stds = {name: float(std) for name, std in zip(feature_names, stds)}

    return {
        'trained_at': datetime.now(timezone.utc).isoformat(),
        'event_count': int(features.shape[0]),
        'feature_means': feature_means,
        'feature_stds': feature_stds,
        'model_path': model_path,
    }


def detect_drift(
    current_features: np.ndarray,
    feature_names: list[str],
    baseline: dict,
    threshold: float = 2.0
) -> dict:
    """Detect if current data has drifted from baseline.

    Drift occurs when feature distributions change significantly from
    the training data. This can indicate:
    - Attack patterns have evolved
    - System behavior has changed
    - Model needs retraining

    Args:
        current_features: Current feature array of shape (n_samples, n_features).
        feature_names: List of feature names.
        baseline: Baseline stats dict from compute_baseline_stats().
        threshold: Number of standard deviations for drift detection.
                  Default 2.0 means features >2σ from baseline are flagged.

    Returns:
        Dictionary containing:
        - drifted_features: List of feature names that have drifted
        - drift_details: Dict mapping drifted features to drift info:
            - z_score: How many std deviations from baseline
            - current_mean: Current mean value
            - baseline_mean: Baseline mean value
            - baseline_std: Baseline std value
        - drift_detected: Boolean, True if any features drifted

    Raises:
        ValueError: If features and feature_names don't match baseline.
    """
    if current_features.shape[1] != len(feature_names):
        raise ValueError(
            f"Feature count mismatch: got {current_features.shape[1]} features "
            f"but {len(feature_names)} names"
        )

    # Compute current statistics
    current_means = np.mean(current_features, axis=0)

    drifted_features = []
    drift_details = {}

    # Check each feature for drift
    for i, name in enumerate(feature_names):
        if name not in baseline['feature_means']:
            continue

        baseline_mean = baseline['feature_means'][name]
        baseline_std = baseline['feature_stds'][name]
        current_mean = float(current_means[i])

        # Calculate z-score (how many std devs from baseline)
        # Avoid division by zero - use MAX_Z_SCORE instead of infinity for JSON safety
        if baseline_std < 1e-10:
            z_score = 0.0 if abs(current_mean - baseline_mean) < 1e-10 else MAX_Z_SCORE
        else:
            z_score = (current_mean - baseline_mean) / baseline_std

        # Check if drifted
        if abs(z_score) > threshold:
            drifted_features.append(name)
            drift_details[name] = {
                'z_score': float(z_score),
                'current_mean': current_mean,
                'baseline_mean': baseline_mean,
                'baseline_std': baseline_std,
                'direction': 'above' if z_score > 0 else 'below',
            }

    return {
        'drifted_features': drifted_features,
        'drift_details': drift_details,
        'drift_detected': len(drifted_features) > 0,
    }


def save_baseline(baseline: dict, path: Path) -> None:
    """Save baseline statistics to JSON file.

    Args:
        baseline: Baseline stats dict from compute_baseline_stats().
        path: Path to save the baseline to.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, 'w') as f:
        json.dump(baseline, f, indent=2)


def load_baseline(path: Path) -> dict:
    """Load baseline statistics from JSON file.

    Args:
        path: Path to load the baseline from.

    Returns:
        Baseline stats dictionary.

    Raises:
        FileNotFoundError: If baseline file doesn't exist.
        ValueError: If baseline file is invalid.
    """
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")

    try:
        with open(path, 'r') as f:
            baseline = json.load(f)

        # Validate required fields
        required_fields = ['trained_at', 'event_count', 'feature_means', 'feature_stds']
        for field in required_fields:
            if field not in baseline:
                raise ValueError(f"Missing required field: {field}")

        return baseline

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid baseline file: {e}")


def format_drift_report(drift_result: dict) -> str:
    """Format drift detection result as a human-readable report.

    Args:
        drift_result: Result from detect_drift().

    Returns:
        Formatted string report.
    """
    if not drift_result['drift_detected']:
        return "No drift detected - data distribution matches baseline."

    lines = ["Data drift detected in the following features:", ""]

    for feature, details in drift_result['drift_details'].items():
        z_score = details['z_score']
        direction = details['direction']
        current = details['current_mean']
        baseline_mean = details['baseline_mean']

        lines.append(
            f"  {feature}: {current:.2f} "
            f"({abs(z_score):.1f}σ {direction} baseline of {baseline_mean:.2f})"
        )

    lines.append("")
    lines.append(
        f"Total drifted features: {len(drift_result['drifted_features'])} "
        f"/ {len(drift_result['drift_details']) + len(drift_result['drifted_features'])}"
    )
    lines.append("")
    lines.append("Recommendation: Consider retraining the model with recent data.")

    return "\n".join(lines)
