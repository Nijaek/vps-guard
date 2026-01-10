"""ML-based anomaly detection module."""

from vpsguard.ml.baseline import (
    compute_baseline_stats,
    detect_drift,
    format_drift_report,
    load_baseline,
    save_baseline,
)
from vpsguard.ml.detector import Detector, IsolationForestDetector
from vpsguard.ml.engine import MLEngine
from vpsguard.ml.explain import explain_anomaly, format_anomaly_summary
from vpsguard.ml.features import FeatureExtractor, FeatureSet

__all__ = [
    'FeatureExtractor',
    'FeatureSet',
    'Detector',
    'IsolationForestDetector',
    'compute_baseline_stats',
    'detect_drift',
    'save_baseline',
    'load_baseline',
    'format_drift_report',
    'explain_anomaly',
    'format_anomaly_summary',
    'MLEngine',
]
