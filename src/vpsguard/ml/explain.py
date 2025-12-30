"""Explainability for ML-based anomaly detection."""

import numpy as np
from typing import Optional


def explain_anomaly(
    features: np.ndarray,
    feature_names: list[str],
    baseline: dict,
    threshold: float = 2.0
) -> list[str]:
    """Generate human-readable explanations for why an IP is anomalous.

    This function analyzes features that deviate significantly from the
    baseline and generates explanations that help security analysts
    understand what makes this IP suspicious.

    Args:
        features: Feature array for a single IP (1D array of length n_features).
        feature_names: List of feature names.
        baseline: Baseline stats dict with 'feature_means' and 'feature_stds'.
        threshold: Z-score threshold for including a feature in explanation.
                  Default 2.0 means features >2σ from baseline are explained.

    Returns:
        List of human-readable explanation strings, sorted by deviation magnitude.
        Returns empty list if no features deviate significantly.

    Example:
        >>> explain_anomaly(features, names, baseline)
        [
            "attempts_per_hour: 50.00 (3.2σ above baseline)",
            "failure_ratio: 0.95 (2.8σ above baseline)",
            "same_target_ips_5min: 12.00 (2.5σ above baseline)"
        ]
    """
    if len(features) != len(feature_names):
        raise ValueError(
            f"Feature count mismatch: got {len(features)} features "
            f"but {len(feature_names)} names"
        )

    explanations = []
    deviations = []  # For sorting

    for i, name in enumerate(feature_names):
        feature_value = features[i]

        # Get baseline stats
        baseline_mean = baseline['feature_means'].get(name, 0.0)
        baseline_std = baseline['feature_stds'].get(name, 0.0)

        # Calculate z-score (deviation from baseline)
        if baseline_std < 1e-10:
            # No variation in baseline - check if current value differs
            if abs(feature_value - baseline_mean) < 1e-10:
                z_score = 0.0
            else:
                # Significant deviation but no baseline variance
                # Treat as maximum deviation
                z_score = float('inf') if feature_value > baseline_mean else float('-inf')
        else:
            z_score = (feature_value - baseline_mean) / baseline_std

        # Only explain features that deviate significantly
        if abs(z_score) >= threshold:
            direction = "above" if z_score > 0 else "below"

            # Format the explanation with context
            explanation = _format_feature_explanation(
                name, feature_value, z_score, direction, baseline_mean
            )

            explanations.append(explanation)
            deviations.append(abs(z_score))

    # Sort by deviation magnitude (most anomalous first)
    if explanations:
        sorted_pairs = sorted(zip(deviations, explanations), reverse=True)
        explanations = [exp for _, exp in sorted_pairs]

    return explanations


def _format_feature_explanation(
    feature_name: str,
    value: float,
    z_score: float,
    direction: str,
    baseline_mean: float
) -> str:
    """Format a single feature explanation with context.

    Args:
        feature_name: Name of the feature.
        value: Current value of the feature.
        z_score: Z-score (standard deviations from baseline).
        direction: "above" or "below".
        baseline_mean: Baseline mean value for comparison.

    Returns:
        Formatted explanation string with context.
    """
    # Special handling for infinite z-scores
    if abs(z_score) == float('inf'):
        z_str = ">>2.0σ"
    else:
        z_str = f"{abs(z_score):.1f}σ"

    # Add context based on feature type
    context = _get_feature_context(feature_name, value, direction)

    # Build explanation
    explanation = f"{feature_name}: {value:.2f} ({z_str} {direction} baseline of {baseline_mean:.2f})"

    if context:
        explanation += f" - {context}"

    return explanation


def _get_feature_context(feature_name: str, value: float, direction: str) -> Optional[str]:
    """Get contextual information about what a feature deviation means.

    Args:
        feature_name: Name of the feature.
        value: Current value of the feature.
        direction: "above" or "below".

    Returns:
        Contextual explanation or None.
    """
    contexts = {
        'attempts_per_hour': {
            'above': 'High attack rate',
            'below': 'Unusually low activity'
        },
        'unique_usernames': {
            'above': 'Username enumeration suspected',
            'below': 'Targeted attack on specific users'
        },
        'failure_ratio': {
            'above': 'Most attempts failed - likely attack',
            'below': 'Unusual success rate'
        },
        'max_failure_streak': {
            'above': 'Long failure sequences - brute force pattern',
            'below': None
        },
        'has_success_after_failures': {
            'above': 'Successful breach after failures',
            'below': None
        },
        'same_target_ips_5min': {
            'above': 'Coordinated attack with other IPs',
            'below': None
        },
        'username_entropy': {
            'above': 'Random username generation - bot activity',
            'below': 'Targeted usernames'
        },
        'hour_of_day_mean': {
            'above': None,
            'below': None
        },
        'hour_of_day_std': {
            'above': 'Activity spread throughout day',
            'below': 'Concentrated in specific hours'
        },
    }

    if feature_name in contexts:
        return contexts[feature_name].get(direction)

    return None


def format_anomaly_summary(
    ip: str,
    score: float,
    explanations: list[str],
    max_explanations: int = 5
) -> str:
    """Format a complete anomaly summary for an IP.

    Args:
        ip: IP address.
        score: Anomaly score (0.0 to 1.0).
        explanations: List of explanation strings from explain_anomaly().
        max_explanations: Maximum number of explanations to include.

    Returns:
        Formatted summary string.
    """
    lines = [
        f"Anomalous IP: {ip}",
        f"Anomaly Score: {score:.3f}",
        "",
    ]

    if explanations:
        lines.append("Key Deviations:")
        for i, explanation in enumerate(explanations[:max_explanations], 1):
            lines.append(f"  {i}. {explanation}")

        if len(explanations) > max_explanations:
            lines.append(f"  ... and {len(explanations) - max_explanations} more")
    else:
        lines.append("No significant feature deviations found.")
        lines.append("Anomaly detected through ensemble decision.")

    return "\n".join(lines)
