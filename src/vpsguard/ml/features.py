"""Feature extraction for ML-based anomaly detection."""

import numpy as np
from dataclasses import dataclass
from collections import defaultdict
from datetime import timedelta
from typing import Optional
from vpsguard.models.events import AuthEvent


@dataclass
class FeatureSet:
    """Features extracted for one IP."""
    ip: str
    features: np.ndarray
    feature_names: list[str]


class FeatureExtractor:
    """Extract ML features from auth events."""

    FEATURE_NAMES = [
        "attempts_per_hour",
        "unique_usernames",
        "failure_ratio",
        "hour_of_day_mean",
        "hour_of_day_std",
        "max_failure_streak",
        "has_success_after_failures",
        "same_target_ips_5min",
        "username_entropy",
    ]

    def extract(self, events: list[AuthEvent]) -> list[FeatureSet]:
        """Extract features grouped by IP.

        Args:
            events: List of authentication events to extract features from.

        Returns:
            List of FeatureSet objects, one per IP address.
        """
        if not events:
            return []

        # Group events by IP
        events_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.ip:
                events_by_ip[event.ip].append(event)

        # Extract features for each IP
        feature_sets = []
        for ip, ip_events in events_by_ip.items():
            features = self._extract_for_ip(ip, ip_events, events)
            feature_sets.append(FeatureSet(
                ip=ip,
                features=features,
                feature_names=self.FEATURE_NAMES.copy()
            ))

        return feature_sets

    def extract_array(self, events: list[AuthEvent]) -> tuple[np.ndarray, list[str]]:
        """Extract features as numpy array with IP list.

        Args:
            events: List of authentication events to extract features from.

        Returns:
            Tuple of (features array, list of IP addresses).
            Features array shape: (n_ips, n_features)
        """
        feature_sets = self.extract(events)

        if not feature_sets:
            return np.array([]), []

        features_array = np.vstack([fs.features for fs in feature_sets])
        ips = [fs.ip for fs in feature_sets]

        return features_array, ips

    def _extract_for_ip(self, ip: str, ip_events: list[AuthEvent], all_events: list[AuthEvent]) -> np.ndarray:
        """Extract features for a single IP.

        Args:
            ip: IP address to extract features for.
            ip_events: Events from this IP.
            all_events: All events (needed for clustering features).

        Returns:
            Numpy array of features.
        """
        # Sort events by timestamp
        ip_events = sorted(ip_events, key=lambda e: e.timestamp)

        # Feature 1: Attempts per hour
        if len(ip_events) > 1:
            time_span = (ip_events[-1].timestamp - ip_events[0].timestamp).total_seconds() / 3600
            attempts_per_hour = len(ip_events) / max(time_span, 0.01)  # Avoid division by zero
        else:
            attempts_per_hour = len(ip_events)

        # Feature 2: Unique usernames
        unique_usernames = len(set(e.username for e in ip_events if e.username))

        # Feature 3: Failure ratio
        failures = sum(1 for e in ip_events if not e.success)
        failure_ratio = failures / len(ip_events) if ip_events else 0.0

        # Feature 4 & 5: Hour of day statistics
        hours = [e.timestamp.hour for e in ip_events]
        hour_of_day_mean = np.mean(hours) if hours else 0.0
        hour_of_day_std = np.std(hours) if len(hours) > 1 else 0.0

        # Feature 6: Max failure streak
        max_failure_streak = self._calculate_max_failure_streak(ip_events)

        # Feature 7: Has success after failures (breach indicator)
        has_success_after_failures = 1.0 if self._has_success_after_failures(ip_events) else 0.0

        # Feature 8: Same target IPs within 5 minutes (clustering/coordination detection)
        same_target_ips_5min = self._calculate_clustering_score(ip, ip_events, all_events)

        # Feature 9: Username entropy (enumeration detection)
        username_entropy = self._calculate_username_entropy(ip_events)

        return np.array([
            attempts_per_hour,
            unique_usernames,
            failure_ratio,
            hour_of_day_mean,
            hour_of_day_std,
            max_failure_streak,
            has_success_after_failures,
            same_target_ips_5min,
            username_entropy,
        ], dtype=np.float64)

    def _calculate_max_failure_streak(self, events: list[AuthEvent]) -> float:
        """Calculate the longest consecutive failure streak.

        Args:
            events: Sorted list of events for one IP.

        Returns:
            Maximum number of consecutive failures.
        """
        max_streak = 0
        current_streak = 0

        for event in events:
            if not event.success:
                current_streak += 1
                max_streak = max(max_streak, current_streak)
            else:
                current_streak = 0

        return float(max_streak)

    def _has_success_after_failures(self, events: list[AuthEvent]) -> bool:
        """Check if there's a successful login after failures.

        This is a strong indicator of a breach (successful brute force).

        Args:
            events: Sorted list of events for one IP.

        Returns:
            True if there's a success after at least one failure.
        """
        had_failure = False

        for event in events:
            if not event.success:
                had_failure = True
            elif had_failure and event.success:
                return True

        return False

    def _calculate_clustering_score(self, ip: str, ip_events: list[AuthEvent], all_events: list[AuthEvent]) -> float:
        """Calculate how many other IPs targeted the same usernames within 5 minutes.

        This detects coordinated botnet attacks where multiple IPs attack
        the same targets simultaneously.

        Args:
            ip: Current IP address.
            ip_events: Events from this IP.
            all_events: All events from all IPs.

        Returns:
            Average number of other IPs attacking same targets within 5 minutes.
        """
        # Get usernames targeted by this IP
        targeted_usernames = set(e.username for e in ip_events if e.username)

        if not targeted_usernames:
            return 0.0

        # For each username, count other IPs that targeted it within 5 minutes
        clustering_scores = []

        for username in targeted_usernames:
            # Get timestamps when this IP targeted this username
            our_timestamps = [e.timestamp for e in ip_events if e.username == username]

            if not our_timestamps:
                continue

            # Count unique IPs that targeted same username within 5 minutes
            other_ips = set()
            for event in all_events:
                if event.ip == ip or event.username != username:
                    continue

                # Check if any of our attempts are within 5 minutes
                for our_ts in our_timestamps:
                    time_diff = abs((event.timestamp - our_ts).total_seconds())
                    if time_diff <= 300:  # 5 minutes
                        other_ips.add(event.ip)
                        break

            clustering_scores.append(len(other_ips))

        return np.mean(clustering_scores) if clustering_scores else 0.0

    def _calculate_username_entropy(self, events: list[AuthEvent]) -> float:
        """Calculate entropy of usernames (randomness).

        High entropy indicates username enumeration attacks (random strings).
        Low entropy indicates targeted attacks (specific users).

        Args:
            events: List of events for one IP.

        Returns:
            Shannon entropy of usernames.
        """
        usernames = [e.username for e in events if e.username]

        if not usernames:
            return 0.0

        # Calculate character-level entropy
        # Concatenate all usernames
        all_chars = ''.join(usernames)

        if not all_chars:
            return 0.0

        # Count character frequencies
        char_counts = defaultdict(int)
        for char in all_chars:
            char_counts[char] += 1

        # Calculate Shannon entropy
        total_chars = len(all_chars)
        entropy = 0.0

        for count in char_counts.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * np.log2(probability)

        return entropy
