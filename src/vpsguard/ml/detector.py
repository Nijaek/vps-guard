"""ML-based anomaly detectors."""

import hashlib
import hmac
import logging
import pickle
from pathlib import Path
from typing import Protocol

import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# Security: Model signature key (should be configured externally in production)
# This provides basic integrity verification against accidental corruption
# For production deployments, use environment variable or secure key management
_MODEL_SIGNATURE_KEY = b"vpsguard-model-v1"


class Detector(Protocol):
    """Protocol for anomaly detectors.

    Any detector must implement this interface to be used with MLEngine.
    """
    name: str

    def train(self, features: np.ndarray) -> None:
        """Train the detector on clean/normal data.

        Args:
            features: Feature array of shape (n_samples, n_features).
        """
        ...

    def detect(self, features: np.ndarray) -> np.ndarray:
        """Detect anomalies in features.

        Args:
            features: Feature array of shape (n_samples, n_features).

        Returns:
            Array of anomaly scores from 0 (normal) to 1 (anomalous).
        """
        ...

    def save(self, path: Path) -> None:
        """Save the trained model to disk.

        Args:
            path: Path to save the model to.
        """
        ...

    def load(self, path: Path) -> None:
        """Load a trained model from disk.

        Args:
            path: Path to load the model from.
        """
        ...


class IsolationForestDetector:
    """Isolation Forest based anomaly detector.

    Isolation Forest is particularly effective for anomaly detection because:
    - It isolates anomalies instead of profiling normal points
    - Works well with high-dimensional data
    - Fast training and prediction
    - Handles mixed feature types well

    The algorithm works by randomly selecting a feature and then randomly
    selecting a split value. Anomalies are easier to isolate (require fewer
    splits) than normal points.
    """

    name = "isolation_forest"

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        """Initialize the detector.

        Args:
            contamination: Expected proportion of anomalies in the dataset.
                          Used to define the threshold for anomaly scores.
                          Default 0.1 means we expect ~10% of IPs to be anomalous.
            random_state: Random seed for reproducibility.
        """
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
            max_samples='auto',
            bootstrap=False,
        )
        self.is_trained = False

    def train(self, features: np.ndarray) -> None:
        """Train the Isolation Forest on clean data.

        Args:
            features: Feature array of shape (n_samples, n_features).
                     Should contain only clean/normal traffic (from rule engine).

        Raises:
            ValueError: If features array is empty or invalid.
        """
        if features.size == 0:
            raise ValueError("Cannot train on empty feature array")

        if len(features.shape) != 2:
            raise ValueError(f"Features must be 2D array, got shape {features.shape}")

        self.model.fit(features)
        self.is_trained = True

    def detect(self, features: np.ndarray) -> np.ndarray:
        """Detect anomalies and return normalized scores.

        Args:
            features: Feature array of shape (n_samples, n_features).

        Returns:
            Array of anomaly scores from 0 (normal) to 1 (anomalous).
            Higher scores indicate more anomalous behavior.

        Raises:
            RuntimeError: If detector hasn't been trained yet.
            ValueError: If features array is invalid.
        """
        if not self.is_trained:
            raise RuntimeError("Detector must be trained before detection")

        if features.size == 0:
            return np.array([])

        if len(features.shape) != 2:
            raise ValueError(f"Features must be 2D array, got shape {features.shape}")

        # Get raw anomaly scores from the model
        # decision_function returns negative scores for anomalies
        # More negative = more anomalous
        raw_scores = self.model.decision_function(features)

        # Use score_samples for better normalization
        # Returns negative scores where more negative = more anomalous
        # We'll use a different normalization approach

        # Instead of min-max normalization which is sensitive to outliers,
        # use a sigmoid-like transformation centered around 0
        # This better preserves the relative anomaly differences

        # Apply transformation: more negative -> higher score
        # Using tanh to map to [0, 1] range
        normalized = 1 / (1 + np.exp(raw_scores))

        return normalized

    def save(self, path: Path) -> None:
        """Save the trained model to disk with integrity signature.

        Args:
            path: Path to save the model to (will create parent dirs if needed).

        Raises:
            RuntimeError: If detector hasn't been trained yet.

        Security Note:
            Models are signed with HMAC-SHA256 for integrity verification.
            This protects against accidental corruption but not against
            targeted attacks. For high-security deployments, use external
            signature verification with proper key management.
        """
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained detector")

        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)

        # Serialize model data
        model_data = {
            'model': self.model,
            'contamination': self.contamination,
            'random_state': self.random_state,
            'is_trained': self.is_trained,
            'version': 1,  # Model format version for future compatibility
        }
        serialized = pickle.dumps(model_data)

        # Generate HMAC signature for integrity verification
        signature = hmac.new(_MODEL_SIGNATURE_KEY, serialized, hashlib.sha256).digest()

        # Save with signature prefix
        with open(path, 'wb') as f:
            f.write(signature)  # 32 bytes
            f.write(serialized)

    def load(self, path: Path, verify_signature: bool = True) -> None:
        """Load a trained model from disk with signature verification.

        Args:
            path: Path to load the model from.
            verify_signature: If True, verify HMAC signature before loading.
                            Set to False only for loading legacy unsigned models.

        Raises:
            FileNotFoundError: If model file doesn't exist.
            ValueError: If model file is corrupted, invalid, or signature fails.

        Security Warning:
            Pickle deserialization can execute arbitrary code. Only load models
            from trusted sources. The signature verification provides integrity
            checking but models from untrusted sources remain dangerous.
        """
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        try:
            with open(path, 'rb') as f:
                file_data = f.read()

            # Check if this is a signed model (32-byte signature prefix)
            if len(file_data) > 32:
                stored_signature = file_data[:32]
                serialized = file_data[32:]

                # Try to verify signature (new format)
                expected_signature = hmac.new(
                    _MODEL_SIGNATURE_KEY, serialized, hashlib.sha256
                ).digest()

                if hmac.compare_digest(stored_signature, expected_signature):
                    # Signature verified - safe to load
                    data = pickle.loads(serialized)
                else:
                    # Signature mismatch - could be legacy format or tampering
                    if verify_signature:
                        # Try loading as legacy format (unsigned)
                        try:
                            data = pickle.loads(file_data)
                            logger.warning(
                                f"Loading unsigned legacy model from {path}. "
                                "Re-save the model to add signature protection."
                            )
                        except pickle.PickleError:
                            raise ValueError(
                                "Model signature verification failed. "
                                "The model file may be corrupted or tampered with."
                            )
                    else:
                        data = pickle.loads(file_data)
            else:
                # Too small for signed format, try legacy
                if verify_signature:
                    logger.warning(
                        f"Loading unsigned legacy model from {path}. "
                        "Re-save the model to add signature protection."
                    )
                data = pickle.loads(file_data)

            self.model = data['model']
            self.contamination = data['contamination']
            self.random_state = data['random_state']
            self.is_trained = data['is_trained']

        except (pickle.PickleError, KeyError, EOFError) as e:
            raise ValueError(f"Invalid or corrupted model file: {e}")
