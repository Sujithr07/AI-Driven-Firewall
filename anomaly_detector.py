"""
anomaly_detector.py
===================
IsolationForest-based unsupervised anomaly detector that can be used
alongside the RandomForest classifier for network traffic analysis.

The detector is trained on the same 11-dimensional feature vector used by
TrafficClassifier in detection_agent.py.  Because IsolationForest is
unsupervised, it needs no labels — it learns the shape of "normal" traffic
and flags statistical outliers.

Usage (standalone):
    from anomaly_detector import AnomalyDetector
    detector = AnomalyDetector()
    is_anomaly, score = detector.predict(numeric_features)  # numpy (1, 11)

Integration with DetectionAgent:
    The DetectionAgent can instantiate an AnomalyDetector and combine its
    anomaly score with the RF prediction for richer decision-making.
"""

import os
import pickle
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    ISOLATION_FOREST_AVAILABLE = True
except ImportError:
    ISOLATION_FOREST_AVAILABLE = False


class AnomalyDetector:
    """
    IsolationForest anomaly detector for network traffic.

    - contamination: expected fraction of anomalies in training data.
    - n_estimators: number of trees in the forest.
    - Persists the fitted model to disk so it survives restarts.
    """

    MODEL_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "isolation_forest_model.pkl"
    )

    def __init__(self, contamination=0.1, n_estimators=100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model = None
        self._buffer = []          # collect samples for initial fit
        self._min_samples = 50     # minimum samples before first fit
        self._retrain_every = 200  # retrain after this many new samples
        self._samples_since_train = 0
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict(self, numeric_features):
        """
        Predict whether a sample is anomalous.

        Parameters
        ----------
        numeric_features : np.ndarray, shape (1, 11)

        Returns
        -------
        (is_anomaly: bool, anomaly_score: float)
            anomaly_score ∈ [-1, 1].  More negative ⇒ more anomalous.
        """
        if self.model is None:
            # Model not ready — treat everything as normal
            return False, 0.0

        label = self.model.predict(numeric_features)[0]   # 1 = normal, -1 = anomaly
        score = float(self.model.decision_function(numeric_features)[0])
        return label == -1, score

    def add_sample(self, numeric_features):
        """
        Feed a new observed sample.  The detector will periodically
        retrain itself so that its notion of "normal" stays current.
        """
        self._buffer.append(numeric_features.flatten().tolist())

        # Keep buffer bounded
        max_buf = 5000
        if len(self._buffer) > max_buf:
            self._buffer = self._buffer[-max_buf:]

        self._samples_since_train += 1

        if self.model is None and len(self._buffer) >= self._min_samples:
            self._fit()
        elif self.model is not None and self._samples_since_train >= self._retrain_every:
            self._fit()

    def save(self):
        """Persist model and buffer to disk."""
        try:
            with open(self.MODEL_PATH, "wb") as f:
                pickle.dump({
                    "model": self.model,
                    "buffer": self._buffer[-2000:],
                }, f)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _fit(self):
        """Fit / refit the IsolationForest on buffered data."""
        if not ISOLATION_FOREST_AVAILABLE or len(self._buffer) < self._min_samples:
            return

        X = np.array(self._buffer, dtype=np.float64)
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        self._samples_since_train = 0

    def _load(self):
        """Load a previously saved model from disk."""
        if os.path.exists(self.MODEL_PATH):
            try:
                with open(self.MODEL_PATH, "rb") as f:
                    saved = pickle.load(f)
                if isinstance(saved, dict):
                    self.model = saved.get("model")
                    self._buffer = saved.get("buffer", [])
                else:
                    self.model = saved
            except Exception:
                pass
