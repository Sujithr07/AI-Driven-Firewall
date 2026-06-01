"""IsolationForest-based unsupervised anomaly detector for network traffic."""

import os
import pickle
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    ISOLATION_FOREST_AVAILABLE = True
except ImportError:
    ISOLATION_FOREST_AVAILABLE = False

from app.core.config import MODELS_DIR


class AnomalyDetector:
    """IsolationForest anomaly detector for network traffic."""

    @property
    def MODEL_PATH(self):
        return os.path.join(MODELS_DIR, "isolation_forest_model.pkl")

    def __init__(self, contamination=0.1, n_estimators=100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model = None
        self._buffer = []
        self._min_samples = 50
        self._retrain_every = 200
        self._samples_since_train = 0
        self._load()

    def predict(self, numeric_features):
        if self.model is None:
            return False, 0.0
        label = self.model.predict(numeric_features)[0]
        score = float(self.model.decision_function(numeric_features)[0])
        return label == -1, score

    def add_sample(self, numeric_features):
        self._buffer.append(numeric_features.flatten().tolist())
        max_buf = 5000
        if len(self._buffer) > max_buf:
            self._buffer = self._buffer[-max_buf:]
        self._samples_since_train += 1
        if self.model is None and len(self._buffer) >= self._min_samples:
            self._fit()
        elif self.model is not None and self._samples_since_train >= self._retrain_every:
            self._fit()

    def save(self):
        try:
            os.makedirs(MODELS_DIR, exist_ok=True)
            with open(self.MODEL_PATH, "wb") as f:
                pickle.dump({"model": self.model, "buffer": self._buffer[-2000:]}, f)
        except Exception:
            pass

    def _fit(self):
        if not ISOLATION_FOREST_AVAILABLE or len(self._buffer) < self._min_samples:
            return
        X = np.array(self._buffer, dtype=np.float64)
        self.model = IsolationForest(n_estimators=self.n_estimators,
                                      contamination=self.contamination,
                                      random_state=42, n_jobs=-1)
        self.model.fit(X)
        self._samples_since_train = 0

    def _load(self):
        model_path = self.MODEL_PATH
        if os.path.exists(model_path):
            try:
                with open(model_path, "rb") as f:
                    saved = pickle.load(f)
                if isinstance(saved, dict):
                    self.model = saved.get("model")
                    self._buffer = saved.get("buffer", [])
                else:
                    self.model = saved
            except Exception:
                pass
