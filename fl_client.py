"""
Federated Learning Client
=========================
Wraps the existing TrafficClassifier to participate in federated learning.
Periodically sends differentially private weight updates to the FL server
and applies global model updates back to the local classifier.
"""

import threading
import time
import math
import logging
import numpy as np
import requests
from datetime import datetime

logger = logging.getLogger(__name__)


class FLClient:
    """
    Federated Learning client that extracts local model weights,
    applies differential privacy noise, and communicates with a
    central FL server for FedAvg aggregation.
    """

    def __init__(self, client_id, server_url="http://localhost:6000",
                 dp_enabled=True, epsilon=1.0, dp_delta=1e-5, clip_norm=1.0,
                 sync_interval=60, min_samples=10):
        self.client_id = client_id
        self.server_url = server_url.rstrip("/")
        self.dp_enabled = dp_enabled
        self.epsilon = epsilon
        self.dp_delta = dp_delta
        self.clip_norm = clip_norm
        self.sync_interval = sync_interval
        self.min_samples = min_samples

        self._classifier = None
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

        self.rounds_participated = 0
        self.last_round_time = None
        self.global_model_version = 0
        self._last_global_weights = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, classifier):
        """Begin background FL sync loop."""
        self._classifier = classifier
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._thread.start()
        logger.info("[FLClient] Started (server=%s, interval=%ds)", self.server_url, self.sync_interval)

    def stop(self):
        """Stop the background sync loop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("[FLClient] Stopped")

    def get_status(self):
        """Return current FL client status dict."""
        n_samples = self._local_sample_count()
        return {
            "client_id": self.client_id,
            "server_url": self.server_url,
            "rounds_participated": self.rounds_participated,
            "last_round_time": self.last_round_time,
            "global_model_version": self.global_model_version,
            "dp_enabled": self.dp_enabled,
            "local_samples": n_samples,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _local_sample_count(self):
        """Get the number of local training samples."""
        if self._classifier is None:
            return 0
        # EnsemblePredictor wraps .rf (TrafficClassifier)
        clf = getattr(self._classifier, "rf", self._classifier)
        return len(getattr(clf, "y_buffer", []))

    def _extract_weights(self):
        """
        Extract a serialisable weight dictionary from the local RF model.
        Uses feature importances and class priors as the weight representation.
        """
        clf = getattr(self._classifier, "rf", self._classifier)
        model = getattr(clf, "model", None)
        if model is None:
            return None

        importances = model.feature_importances_.tolist()
        # Class priors: fraction of each class in training data
        y = np.array(getattr(clf, "y_buffer", []))
        if len(y) == 0:
            return None
        classes = sorted(set(int(v) for v in y))
        priors = {str(c): float((y == c).mean()) for c in classes}

        return {
            "feature_importances": importances,
            "class_priors": priors,
        }

    def _compute_delta(self, current_weights):
        """Compute the delta between current weights and last known global weights."""
        if self._last_global_weights is None:
            return current_weights

        delta = {}
        for key in current_weights:
            cur = current_weights[key]
            prev = self._last_global_weights.get(key)
            if isinstance(cur, list) and isinstance(prev, list):
                delta[key] = [c - p for c, p in zip(cur, prev)]
            elif isinstance(cur, dict) and isinstance(prev, dict):
                delta[key] = {k: cur.get(k, 0) - prev.get(k, 0) for k in set(list(cur.keys()) + list(prev.keys()))}
            else:
                delta[key] = cur
        return delta

    def _clip_and_noise(self, delta):
        """Apply gradient clipping and Gaussian DP noise."""
        if not self.dp_enabled:
            return delta

        noised = {}
        for key, val in delta.items():
            if isinstance(val, list):
                arr = np.array(val, dtype=np.float64)
                # L2 clip
                norm = np.linalg.norm(arr)
                if norm > self.clip_norm:
                    arr = arr * (self.clip_norm / norm)
                # Gaussian mechanism: sigma = clip_norm * sqrt(2 * ln(1.25/delta)) / epsilon
                sigma = self.clip_norm * math.sqrt(2.0 * math.log(1.25 / self.dp_delta)) / self.epsilon
                arr += np.random.normal(0, sigma, size=arr.shape)
                noised[key] = arr.tolist()
            elif isinstance(val, dict):
                vals = np.array(list(val.values()), dtype=np.float64)
                norm = np.linalg.norm(vals)
                if norm > self.clip_norm:
                    vals = vals * (self.clip_norm / norm)
                sigma = self.clip_norm * math.sqrt(2.0 * math.log(1.25 / self.dp_delta)) / self.epsilon
                vals += np.random.normal(0, sigma, size=vals.shape)
                noised[key] = {k: float(v) for k, v in zip(val.keys(), vals)}
            else:
                noised[key] = val
        return noised

    def _submit_update(self, update, n_samples):
        """POST the weight update to the FL server."""
        payload = {
            "client_id": self.client_id,
            "update": update,
            "n_samples": n_samples,
            "timestamp": datetime.utcnow().isoformat(),
        }
        resp = requests.post(
            f"{self.server_url}/fl/submit_update",
            json=payload,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    def _fetch_global_model(self):
        """GET the aggregated global model from the FL server."""
        resp = requests.get(
            f"{self.server_url}/fl/global_model",
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    def _apply_global_model(self, global_weights):
        """
        Apply global model via FedAvg-style weight blending.

        Instead of injecting random noise, we:
        1. Sample a small number of anchor examples from the *local* buffer,
           weighted by the global feature importances so high-importance
           features are better represented.
        2. Retrain the local model on the augmented buffer.
        """
        clf = getattr(self._classifier, "rf", self._classifier)

        importances = global_weights.get("feature_importances")
        priors = global_weights.get("class_priors", {})
        if importances is None:
            return

        importances = np.array(importances, dtype=np.float64)
        X_buf = getattr(clf, "X_buffer", [])
        y_buf = getattr(clf, "y_buffer", [])
        if len(X_buf) < 2:
            return

        X_arr = np.array(X_buf, dtype=np.float64)
        y_arr = np.array(y_buf)

        # Build per-sample weight proportional to global feature importances
        imp_safe = importances / (importances.sum() + 1e-12)
        sample_weights = X_arr @ imp_safe  # dot product gives importance-weighted score
        sample_weights = np.abs(sample_weights)
        sample_weights = sample_weights / (sample_weights.sum() + 1e-12)

        # Draw 8 anchor samples from the local buffer weighted by global importances
        n_anchors = min(8, len(X_buf))
        rng = np.random.RandomState(42)
        indices = rng.choice(len(X_buf), size=n_anchors, replace=True, p=sample_weights)

        for idx in indices:
            clf.add_sample(np.array(X_buf[idx]).reshape(1, -1), int(y_buf[idx]))

        # Force retrain with the augmented buffer
        clf._train()

        n_estimators = 0
        model = getattr(clf, "model", None)
        if model is not None:
            n_estimators = getattr(model, "n_estimators", 0)
        logger.info(
            "[FLClient] Applied global model: blended global weights into local "
            "model using FedAvg (n=%d estimators)", n_estimators,
        )

    # ------------------------------------------------------------------
    # Background sync loop
    # ------------------------------------------------------------------

    def _sync_loop(self):
        """Background thread that periodically syncs with the FL server."""
        while self._running:
            try:
                time.sleep(self.sync_interval)
                if not self._running:
                    break
                self._do_round()
            except Exception as e:
                logger.warning("[FLClient] Sync error: %s", e)

    def _do_round(self):
        """Execute one FL round: extract -> delta -> noise -> submit -> fetch -> apply."""
        n_samples = self._local_sample_count()
        if n_samples < self.min_samples:
            logger.debug("[FLClient] Skipping round: only %d samples (need %d)", n_samples, self.min_samples)
            return

        weights = self._extract_weights()
        if weights is None:
            return

        delta = self._compute_delta(weights)
        noised_delta = self._clip_and_noise(delta)

        try:
            self._submit_update(noised_delta, n_samples)
        except Exception as e:
            logger.warning("[FLClient] Failed to submit update: %s", e)
            return

        try:
            global_model = self._fetch_global_model()
            if global_model and global_model.get("weights"):
                self._apply_global_model(global_model["weights"])
                self._last_global_weights = global_model["weights"]
                self.global_model_version = global_model.get("version", 0)
        except Exception as e:
            logger.warning("[FLClient] Failed to fetch global model: %s", e)

        self.rounds_participated += 1
        self.last_round_time = datetime.utcnow().isoformat()
        logger.info("[FLClient] Completed round %d (samples=%d)", self.rounds_participated, n_samples)
