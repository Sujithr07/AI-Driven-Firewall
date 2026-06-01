"""
LSTM-based sequential anomaly detector for network traffic.

Analyses sliding windows of recent packet features to detect temporal
attack patterns that single-packet classifiers miss (e.g. port scans,
slow-rate DDoS, lateral movement).
"""

import os
import collections
import pickle
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from app.core.config import MODELS_DIR

FEATURE_DIM = 11


if TORCH_AVAILABLE:
    class _LSTMNet(nn.Module):
        def __init__(self, input_dim=FEATURE_DIM, hidden_dim=64, num_layers=2, dropout=0.2):
            super().__init__()
            self.lstm = nn.LSTM(input_size=input_dim, hidden_size=hidden_dim,
                                num_layers=num_layers, batch_first=True,
                                dropout=dropout if num_layers > 1 else 0.0)
            self.fc = nn.Sequential(nn.Linear(hidden_dim, 32), nn.ReLU(),
                                     nn.Linear(32, 1), nn.Sigmoid())

        def forward(self, x):
            lstm_out, _ = self.lstm(x)
            last_hidden = lstm_out[:, -1, :]
            return self.fc(last_hidden)


class LSTMDetector:
    """Sliding-window LSTM anomaly detector."""

    @property
    def MODEL_PATH(self):
        return os.path.join(MODELS_DIR, "lstm_model.pt")

    def __init__(self, window_size=20, threshold=0.5, lr=1e-3):
        self.window_size = window_size
        self.threshold = threshold
        self._window = collections.deque(maxlen=window_size)
        self._train_buffer = collections.deque(maxlen=5000)
        self._min_train = 50
        self._retrain_every = 100
        self._samples_since_train = 0
        if TORCH_AVAILABLE:
            self.model = _LSTMNet()
            self._optimizer = optim.Adam(self.model.parameters(), lr=lr)
            self._loss_fn = nn.BCELoss()
            self._load()
        else:
            self.model = None

    def add_packet(self, numeric_features, label=None):
        vec = np.asarray(numeric_features, dtype=np.float32).flatten()
        self._window.append(vec)
        if label is not None and len(self._window) == self.window_size:
            window_arr = np.array(self._window, dtype=np.float32)
            self._train_buffer.append((window_arr, float(label)))
            self._samples_since_train += 1
            if self._samples_since_train >= self._retrain_every and len(self._train_buffer) >= self._min_train:
                self._train()

    def predict_current(self):
        if self.model is None or len(self._window) < self.window_size:
            return False, 0.0
        window_arr = np.array(self._window, dtype=np.float32)
        x = torch.tensor(window_arr).unsqueeze(0)
        self.model.eval()
        with torch.no_grad():
            score = float(self.model(x).item())
        return score >= self.threshold, round(score, 4)

    def save(self):
        if not TORCH_AVAILABLE:
            return
        try:
            os.makedirs(MODELS_DIR, exist_ok=True)
            torch.save({"state_dict": self.model.state_dict(),
                        "window_size": self.window_size,
                        "threshold": self.threshold}, self.MODEL_PATH)
        except Exception:
            pass

    def _train(self, epochs=3):
        if not TORCH_AVAILABLE or len(self._train_buffer) < self._min_train:
            return
        buf = list(self._train_buffer)
        X = np.array([b[0] for b in buf], dtype=np.float32)
        y = np.array([b[1] for b in buf], dtype=np.float32).reshape(-1, 1)
        X_t = torch.tensor(X); y_t = torch.tensor(y)
        self.model.train()
        batch_size = min(64, len(buf))
        for _ in range(epochs):
            indices = torch.randperm(len(buf))
            for start in range(0, len(buf), batch_size):
                idx = indices[start:start + batch_size]
                pred = self.model(X_t[idx])
                loss = self._loss_fn(pred, y_t[idx])
                self._optimizer.zero_grad(); loss.backward(); self._optimizer.step()
        self._samples_since_train = 0

    def _load(self):
        if not TORCH_AVAILABLE:
            return
        model_path = self.MODEL_PATH
        if os.path.exists(model_path):
            try:
                ckpt = torch.load(model_path, map_location="cpu", weights_only=True)
                self.model.load_state_dict(ckpt["state_dict"])
                self.window_size = ckpt.get("window_size", self.window_size)
                self.threshold = ckpt.get("threshold", self.threshold)
                print(f"[LSTMDetector] Loaded model from {model_path}")
            except Exception as e:
                print(f"[LSTMDetector] Could not load model: {e}")
