"""
Detection Agent Module
======================
Reinforcement Learning + RandomForest-based network intrusion detection agent.

Pipeline:
  1. Scapy sniffs packets from the network interface
  2. Features extracted: src IP, dst IP, protocol, port, TCP flags, packet size
  3. RandomForest Classifier gives initial prediction (attack / normal)
  4. RL Agent builds state tuple and uses epsilon-greedy Q-learning
  5. Action: "allow" or "block"
  6. Reward: +1 correct, -1 mistake
  7. Q-table updated, epsilon decays
"""

import threading
import time
import random
import json
import os
import pickle
import collections
import uuid
import numpy as np
from datetime import datetime

from fl_client import FLClient

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from sklearn.ensemble import RandomForestClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    from lstm_detector import LSTMDetector
    LSTM_AVAILABLE = True
except ImportError:
    LSTM_AVAILABLE = False


# ---------------------------------------------------------------------------
# Known malicious / suspicious IP ranges and ports (for labeling)
# ---------------------------------------------------------------------------

SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 12345, 65535, 8888, 9999}
WELL_KNOWN_PORTS = {80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 8080, 3306, 5432, 27017}

PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
]


def _ip_to_int(ip_str):
    """Convert dotted IP string to integer."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return 0
    try:
        return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
    except ValueError:
        return 0


def _is_private(ip_str):
    """Check if IP is in a private / reserved range."""
    ip_int = _ip_to_int(ip_str)
    for lo, hi in PRIVATE_RANGES:
        if _ip_to_int(lo) <= ip_int <= _ip_to_int(hi):
            return True
    return False


# ---------------------------------------------------------------------------
# Feature extraction from a Scapy packet
# ---------------------------------------------------------------------------

def extract_features(packet):
    """
    Extract numeric + categorical features from a raw Scapy packet.
    Returns (feature_dict, numeric_vector) or None if packet is not IP.
    """
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto_num = ip_layer.proto  # 6=TCP, 17=UDP, 1=ICMP
    pkt_size = len(packet)

    # Determine protocol name
    if packet.haslayer(TCP):
        protocol = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        flags = ""
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        sport = 0
        dport = 0
        flags = ""
    else:
        protocol = f"OTHER({proto_num})"
        sport = 0
        dport = 0
        flags = ""

    # Categorical features for RL state
    src_private = _is_private(src_ip)
    dst_private = _is_private(dst_ip)

    # IP type classification
    if not src_private and dst_private:
        ip_type = "external_to_internal"
    elif src_private and not dst_private:
        ip_type = "internal_to_external"
    elif src_private and dst_private:
        ip_type = "internal"
    else:
        ip_type = "external"

    # Port type classification
    if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
        port_type = "suspicious"
    elif dport in WELL_KNOWN_PORTS or sport in WELL_KNOWN_PORTS:
        port_type = "well_known"
    elif dport > 1024 or sport > 1024:
        port_type = "high"
    else:
        port_type = "low_unknown"

    # Flag-based risk marker
    has_syn = "S" in flags and "A" not in flags  # SYN without ACK = scan
    has_fin = "F" in flags
    has_rst = "R" in flags

    # Numeric feature vector for RandomForest:
    # [proto_num, sport, dport, pkt_size, is_src_private, is_dst_private,
    #  has_syn, has_fin, has_rst, port_is_suspicious, port_is_well_known]
    numeric = np.array([
        proto_num,
        sport,
        dport,
        pkt_size,
        int(src_private),
        int(dst_private),
        int(has_syn),
        int(has_fin),
        int(has_rst),
        int(dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS),
        int(dport in WELL_KNOWN_PORTS or sport in WELL_KNOWN_PORTS),
    ], dtype=np.float64).reshape(1, -1)

    feature_dict = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "sport": sport,
        "dport": dport,
        "size": pkt_size,
        "flags": flags,
        "ip_type": ip_type,
        "port_type": port_type,
        "has_syn": has_syn,
        "has_fin": has_fin,
        "has_rst": has_rst,
    }

    return feature_dict, numeric


# ---------------------------------------------------------------------------
# RandomForest Classifier (fast initial prediction)
# ---------------------------------------------------------------------------

class TrafficClassifier:
    """
    RandomForest classifier that provides fast initial attack/normal prediction.
    Self-trains on labeled samples collected during operation.
    """

    MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rf_model.pkl")

    def __init__(self):
        self.model = None
        self.X_buffer = []
        self.y_buffer = []
        self.min_samples = 20  # Minimum samples before training
        self._load_or_init()

    def _load_or_init(self):
        """Load a pre-trained model from disk, or fall back to synthetic baseline."""
        if os.path.exists(self.MODEL_PATH):
            try:
                with open(self.MODEL_PATH, "rb") as f:
                    saved = pickle.load(f)
                if isinstance(saved, dict):
                    self.model = saved["model"]
                    self.X_buffer = saved.get("X_buffer", [])
                    self.y_buffer = saved.get("y_buffer", [])
                else:
                    # Bare sklearn model (e.g. saved directly by train_model.py)
                    self.model = saved
                print(f"[TrafficClassifier] Loaded pre-trained model from {self.MODEL_PATH}")
                return
            except Exception as e:
                print(f"[TrafficClassifier] Failed to load model: {e}")

        # Bootstrap with synthetic training data so agent works from the start
        print("[TrafficClassifier] No pre-trained model found, generating synthetic baseline...")
        self._generate_synthetic_baseline()

    def _generate_synthetic_baseline(self):
        """Generate synthetic training data for initial model."""
        rng = random.Random(42)
        X, y = [], []

        for _ in range(200):
            # Normal traffic patterns
            proto = rng.choice([6, 17])  # TCP/UDP
            sport = rng.randint(1024, 65535)
            dport = rng.choice([80, 443, 53, 22, 8080, 3306])
            size = rng.randint(64, 1500)
            X.append([proto, sport, dport, size, 1, 0, 0, 0, 0, 0, 1])
            y.append(0)  # normal

        for _ in range(100):
            # Attack-like patterns
            proto = rng.choice([6, 17, 1])
            sport = rng.randint(1024, 65535)
            dport = rng.choice(list(SUSPICIOUS_PORTS) + [0, 445, 135, 139])
            size = rng.choice([0, 40, 60, rng.randint(5000, 65535)])
            has_syn = rng.choice([0, 1, 1])  # more SYN scans
            X.append([proto, sport, dport, size, 0, 1, has_syn, 0, 0, 1, 0])
            y.append(1)  # attack

        self.X_buffer = X
        self.y_buffer = y
        self._train()

    def _train(self):
        """Train / retrain the RandomForest on buffered data."""
        if not SKLEARN_AVAILABLE or len(self.X_buffer) < self.min_samples:
            return
        X = np.array(self.X_buffer)
        y = np.array(self.y_buffer)
        self.model = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
        self.model.fit(X, y)

    def predict(self, numeric_features):
        """
        Predict: 0 = normal, 1 = attack.
        Returns (prediction, confidence).
        """
        if self.model is None:
            # Heuristic fallback if model not ready
            dport = numeric_features[0, 2]
            is_susp = numeric_features[0, 9]
            if is_susp:
                return 1, 0.7
            return 0, 0.6

        pred = self.model.predict(numeric_features)[0]
        proba = self.model.predict_proba(numeric_features)[0]
        confidence = float(max(proba))
        return int(pred), confidence

    def add_sample(self, numeric_features, label):
        """Add a labeled sample and periodically retrain."""
        self.X_buffer.append(numeric_features.flatten().tolist())
        self.y_buffer.append(label)

        # Keep buffer bounded
        max_buffer = 5000
        if len(self.X_buffer) > max_buffer:
            self.X_buffer = self.X_buffer[-max_buffer:]
            self.y_buffer = self.y_buffer[-max_buffer:]

        # Retrain every 50 new samples
        if len(self.X_buffer) % 50 == 0:
            self._train()

    def save(self):
        """Persist model to disk."""
        try:
            with open(self.MODEL_PATH, "wb") as f:
                pickle.dump({
                    "model": self.model,
                    "X_buffer": self.X_buffer[-2000:],
                    "y_buffer": self.y_buffer[-2000:],
                }, f)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# XGBoost Classifier (ensemble partner for RandomForest)
# ---------------------------------------------------------------------------

class XGBoostClassifier:
    """
    Gradient-boosted tree classifier that runs alongside the RandomForest.
    Its prediction is averaged with the RF prediction for a more robust
    ensemble score.
    """

    MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xgb_model.pkl")

    def __init__(self):
        self.model = None
        self.X_buffer = []
        self.y_buffer = []
        self.min_samples = 30
        self._load_or_init()

    def _load_or_init(self):
        if os.path.exists(self.MODEL_PATH):
            try:
                with open(self.MODEL_PATH, "rb") as f:
                    saved = pickle.load(f)
                if isinstance(saved, dict):
                    self.model = saved["model"]
                    self.X_buffer = saved.get("X_buffer", [])
                    self.y_buffer = saved.get("y_buffer", [])
                else:
                    self.model = saved
                print(f"[XGBoostClassifier] Loaded model from {self.MODEL_PATH}")
                return
            except Exception as e:
                print(f"[XGBoostClassifier] Failed to load model: {e}")
        self._generate_synthetic_baseline()

    def _generate_synthetic_baseline(self):
        rng = random.Random(42)
        X, y = [], []
        for _ in range(200):
            proto = rng.choice([6, 17])
            sport = rng.randint(1024, 65535)
            dport = rng.choice([80, 443, 53, 22, 8080, 3306])
            size = rng.randint(64, 1500)
            X.append([proto, sport, dport, size, 1, 0, 0, 0, 0, 0, 1])
            y.append(0)
        for _ in range(100):
            proto = rng.choice([6, 17, 1])
            sport = rng.randint(1024, 65535)
            dport = rng.choice(list(SUSPICIOUS_PORTS) + [0, 445, 135, 139])
            size = rng.choice([0, 40, 60, rng.randint(5000, 65535)])
            has_syn = rng.choice([0, 1, 1])
            X.append([proto, sport, dport, size, 0, 1, has_syn, 0, 0, 1, 0])
            y.append(1)
        self.X_buffer = X
        self.y_buffer = y
        self._train()

    def _train(self):
        if not XGBOOST_AVAILABLE or len(self.X_buffer) < self.min_samples:
            return
        X = np.array(self.X_buffer)
        y = np.array(self.y_buffer)
        self.model = xgb.XGBClassifier(
            n_estimators=80,
            max_depth=8,
            learning_rate=0.1,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
            verbosity=0,
        )
        self.model.fit(X, y)

    def predict(self, numeric_features):
        """Returns (prediction, confidence)."""
        if self.model is None:
            return 0, 0.5
        pred = int(self.model.predict(numeric_features)[0])
        proba = self.model.predict_proba(numeric_features)[0]
        return pred, float(max(proba))

    def add_sample(self, numeric_features, label):
        self.X_buffer.append(numeric_features.flatten().tolist())
        self.y_buffer.append(label)
        max_buffer = 5000
        if len(self.X_buffer) > max_buffer:
            self.X_buffer = self.X_buffer[-max_buffer:]
            self.y_buffer = self.y_buffer[-max_buffer:]
        if len(self.X_buffer) % 50 == 0:
            self._train()

    def save(self):
        try:
            with open(self.MODEL_PATH, "wb") as f:
                pickle.dump({
                    "model": self.model,
                    "X_buffer": self.X_buffer[-2000:],
                    "y_buffer": self.y_buffer[-2000:],
                }, f)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Ensemble Predictor — combines RF + XGBoost
# ---------------------------------------------------------------------------

class EnsemblePredictor:
    """Averages predictions from RandomForest and XGBoost."""

    def __init__(self):
        self.rf = TrafficClassifier()
        self.xgb = XGBoostClassifier()

    def predict(self, numeric_features):
        rf_pred, rf_conf = self.rf.predict(numeric_features)
        xgb_pred, xgb_conf = self.xgb.predict(numeric_features)

        # Weighted average of predicted probabilities
        rf_attack_prob  = rf_conf  if rf_pred  == 1 else 1.0 - rf_conf
        xgb_attack_prob = xgb_conf if xgb_pred == 1 else 1.0 - xgb_conf

        avg_attack_prob = 0.5 * rf_attack_prob + 0.5 * xgb_attack_prob
        pred = 1 if avg_attack_prob >= 0.5 else 0
        confidence = avg_attack_prob if pred == 1 else 1.0 - avg_attack_prob
        return pred, round(confidence, 4)

    def add_sample(self, numeric_features, label):
        self.rf.add_sample(numeric_features, label)
        self.xgb.add_sample(numeric_features, label)

    def save(self):
        self.rf.save()
        self.xgb.save()


# ---------------------------------------------------------------------------
# DQN Agent — Deep Q-Network with experience replay
# ---------------------------------------------------------------------------

# State encoding maps for deterministic integer encoding
_REASON_MAP = {
    "syn_scan": 0, "suspicious_port": 1, "external_intrusion": 2,
    "rf_flagged": 3, "normal_service": 4, "internal_traffic": 5, "benign": 6,
}
_IP_TYPE_MAP = {
    "external_to_internal": 0, "internal_to_external": 1,
    "internal": 2, "external": 3,
}
_PROTO_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}
_PORT_TYPE_MAP = {"suspicious": 0, "well_known": 1, "high": 2, "low_unknown": 3}
_CONF_MAP = {"very_high": 0, "high": 1, "medium": 2, "low": 3}
_SIZE_MAP = {"tiny": 0, "small": 1, "normal": 2, "large": 3}
_FLAG_MAP = {"none": 0, "S": 1, "F": 2, "R": 3, "SF": 4, "SR": 5, "FR": 6, "SFR": 7}

STATE_DIM = 7   # length of encoded state vector
ACTION_DIM = 2  # allow=0, block=1


def _encode_state(state_tuple):
    """Convert a 7-token state tuple into a float32 numpy vector."""
    reason, ip_type, protocol, port_type, conf_lvl, size_cat, flag_sig = state_tuple
    vec = np.array([
        _REASON_MAP.get(reason, 6),
        _IP_TYPE_MAP.get(ip_type, 3),
        _PROTO_MAP.get(protocol, 2),
        _PORT_TYPE_MAP.get(port_type, 3),
        _CONF_MAP.get(conf_lvl, 3),
        _SIZE_MAP.get(size_cat, 2),
        _FLAG_MAP.get(flag_sig, 0),
    ], dtype=np.float32)
    return vec


if TORCH_AVAILABLE:
    class _QNetwork(nn.Module):
        """Small MLP that maps state -> Q-values for each action."""
        def __init__(self, state_dim=STATE_DIM, action_dim=ACTION_DIM, hidden=64):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(state_dim, hidden),
                nn.ReLU(),
                nn.Linear(hidden, hidden),
                nn.ReLU(),
                nn.Linear(hidden, action_dim),
            )

        def forward(self, x):
            return self.net(x)


class DQNAgent:
    """
    Deep Q-Network agent with experience replay.

    Falls back to simple Q-table logic when PyTorch is unavailable.
    """

    ACTIONS = ["allow", "block"]
    MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dqn_model.pt")
    Q_TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "q_table.json")

    def __init__(self, alpha=1e-3, gamma=0.9, epsilon=1.0,
                 epsilon_decay=0.995, epsilon_min=0.05,
                 replay_size=5000, batch_size=64):
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.batch_size = batch_size
        self.total_decisions = 0
        self.correct_decisions = 0
        self.episode_rewards = []

        # Experience replay buffer: list of (state, action_idx, reward, next_state)
        self._replay = collections.deque(maxlen=replay_size)

        if TORCH_AVAILABLE:
            self._policy_net = _QNetwork()
            self._target_net = _QNetwork()
            self._target_net.load_state_dict(self._policy_net.state_dict())
            self._optimizer = optim.Adam(self._policy_net.parameters(), lr=alpha)
            self._update_target_every = 200
            self._steps = 0
            self._load_torch()
        else:
            # Thin Q-table fallback
            self.q_table = {}
            self.alpha = 0.1
            self._load_qtable()

    # ----- action selection -----

    def choose_action(self, state_tuple):
        if random.random() < self.epsilon:
            action = random.choice(self.ACTIONS)
            return action, True

        if TORCH_AVAILABLE:
            state_t = torch.tensor(_encode_state(state_tuple)).unsqueeze(0)
            with torch.no_grad():
                q_vals = self._policy_net(state_t).squeeze(0)
            action_idx = int(q_vals.argmax().item())
        else:
            key = "|".join(str(s) for s in state_tuple)
            if key not in self.q_table:
                self.q_table[key] = {"allow": 0.0, "block": 0.0}
            q = self.q_table[key]
            action_idx = 1 if q["block"] > q["allow"] else (0 if q["allow"] > q["block"] else random.randint(0, 1))

        return self.ACTIONS[action_idx], False

    # ----- learning -----

    def update(self, state_tuple, action, reward, next_state_tuple=None):
        action_idx = self.ACTIONS.index(action)

        if TORCH_AVAILABLE:
            next_state = state_tuple if next_state_tuple is None else next_state_tuple
            self._replay.append((
                _encode_state(state_tuple),
                action_idx,
                reward,
                _encode_state(next_state),
            ))
            self._steps += 1
            if len(self._replay) >= self.batch_size:
                self._train_batch()
            if self._steps % self._update_target_every == 0:
                self._target_net.load_state_dict(self._policy_net.state_dict())
        else:
            key = "|".join(str(s) for s in state_tuple)
            if key not in self.q_table:
                self.q_table[key] = {"allow": 0.0, "block": 0.0}
            old = self.q_table[key][action]
            max_next = 0.0
            if next_state_tuple is not None:
                nk = "|".join(str(s) for s in next_state_tuple)
                if nk not in self.q_table:
                    self.q_table[nk] = {"allow": 0.0, "block": 0.0}
                max_next = max(self.q_table[nk].values())
            self.q_table[key][action] = old + self.alpha * (reward + self.gamma * max_next - old)

        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
        self.total_decisions += 1
        if reward > 0:
            self.correct_decisions += 1
        self.episode_rewards.append(reward)
        if len(self.episode_rewards) > 500:
            self.episode_rewards = self.episode_rewards[-500:]

    def _train_batch(self):
        batch = random.sample(self._replay, self.batch_size)
        states  = torch.tensor(np.array([b[0] for b in batch]))
        actions = torch.tensor([b[1] for b in batch], dtype=torch.long).unsqueeze(1)
        rewards = torch.tensor([b[2] for b in batch], dtype=torch.float32).unsqueeze(1)
        next_s  = torch.tensor(np.array([b[3] for b in batch]))

        q_values = self._policy_net(states).gather(1, actions)
        with torch.no_grad():
            max_next_q = self._target_net(next_s).max(1, keepdim=True)[0]
        target = rewards + self.gamma * max_next_q

        loss = nn.functional.mse_loss(q_values, target)
        self._optimizer.zero_grad()
        loss.backward()
        self._optimizer.step()

    # ----- stats (same interface as old RLAgent) -----

    def get_stats(self):
        accuracy = (self.correct_decisions / self.total_decisions * 100) if self.total_decisions > 0 else 0.0
        recent = self.episode_rewards[-100:] if self.episode_rewards else []
        avg_rwd = sum(recent) / len(recent) if recent else 0.0
        q_size = len(self.q_table) if not TORCH_AVAILABLE else self._steps
        return {
            "epsilon": round(self.epsilon, 4),
            "total_decisions": self.total_decisions,
            "correct_decisions": self.correct_decisions,
            "accuracy": round(accuracy, 2),
            "avg_reward_last_100": round(avg_rwd, 3),
            "q_table_size": q_size,
            "exploration_rate": f"{self.epsilon * 100:.1f}%",
            "backend": "DQN/PyTorch" if TORCH_AVAILABLE else "Q-table/fallback",
            "replay_buffer": len(self._replay) if TORCH_AVAILABLE else 0,
        }

    def get_q_table_summary(self):
        """Return Q-value summary.  DQN evaluates states on-the-fly."""
        if TORCH_AVAILABLE:
            # Sample recent replay states and evaluate them
            if not self._replay:
                return []
            sample = list(self._replay)[-50:]
            entries = []
            for s_vec, a_idx, rwd, _ in sample:
                s_t = torch.tensor(s_vec).unsqueeze(0)
                with torch.no_grad():
                    qv = self._policy_net(s_t).squeeze(0).tolist()
                best = "block" if qv[1] > qv[0] else "allow"
                entries.append({
                    "state": "|".join(str(round(float(v))) for v in s_vec),
                    "allow_q": round(qv[0], 3),
                    "block_q": round(qv[1], 3),
                    "best_action": best,
                    "confidence": round(abs(qv[1] - qv[0]), 3),
                })
            entries.sort(key=lambda x: x["confidence"], reverse=True)
            return entries[:50]
        else:
            entries = []
            for sk, qv in self.q_table.items():
                best = max(qv, key=qv.get)
                entries.append({
                    "state": sk,
                    "allow_q": round(qv["allow"], 3),
                    "block_q": round(qv["block"], 3),
                    "best_action": best,
                    "confidence": round(abs(qv["block"] - qv["allow"]), 3),
                })
            entries.sort(key=lambda x: x["confidence"], reverse=True)
            return entries[:50]

    # ----- persistence -----

    def save(self):
        if TORCH_AVAILABLE:
            try:
                torch.save({
                    "policy_state": self._policy_net.state_dict(),
                    "target_state": self._target_net.state_dict(),
                    "epsilon": self.epsilon,
                    "total_decisions": self.total_decisions,
                    "correct_decisions": self.correct_decisions,
                    "steps": self._steps,
                }, self.MODEL_PATH)
            except Exception:
                pass
        else:
            try:
                with open(self.Q_TABLE_PATH, "w") as f:
                    json.dump({
                        "q_table": self.q_table,
                        "epsilon": self.epsilon,
                        "total_decisions": self.total_decisions,
                        "correct_decisions": self.correct_decisions,
                    }, f)
            except Exception:
                pass

    def _load_torch(self):
        if os.path.exists(self.MODEL_PATH):
            try:
                ckpt = torch.load(self.MODEL_PATH, map_location="cpu", weights_only=True)
                self._policy_net.load_state_dict(ckpt["policy_state"])
                self._target_net.load_state_dict(ckpt["target_state"])
                self.epsilon = ckpt.get("epsilon", self.epsilon)
                self.total_decisions = ckpt.get("total_decisions", 0)
                self.correct_decisions = ckpt.get("correct_decisions", 0)
                self._steps = ckpt.get("steps", 0)
                print(f"[DQNAgent] Loaded PyTorch model from {self.MODEL_PATH}")
            except Exception as e:
                print(f"[DQNAgent] Could not load model: {e}")

    def _load_qtable(self):
        if os.path.exists(self.Q_TABLE_PATH):
            try:
                with open(self.Q_TABLE_PATH, "r") as f:
                    data = json.load(f)
                self.q_table = data.get("q_table", {})
                self.epsilon = data.get("epsilon", self.epsilon)
                self.total_decisions = data.get("total_decisions", 0)
                self.correct_decisions = data.get("correct_decisions", 0)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Detection Agent — orchestrates sniffer, classifier, and RL agent
# ---------------------------------------------------------------------------

class DetectionAgent:
    """
    Main orchestrator that:
      1. Sniffs packets via Scapy
      2. Extracts features
      3. Gets RF classifier prediction
      4. Builds RL state and picks action
      5. Computes reward and updates Q-table
    """

    def __init__(self, db_callback=None, fl_server_url=None, client_id=None):
        self.classifier = EnsemblePredictor()
        self.rl_agent = DQNAgent()
        self.lstm = LSTMDetector() if LSTM_AVAILABLE else None
        self.db_callback = db_callback  # Function to save detections to DB

        self._running = False
        self._thread = None
        self._lock = threading.Lock()

        # Recent detections buffer (thread-safe ring buffer)
        self.max_detections = 200
        self.detections = collections.deque(maxlen=self.max_detections)

        # Aggregate counters
        self.stats = {
            "packets_processed": 0,
            "attacks_detected": 0,
            "packets_allowed": 0,
            "packets_blocked": 0,
            "start_time": None,
        }

        # Federated Learning
        if fl_server_url:
            cid = client_id or f"client-{uuid.uuid4().hex[:8]}"
            self.fl_client = FLClient(client_id=cid, server_url=fl_server_url)
            self.fl_client.start(self.classifier)
        else:
            self.fl_client = None

    # ---- public API ----

    def start(self, interface=None, use_simulation=False):
        """Start the detection agent in a background thread."""
        if self._running:
            return {"status": "already_running"}

        self._running = True
        self.stats["start_time"] = time.time()

        if use_simulation or not SCAPY_AVAILABLE:
            self._thread = threading.Thread(target=self._simulation_loop, daemon=True)
        else:
            self._thread = threading.Thread(
                target=self._sniff_loop, args=(interface,), daemon=True
            )
        self._thread.start()
        mode = "simulation" if (use_simulation or not SCAPY_AVAILABLE) else "live_capture"
        return {"status": "started", "mode": mode}

    def stop(self):
        """Stop the detection agent."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        # Persist learned data
        self.classifier.save()
        self.rl_agent.save()
        if self.lstm is not None:
            self.lstm.save()
        if self.fl_client:
            self.fl_client.stop()
        return {"status": "stopped"}

    def is_running(self):
        return self._running

    def get_recent_detections(self, limit=50):
        """Return recent detections."""
        with self._lock:
            items = list(self.detections)
        return items[-limit:]

    def get_status(self):
        """Full status report."""
        uptime = 0
        if self.stats["start_time"]:
            uptime = time.time() - self.stats["start_time"]
        return {
            "running": self._running,
            "uptime_seconds": round(uptime, 1),
            "packets_processed": self.stats["packets_processed"],
            "attacks_detected": self.stats["attacks_detected"],
            "packets_allowed": self.stats["packets_allowed"],
            "packets_blocked": self.stats["packets_blocked"],
            "rl_stats": self.rl_agent.get_stats(),
            "scapy_available": SCAPY_AVAILABLE,
            "sklearn_available": SKLEARN_AVAILABLE,
            "xgboost_available": XGBOOST_AVAILABLE,
            "torch_available": TORCH_AVAILABLE,
            "lstm_available": LSTM_AVAILABLE,
            "fl_status": self.fl_client.get_status() if self.fl_client else None,
        }

    # ---- internal ----

    def _process_packet(self, packet):
        """Core pipeline: extract -> classify -> RL decide -> reward -> update."""
        result = extract_features(packet)
        if result is None:
            return  # Non-IP packet, skip

        features, numeric = result

        # Step 1: RandomForest initial prediction
        rf_pred, rf_confidence = self.classifier.predict(numeric)
        rf_label = "attack" if rf_pred == 1 else "normal"

        # Step 2: Build RL state
        # Determine reason from RF + feature heuristics
        if rf_pred == 1:
            if features["has_syn"]:
                reason = "syn_scan"
            elif features["port_type"] == "suspicious":
                reason = "suspicious_port"
            elif features["ip_type"] == "external_to_internal":
                reason = "external_intrusion"
            else:
                reason = "rf_flagged"
        else:
            if features["port_type"] == "well_known":
                reason = "normal_service"
            elif features["ip_type"] == "internal":
                reason = "internal_traffic"
            else:
                reason = "benign"

        # RF confidence level bucket
        if rf_confidence >= 0.85:
            rf_conf_level = "very_high"
        elif rf_confidence >= 0.7:
            rf_conf_level = "high"
        elif rf_confidence >= 0.5:
            rf_conf_level = "medium"
        else:
            rf_conf_level = "low"

        # Packet size category
        pkt_size = features["size"]
        if pkt_size < 64:
            size_cat = "tiny"
        elif pkt_size <= 256:
            size_cat = "small"
        elif pkt_size <= 1500:
            size_cat = "normal"
        else:
            size_cat = "large"

        # Flag signature
        flag_parts = []
        if features["has_syn"]:
            flag_parts.append("S")
        if features["has_fin"]:
            flag_parts.append("F")
        if features["has_rst"]:
            flag_parts.append("R")
        flag_sig = "".join(flag_parts) if flag_parts else "none"

        state = (
            reason, features["ip_type"], features["protocol"], features["port_type"],
            rf_conf_level, size_cat, flag_sig,
        )

        # Step 3: RL agent chooses action
        action, was_exploration = self.rl_agent.choose_action(state)

        # Step 4: Compute reward
        # Ground truth heuristic: combine RF prediction with feature-based rules
        is_actually_malicious = self._heuristic_ground_truth(features, rf_pred, rf_confidence)

        if action == "block" and is_actually_malicious:
            reward = 1.0   # Correctly blocked an attack
        elif action == "allow" and not is_actually_malicious:
            reward = 1.0   # Correctly allowed safe traffic
        elif action == "block" and not is_actually_malicious:
            reward = -1.0  # False positive — blocked safe traffic
        else:
            reward = -1.0  # False negative — allowed an attack

        # Step 5: Update DQN
        self.rl_agent.update(state, action, reward)

        # Step 6: Feed back to classifier for continuous learning
        true_label = 1 if is_actually_malicious else 0
        self.classifier.add_sample(numeric, true_label)

        # Step 6b: Feed LSTM sequential detector
        lstm_anomaly = False
        lstm_score = 0.0
        if self.lstm is not None:
            self.lstm.add_packet(numeric, label=true_label)
            lstm_anomaly, lstm_score = self.lstm.predict_current()

        # Step 7: Record detection
        severity = "High" if is_actually_malicious else ("Medium" if rf_confidence < 0.7 else "Low")
        if action == "block" and is_actually_malicious:
            severity = "High"
        elif action == "block" and not is_actually_malicious:
            severity = "Medium"
        # Escalate if LSTM detects sequential anomaly
        if lstm_anomaly and severity == "Low":
            severity = "Medium"

        detection = {
            "timestamp": time.time() * 1000,
            "src_ip": features["src_ip"],
            "dst_ip": features["dst_ip"],
            "protocol": features["protocol"],
            "sport": features["sport"],
            "dport": features["dport"],
            "size": features["size"],
            "flags": features["flags"],
            "rf_prediction": rf_label,
            "rf_confidence": round(rf_confidence, 3),
            "rl_state": "|".join(str(s) for s in state),
            "rl_action": action,
            "rl_reward": reward,
            "was_exploration": was_exploration,
            "is_malicious": is_actually_malicious,
            "severity": severity,
            "reason": reason,
            "epsilon": round(self.rl_agent.epsilon, 4),
            "lstm_anomaly": lstm_anomaly,
            "lstm_score": lstm_score,
        }

        with self._lock:
            self.detections.append(detection)
            self.stats["packets_processed"] += 1
            if is_actually_malicious:
                self.stats["attacks_detected"] += 1
            if action == "allow":
                self.stats["packets_allowed"] += 1
            else:
                self.stats["packets_blocked"] += 1

        # Callback to save to DB
        if self.db_callback:
            try:
                self.db_callback(detection)
            except Exception:
                pass

        # Auto-save periodically
        if self.stats["packets_processed"] % 100 == 0:
            self.classifier.save()
            self.rl_agent.save()
            if self.lstm is not None:
                self.lstm.save()

    def _heuristic_ground_truth(self, features, rf_pred, rf_confidence):
        """
        Approximate ground truth using multi-signal heuristic.
        In production this would use labeled data or threat intel feeds.
        """
        score = 0.0

        # RF prediction with confidence weighting
        if rf_pred == 1:
            score += 0.4 * rf_confidence
        else:
            score -= 0.3 * rf_confidence

        # Port-based signals
        if features["port_type"] == "suspicious":
            score += 0.35
        elif features["port_type"] == "well_known":
            score -= 0.2

        # SYN scan detection
        if features["has_syn"] and features["protocol"] == "TCP":
            score += 0.25

        # RST flood
        if features["has_rst"]:
            score += 0.1

        # External to internal is riskier
        if features["ip_type"] == "external_to_internal":
            score += 0.15
        elif features["ip_type"] == "internal":
            score -= 0.15

        # Very large or very small packets
        if features["size"] > 8000 or features["size"] < 40:
            score += 0.1

        return score >= 0.35

    def _sniff_loop(self, interface):
        """Live packet capture using Scapy."""
        try:
            # Disable verbose output
            conf.verb = 0
            sniff(
                iface=interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            print("[DetectionAgent] ERROR: Packet capture requires administrator/root privileges.")
            print("[DetectionAgent] Falling back to simulation mode.")
            self._simulation_loop()
        except Exception as e:
            print(f"[DetectionAgent] Sniff error: {e}")
            print("[DetectionAgent] Falling back to simulation mode.")
            self._simulation_loop()

    def _simulation_loop(self):
        """
        Simulated packet generation for development / non-admin environments.
        Creates realistic synthetic packets that go through the full pipeline.
        """
        if not SCAPY_AVAILABLE:
            # Pure simulation without Scapy — generate feature dicts directly
            self._pure_simulation_loop()
            return

        from scapy.all import Ether, Raw

        while self._running:
            try:
                packet = self._generate_synthetic_packet()
                self._process_packet(packet)
                # Variable rate: faster when exploring, slower when stable
                delay = random.uniform(0.5, 2.0)
                time.sleep(delay)
            except Exception as e:
                print(f"[DetectionAgent] Simulation error: {e}")
                time.sleep(1)

    def _generate_synthetic_packet(self):
        """Create a realistic synthetic Scapy packet."""
        from scapy.all import Ether, Raw

        # 70% normal, 30% attack-like
        is_attack = random.random() < 0.30

        if is_attack:
            src_ip = random.choice([
                f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "203.0.113.42", "198.51.100.1", "185.220.101.1",
            ])
            dst_ip = random.choice([
                "192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.15",
            ])
            proto = random.choice(["TCP_SYN", "TCP_SUSPICIOUS", "UDP_SUSPICIOUS", "ICMP"])
        else:
            src_ip = random.choice([
                "192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.15",
            ])
            dst_ip = random.choice([
                "8.8.8.8", "1.1.1.1", "192.168.1.1", "172.217.0.46",
            ])
            proto = random.choice(["TCP_NORMAL", "UDP_DNS", "TCP_HTTPS", "TCP_HTTP"])

        if proto == "TCP_SYN":
            sport = random.randint(1024, 65535)
            dport = random.choice(list(SUSPICIOUS_PORTS) + [22, 445, 135, 3389])
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S")
        elif proto == "TCP_SUSPICIOUS":
            sport = random.randint(1024, 65535)
            dport = random.choice(list(SUSPICIOUS_PORTS))
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=b"X" * random.randint(100, 5000))
        elif proto == "UDP_SUSPICIOUS":
            sport = random.randint(1024, 65535)
            dport = random.choice(list(SUSPICIOUS_PORTS) + [0])
            pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=b"\x00" * random.randint(500, 10000))
        elif proto == "ICMP":
            pkt = IP(src=src_ip, dst=dst_ip) / ICMP() / Raw(load=b"\x00" * random.randint(64, 2000))
        elif proto == "TCP_HTTPS":
            sport = random.randint(1024, 65535)
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=443, flags="PA") / Raw(load=b"\x16\x03\x01" + b"\x00" * random.randint(100, 1400))
        elif proto == "TCP_HTTP":
            sport = random.randint(1024, 65535)
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=80, flags="PA") / Raw(load=b"GET / HTTP/1.1\r\n" + b"\x00" * random.randint(50, 500))
        elif proto == "UDP_DNS":
            sport = random.randint(1024, 65535)
            pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=53) / Raw(load=b"\x00" * random.randint(30, 128))
        else:  # TCP_NORMAL
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 8080, 3306])
            pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A") / Raw(load=b"\x00" * random.randint(64, 1500))

        return pkt

    def _pure_simulation_loop(self):
        """Fallback simulation when Scapy is not installed at all."""
        while self._running:
            try:
                detection = self._generate_pure_synthetic_detection()
                with self._lock:
                    self.detections.append(detection)
                    self.stats["packets_processed"] += 1
                    if detection["is_malicious"]:
                        self.stats["attacks_detected"] += 1
                    if detection["rl_action"] == "allow":
                        self.stats["packets_allowed"] += 1
                    else:
                        self.stats["packets_blocked"] += 1

                if self.db_callback:
                    try:
                        self.db_callback(detection)
                    except Exception:
                        pass

                if self.stats["packets_processed"] % 100 == 0:
                    self.rl_agent.save()

                time.sleep(random.uniform(0.5, 2.0))
            except Exception as e:
                print(f"[DetectionAgent] Pure simulation error: {e}")
                time.sleep(1)

    def _generate_pure_synthetic_detection(self):
        """Generate a synthetic detection without Scapy."""
        is_attack = random.random() < 0.30

        if is_attack:
            src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            dst_ip = random.choice(["192.168.1.10", "10.0.0.5", "172.16.0.15"])
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            dport = random.choice(list(SUSPICIOUS_PORTS) + [445, 135, 3389])
            sport = random.randint(1024, 65535)
            size = random.choice([40, 60, random.randint(5000, 65535)])
            reason = random.choice(["syn_scan", "suspicious_port", "external_intrusion", "rf_flagged"])
            ip_type = "external_to_internal"
            port_type = "suspicious"
        else:
            src_ip = random.choice(["192.168.1.10", "192.168.1.20", "10.0.0.5"])
            dst_ip = random.choice(["8.8.8.8", "1.1.1.1", "192.168.1.1"])
            protocol = random.choice(["TCP", "UDP"])
            dport = random.choice([80, 443, 53, 22, 8080])
            sport = random.randint(1024, 65535)
            size = random.randint(64, 1500)
            reason = random.choice(["normal_service", "internal_traffic", "benign"])
            ip_type = random.choice(["internal", "internal_to_external"])
            port_type = "well_known"

        rf_confidence = random.uniform(0.55, 0.95)

        # RF confidence level bucket
        if rf_confidence >= 0.85:
            rf_conf_level = "very_high"
        elif rf_confidence >= 0.7:
            rf_conf_level = "high"
        elif rf_confidence >= 0.5:
            rf_conf_level = "medium"
        else:
            rf_conf_level = "low"

        # Packet size category
        if size < 64:
            size_cat = "tiny"
        elif size <= 256:
            size_cat = "small"
        elif size <= 1500:
            size_cat = "normal"
        else:
            size_cat = "large"

        # Flag signature (no TCP flags in pure sim)
        flag_sig = "none"

        state = (
            reason, ip_type, protocol, port_type,
            rf_conf_level, size_cat, flag_sig,
        )
        action, was_exploration = self.rl_agent.choose_action(state)

        # Reward
        if action == "block" and is_attack:
            reward = 1.0
        elif action == "allow" and not is_attack:
            reward = 1.0
        else:
            reward = -1.0

        self.rl_agent.update(state, action, reward)

        severity = "High" if is_attack else "Low"
        if action == "block" and not is_attack:
            severity = "Medium"

        # LSTM in synthetic mode
        lstm_anomaly = False
        lstm_score = 0.0
        if self.lstm is not None:
            numeric = [0]*11  # placeholder features for pure synthetic
            self.lstm.add_packet(numeric, label=1 if is_attack else 0)
            lstm_anomaly, lstm_score = self.lstm.predict_current()

        if lstm_anomaly and severity == "Low":
            severity = "Medium"

        return {
            "timestamp": time.time() * 1000,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "sport": sport,
            "dport": dport,
            "size": size,
            "flags": "",
            "rf_prediction": "attack" if is_attack else "normal",
            "rf_confidence": round(rf_confidence, 3),
            "rl_state": "|".join(str(s) for s in state),
            "rl_action": action,
            "rl_reward": reward,
            "was_exploration": was_exploration,
            "is_malicious": is_attack,
            "severity": severity,
            "reason": reason,
            "epsilon": round(self.rl_agent.epsilon, 4),
            "lstm_anomaly": lstm_anomaly,
            "lstm_score": lstm_score,
        }
