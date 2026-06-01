"""
Central MLflow experiment tracking.

All MLflow interaction lives here. Every public function degrades gracefully
(silent no-op) when MLflow is not installed or the tracking server is down.
"""

import os
import tempfile
from typing import Any

try:
    import mlflow
    import mlflow.sklearn
    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False

from app.core.config import DATA_DIR, MLFLOW_URI

EXPERIMENT_RF_TRAINING = "firewall/rf-training"
EXPERIMENT_EVALUATION  = "firewall/model-evaluation"
EXPERIMENT_RL_AGENT    = "firewall/rl-agent"

TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", MLFLOW_URI)

if MLFLOW_AVAILABLE:
    os.makedirs(DATA_DIR, exist_ok=True)
    mlflow.set_tracking_uri(TRACKING_URI)


def log_confusion_matrix(cm: list, labels: list[str], name: str = "confusion_matrix") -> None:
    if not MLFLOW_AVAILABLE:
        return
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        cm_arr = np.array(cm, dtype=float)
        fig, ax = plt.subplots(figsize=(5, 4))
        im = ax.imshow(cm_arr, interpolation="nearest", cmap="Blues")
        plt.colorbar(im, ax=ax)
        ax.set_xticks(range(len(labels))); ax.set_yticks(range(len(labels)))
        ax.set_xticklabels(labels, fontsize=10); ax.set_yticklabels(labels, fontsize=10)
        ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title("Confusion Matrix")
        thresh = cm_arr.max() / 2.0
        for i in range(len(labels)):
            for j in range(len(labels)):
                ax.text(j, i, str(int(cm_arr[i, j])), ha="center", va="center",
                        color="white" if cm_arr[i, j] > thresh else "black")
        plt.tight_layout()
        tmp = os.path.join(tempfile.gettempdir(), f"mlf_{name}_{os.getpid()}.png")
        fig.savefig(tmp, dpi=100); plt.close(fig)
        mlflow.log_artifact(tmp, artifact_path="plots"); os.unlink(tmp)
    except Exception:
        pass


def log_feature_importance(model: Any, feature_names: list[str], name: str = "feature_importance") -> None:
    if not MLFLOW_AVAILABLE or not hasattr(model, "feature_importances_"):
        return
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1]
        sorted_names = [feature_names[i] for i in indices]
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.bar(range(len(importances)), importances[indices], color="steelblue")
        ax.set_xticks(range(len(importances)))
        ax.set_xticklabels(sorted_names, rotation=40, ha="right", fontsize=9)
        ax.set_title("Feature Importances"); ax.set_ylabel("Importance"); plt.tight_layout()
        tmp = os.path.join(tempfile.gettempdir(), f"mlf_{name}_{os.getpid()}.png")
        fig.savefig(tmp, dpi=100); plt.close(fig)
        mlflow.log_artifact(tmp, artifact_path="plots"); os.unlink(tmp)
    except Exception:
        pass


def log_artifact(path: str, artifact_path: str | None = None) -> None:
    if not MLFLOW_AVAILABLE or not os.path.exists(path):
        return
    try:
        mlflow.log_artifact(path, artifact_path=artifact_path)
    except Exception:
        pass


class RLTracker:
    """Logs DQN agent metrics to a persistent MLflow run."""

    def __init__(self, run_name: str = "dqn-agent", log_every: int = 100) -> None:
        self._run_id: str | None = None
        self._log_every = log_every
        self._cumulative_reward = 0.0
        if not MLFLOW_AVAILABLE:
            return
        try:
            mlflow.set_experiment(EXPERIMENT_RL_AGENT)
            run = mlflow.start_run(run_name=run_name)
            self._run_id = run.info.run_id
            mlflow.end_run()
        except Exception:
            pass

    def log_hyperparams(self, params: dict) -> None:
        if self._run_id is None:
            return
        try:
            with mlflow.start_run(run_id=self._run_id):
                mlflow.log_params(params)
        except Exception:
            pass

    def log_step(self, step: int, epsilon: float, reward: float,
                 accuracy: float, avg_reward_last_100: float) -> None:
        self._cumulative_reward += reward
        if self._run_id is None or step % self._log_every != 0:
            return
        try:
            with mlflow.start_run(run_id=self._run_id):
                mlflow.log_metrics({
                    "epsilon": round(epsilon, 4),
                    "accuracy_pct": round(accuracy, 2),
                    "avg_reward_last_100": round(avg_reward_last_100, 4),
                    "cumulative_reward": round(self._cumulative_reward, 4),
                }, step=step)
        except Exception:
            pass
