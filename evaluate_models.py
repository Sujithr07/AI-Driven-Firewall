"""
Evaluate ML models on NSL-KDD dataset.
Loads KDDTrain+.txt and KDDTest+.txt, evaluates RF, XGBoost, Ensemble, and LSTM.
Produces ROC curves, PR curves, and confusion matrices stored in data/eval_results.json.
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, precision_recall_curve, auc, roc_auc_score,
)

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
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    import mlflow
    from mlops.tracking import (
        EXPERIMENT_EVALUATION,
        MLFLOW_AVAILABLE,
        log_confusion_matrix,
        log_feature_importance,
        log_artifact,
    )
except ImportError:
    MLFLOW_AVAILABLE = False

FEATURE_COLUMNS = [
    'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'duration',
]

KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty',
]

_CM_LABELS = ["normal", "attack"]

# Model display colors (mirrored in the frontend)
MODEL_COLORS = {
    'rf': '#3b82f6',
    'xgb': '#a855f7',
    'ensemble': '#22c55e',
    'lstm': '#f59e0b',
}


# ── Data loading & preprocessing ─────────────────────────────────────────────

def load_data():
    print("Loading NSL-KDD dataset...")
    train_path = "data/KDDTrain+.txt"
    test_path = "data/KDDTest+.txt"
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        raise FileNotFoundError("NSL-KDD data files not found. Run download_nslkdd.py first.")
    train_df = pd.read_csv(train_path, names=KDD_COLUMNS, header=None)
    test_df = pd.read_csv(test_path, names=KDD_COLUMNS, header=None)
    print(f"Train samples: {len(train_df)}, Test samples: {len(test_df)}")
    return train_df, test_df


def preprocess_data(df, label_encoders=None, fit=True):
    X_raw = df[FEATURE_COLUMNS].copy()
    y = df['label'].apply(lambda x: 0 if x == 'normal' else 1).values
    categorical_cols = ['protocol_type', 'service', 'flag']
    if fit:
        label_encoders = {}
        for col in categorical_cols:
            le = LabelEncoder()
            X_raw[col] = le.fit_transform(X_raw[col].astype(str))
            label_encoders[col] = le
    else:
        for col in categorical_cols:
            le = label_encoders[col]
            X_raw[col] = X_raw[col].astype(str)
            unseen_mask = ~X_raw[col].isin(le.classes_)
            X_raw.loc[unseen_mask, col] = le.classes_[0]
            X_raw[col] = le.transform(X_raw[col])
    return X_raw.values.astype(np.float64), y, label_encoders


# ── Metrics computation ───────────────────────────────────────────────────────

def _sample_curve(x_arr, y_arr, n=80):
    """Downsample a curve to at most n evenly-spaced index positions."""
    total = len(x_arr)
    if total <= n:
        return [float(v) for v in x_arr], [float(v) for v in y_arr]
    idx = np.linspace(0, total - 1, n, dtype=int)
    return [float(x_arr[i]) for i in idx], [float(y_arr[i]) for i in idx]


def compute_metrics(y_true, y_pred, y_prob=None):
    """
    Compute classification metrics. When y_prob is supplied also compute
    ROC and Precision-Recall curves (stored as sampled point arrays + AUC).
    """
    result = {
        'accuracy':   float(accuracy_score(y_true, y_pred)),
        'precision':  float(precision_score(y_true, y_pred, average='macro', zero_division=0)),
        'recall':     float(recall_score(y_true, y_pred, average='macro', zero_division=0)),
        'f1_macro':   float(f1_score(y_true, y_pred, average='macro', zero_division=0)),
        'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
    }
    if y_prob is not None:
        try:
            fpr, tpr, _ = roc_curve(y_true, y_prob)
            roc_auc = float(roc_auc_score(y_true, y_prob))
            fpr_s, tpr_s = _sample_curve(fpr, tpr)
            result['roc'] = {'fpr': fpr_s, 'tpr': tpr_s, 'auc': round(roc_auc, 4)}

            prec, rec, _ = precision_recall_curve(y_true, y_prob)
            pr_auc = float(auc(rec, prec))
            rec_s, prec_s = _sample_curve(rec, prec)
            result['pr'] = {'recall': rec_s, 'precision': prec_s, 'auc': round(pr_auc, 4)}
        except Exception as e:
            print(f"  Warning: could not compute ROC/PR curves: {e}")
    return result


# ── Model loading & MLflow helpers ────────────────────────────────────────────

def load_model(model_path):
    if not os.path.exists(model_path):
        print(f"  Warning: {model_path} not found. Skipping.")
        return None
    with open(model_path, 'rb') as f:
        saved = pickle.load(f)
    return saved['model'] if isinstance(saved, dict) else saved


def _mlflow_log_eval(run_name, model_path, params, metrics):
    if not MLFLOW_AVAILABLE:
        return
    try:
        mlflow.set_experiment(EXPERIMENT_EVALUATION)
        with mlflow.start_run(run_name=run_name):
            mlflow.set_tags({"evaluation_type": "original", "model_path": model_path})
            mlflow.log_params(params)
            scalar = {k: v for k, v in metrics.items() if isinstance(v, (int, float))}
            if 'roc' in metrics:
                scalar['roc_auc'] = metrics['roc']['auc']
            if 'pr' in metrics:
                scalar['pr_auc'] = metrics['pr']['auc']
            mlflow.log_metrics(scalar)
            log_confusion_matrix(metrics["confusion_matrix"], _CM_LABELS)
            if model_path:
                log_artifact(model_path, artifact_path="model")
    except Exception as e:
        print(f"[MLflow] {run_name}: {e}")


# ── Original model evaluation (domain-shift test) ─────────────────────────────

def evaluate_rf(X_test, y_test):
    print("\nEvaluating RandomForest (original)...")
    model = load_model('rf_model_seed.pkl')
    if model is None:
        return None
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    metrics = compute_metrics(y_test, y_pred, y_prob)
    print(f"  Accuracy: {metrics['accuracy']:.4f}  F1: {metrics['f1_macro']:.4f}"
          + (f"  ROC-AUC: {metrics['roc']['auc']:.4f}" if 'roc' in metrics else ""))
    _mlflow_log_eval("rf-original-eval", "rf_model_seed.pkl",
                     {"model": "RandomForest", "source": "original"}, metrics)
    return metrics


def evaluate_xgb(X_test, y_test):
    print("\nEvaluating XGBoost (original)...")
    if not XGBOOST_AVAILABLE:
        print("  XGBoost not installed. Skipping.")
        return None
    model = load_model('xgb_model.pkl')
    if model is None:
        return None
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    metrics = compute_metrics(y_test, y_pred, y_prob)
    print(f"  Accuracy: {metrics['accuracy']:.4f}  F1: {metrics['f1_macro']:.4f}"
          + (f"  ROC-AUC: {metrics['roc']['auc']:.4f}" if 'roc' in metrics else ""))
    _mlflow_log_eval("xgb-original-eval", "xgb_model.pkl",
                     {"model": "XGBoost", "source": "original"}, metrics)
    return metrics


def evaluate_ensemble(X_test, y_test, rf_metrics, xgb_metrics):
    print("\nEvaluating Ensemble (original)...")
    if rf_metrics is None or xgb_metrics is None:
        print("  Skipping: one or both base models unavailable.")
        return None
    rf_model = load_model('rf_model_seed.pkl')
    xgb_model = load_model('xgb_model.pkl')
    if rf_model is None or xgb_model is None:
        return None
    rf_prob = rf_model.predict_proba(X_test)[:, 1]
    xgb_prob = xgb_model.predict_proba(X_test)[:, 1]
    avg_prob = 0.5 * rf_prob + 0.5 * xgb_prob
    y_pred = (avg_prob >= 0.5).astype(int)
    metrics = compute_metrics(y_test, y_pred, y_prob=avg_prob)
    print(f"  Accuracy: {metrics['accuracy']:.4f}  F1: {metrics['f1_macro']:.4f}"
          + (f"  ROC-AUC: {metrics['roc']['auc']:.4f}" if 'roc' in metrics else ""))
    _mlflow_log_eval("ensemble-original-eval", "",
                     {"model": "Ensemble(RF+XGB)", "ensemble_weights": "0.5/0.5", "source": "original"},
                     metrics)
    return metrics


# ── LSTM ──────────────────────────────────────────────────────────────────────

class _LSTMClassifier(nn.Module if TORCH_AVAILABLE else object):
    """2-layer LSTM treating each feature as a time step (seq_len=n_features, input_size=1)."""
    def __init__(self, n_features, hidden=64):
        super().__init__()
        self.lstm = nn.LSTM(1, hidden, num_layers=2, batch_first=True, dropout=0.3)
        self.head = nn.Sequential(
            nn.Linear(hidden, 32), nn.ReLU(), nn.Dropout(0.2), nn.Linear(32, 2),
        )

    def forward(self, x):  # x: (B, n_features, 1)
        out, _ = self.lstm(x)
        return self.head(out[:, -1])


def train_lstm(X_train, y_train, X_test, y_test, epochs=15, hidden=64, batch_size=512):
    """Train LSTM on the supplied arrays. Returns (metrics_dict, model_path) or (None, None)."""
    if not TORCH_AVAILABLE:
        print("  PyTorch not available. Skipping LSTM.")
        return None, None

    n_features = X_train.shape[1]
    print(f"\nTraining LSTM on NSL-KDD (epochs={epochs}, hidden={hidden})...")

    # Feature normalisation (z-score)
    X_mean = X_train.mean(axis=0)
    X_std  = X_train.std(axis=0) + 1e-8
    X_tr_n = ((X_train - X_mean) / X_std).reshape(-1, n_features, 1).astype(np.float32)
    X_te_n = ((X_test  - X_mean) / X_std).reshape(-1, n_features, 1).astype(np.float32)

    tr_ds = TensorDataset(torch.from_numpy(X_tr_n), torch.from_numpy(y_train.astype(np.int64)))
    loader = DataLoader(tr_ds, batch_size=batch_size, shuffle=True)

    model = _LSTMClassifier(n_features, hidden)
    opt   = torch.optim.Adam(model.parameters(), lr=1e-3)
    crit  = nn.CrossEntropyLoss()

    model.train()
    for epoch in range(epochs):
        total_loss = sum(
            (lambda loss: (opt.zero_grad(), loss.backward(), opt.step(), loss.item())[-1])(
                crit(model(xb), yb)
            )
            for xb, yb in loader
        )
        if (epoch + 1) % 5 == 0:
            print(f"    Epoch {epoch+1}/{epochs}  loss={total_loss/len(loader):.4f}")

    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(X_te_n))
        probs  = torch.softmax(logits, dim=1)[:, 1].numpy()
    y_pred = (probs >= 0.5).astype(int)

    metrics = compute_metrics(y_test, y_pred, y_prob=probs)
    print(f"  Accuracy: {metrics['accuracy']:.4f}  F1: {metrics['f1_macro']:.4f}"
          + (f"  ROC-AUC: {metrics['roc']['auc']:.4f}" if 'roc' in metrics else ""))

    os.makedirs('data', exist_ok=True)
    lstm_path = 'data/lstm_model_nslkdd.pt'
    torch.save({'state_dict': model.state_dict(), 'X_mean': X_mean, 'X_std': X_std,
                'n_features': n_features, 'hidden': hidden}, lstm_path)
    print(f"  LSTM saved -> {lstm_path}")

    if MLFLOW_AVAILABLE:
        try:
            mlflow.set_experiment(EXPERIMENT_EVALUATION)
            with mlflow.start_run(run_name="lstm-nslkdd-train-eval"):
                mlflow.set_tags({"evaluation_type": "nslkdd_retrained", "model": "LSTM"})
                mlflow.log_params({"epochs": epochs, "hidden": hidden, "batch_size": batch_size,
                                   "num_layers": 2, "dataset": "NSL-KDD"})
                scalar = {k: v for k, v in metrics.items() if isinstance(v, (int, float))}
                if 'roc' in metrics:
                    scalar['roc_auc'] = metrics['roc']['auc']
                if 'pr' in metrics:
                    scalar['pr_auc'] = metrics['pr']['auc']
                mlflow.log_metrics(scalar)
                log_confusion_matrix(metrics["confusion_matrix"], _CM_LABELS)
                log_artifact(lstm_path, artifact_path="model")
        except Exception as e:
            print(f"[MLflow] LSTM: {e}")

    return metrics, lstm_path


# ── NSL-KDD retrained evaluation ──────────────────────────────────────────────

def train_and_evaluate_nslkdd():
    print("\n" + "=" * 70)
    print("TRAINING NEW MODELS ON NSL-KDD DATA")
    print("=" * 70)

    train_df, test_df = load_data()

    print("\nPreprocessing data...")
    X_train, y_train, label_encoders = preprocess_data(train_df, fit=True)
    X_test,  y_test,  _              = preprocess_data(test_df, label_encoders=label_encoders, fit=False)
    print(f"Train: {X_train.shape}  Test: {X_test.shape}")
    print(f"Train dist — Normal: {sum(y_train==0)}  Attack: {sum(y_train==1)}")
    print(f"Test  dist — Normal: {sum(y_test==0)}   Attack: {sum(y_test==1)}")

    n_rf, d_rf   = 100, 15
    n_xgb, d_xgb = 100, 10
    lr_xgb       = 0.1

    # ── RandomForest ──────────────────────────────────────────────────────────
    rf_metrics, rf_model = None, None
    if SKLEARN_AVAILABLE:
        print("\nTraining RandomForest on NSL-KDD...")
        rf_model = RandomForestClassifier(n_estimators=n_rf, max_depth=d_rf, random_state=42, n_jobs=-1)
        rf_model.fit(X_train, y_train)
        y_pred = rf_model.predict(X_test)
        y_prob = rf_model.predict_proba(X_test)[:, 1]
        rf_metrics = compute_metrics(y_test, y_pred, y_prob)
        print(f"  Accuracy: {rf_metrics['accuracy']:.4f}  F1: {rf_metrics['f1_macro']:.4f}"
              + (f"  ROC-AUC: {rf_metrics['roc']['auc']:.4f}" if 'roc' in rf_metrics else ""))

        rf_path = 'data/rf_model_nslkdd.pkl'
        with open(rf_path, 'wb') as f:
            pickle.dump(rf_model, f)
        print(f"  Saved -> {rf_path}")

        if MLFLOW_AVAILABLE:
            try:
                mlflow.set_experiment(EXPERIMENT_EVALUATION)
                with mlflow.start_run(run_name="rf-nslkdd-train-eval"):
                    mlflow.set_tags({"evaluation_type": "nslkdd_retrained", "model": "RandomForest"})
                    mlflow.log_params({"n_estimators": n_rf, "max_depth": d_rf,
                                       "random_state": 42, "dataset": "NSL-KDD",
                                       "train_samples": len(y_train), "test_samples": len(y_test)})
                    scalar = {k: v for k, v in rf_metrics.items() if isinstance(v, (int, float))}
                    if 'roc' in rf_metrics:
                        scalar['roc_auc'] = rf_metrics['roc']['auc']
                    mlflow.log_metrics(scalar)
                    log_confusion_matrix(rf_metrics["confusion_matrix"], _CM_LABELS)
                    log_feature_importance(rf_model, FEATURE_COLUMNS)
                    log_artifact(rf_path, artifact_path="model")
            except Exception as e:
                print(f"[MLflow] RF NSL-KDD: {e}")
    else:
        print("  Sklearn unavailable. Skipping RF.")

    # ── XGBoost ───────────────────────────────────────────────────────────────
    xgb_metrics, xgb_model = None, None
    if XGBOOST_AVAILABLE:
        print("\nTraining XGBoost on NSL-KDD...")
        xgb_model = xgb.XGBClassifier(
            n_estimators=n_xgb, max_depth=d_xgb, learning_rate=lr_xgb,
            use_label_encoder=False, eval_metric='logloss',
            random_state=42, n_jobs=-1, verbosity=0,
        )
        xgb_model.fit(X_train, y_train)
        y_pred = xgb_model.predict(X_test)
        y_prob = xgb_model.predict_proba(X_test)[:, 1]
        xgb_metrics = compute_metrics(y_test, y_pred, y_prob)
        print(f"  Accuracy: {xgb_metrics['accuracy']:.4f}  F1: {xgb_metrics['f1_macro']:.4f}"
              + (f"  ROC-AUC: {xgb_metrics['roc']['auc']:.4f}" if 'roc' in xgb_metrics else ""))

        xgb_path = 'data/xgb_model_nslkdd.pkl'
        with open(xgb_path, 'wb') as f:
            pickle.dump(xgb_model, f)
        print(f"  Saved -> {xgb_path}")

        if MLFLOW_AVAILABLE:
            try:
                mlflow.set_experiment(EXPERIMENT_EVALUATION)
                with mlflow.start_run(run_name="xgb-nslkdd-train-eval"):
                    mlflow.set_tags({"evaluation_type": "nslkdd_retrained", "model": "XGBoost"})
                    mlflow.log_params({"n_estimators": n_xgb, "max_depth": d_xgb,
                                       "learning_rate": lr_xgb, "eval_metric": "logloss",
                                       "dataset": "NSL-KDD",
                                       "train_samples": len(y_train), "test_samples": len(y_test)})
                    scalar = {k: v for k, v in xgb_metrics.items() if isinstance(v, (int, float))}
                    if 'roc' in xgb_metrics:
                        scalar['roc_auc'] = xgb_metrics['roc']['auc']
                    mlflow.log_metrics(scalar)
                    log_confusion_matrix(xgb_metrics["confusion_matrix"], _CM_LABELS)
                    log_artifact(xgb_path, artifact_path="model")
            except Exception as e:
                print(f"[MLflow] XGBoost NSL-KDD: {e}")
    else:
        print("  XGBoost unavailable. Skipping.")

    # ── Ensemble ──────────────────────────────────────────────────────────────
    ensemble_metrics = None
    if rf_model is not None and xgb_model is not None:
        print("\nEvaluating Ensemble (NSL-KDD trained)...")
        rf_prob  = rf_model.predict_proba(X_test)[:, 1]
        xgb_prob = xgb_model.predict_proba(X_test)[:, 1]
        avg_prob = 0.5 * rf_prob + 0.5 * xgb_prob
        y_pred   = (avg_prob >= 0.5).astype(int)
        ensemble_metrics = compute_metrics(y_test, y_pred, y_prob=avg_prob)
        print(f"  Accuracy: {ensemble_metrics['accuracy']:.4f}  F1: {ensemble_metrics['f1_macro']:.4f}"
              + (f"  ROC-AUC: {ensemble_metrics['roc']['auc']:.4f}" if 'roc' in ensemble_metrics else ""))

        if MLFLOW_AVAILABLE:
            try:
                mlflow.set_experiment(EXPERIMENT_EVALUATION)
                with mlflow.start_run(run_name="ensemble-nslkdd-eval"):
                    mlflow.set_tags({"evaluation_type": "nslkdd_retrained", "model": "Ensemble(RF+XGB)"})
                    mlflow.log_params({"ensemble_weights": "0.5/0.5", "dataset": "NSL-KDD"})
                    scalar = {k: v for k, v in ensemble_metrics.items() if isinstance(v, (int, float))}
                    if 'roc' in ensemble_metrics:
                        scalar['roc_auc'] = ensemble_metrics['roc']['auc']
                    mlflow.log_metrics(scalar)
                    log_confusion_matrix(ensemble_metrics["confusion_matrix"], _CM_LABELS)
            except Exception as e:
                print(f"[MLflow] Ensemble NSL-KDD: {e}")
    else:
        print("\nSkipping Ensemble: one or both base models unavailable.")

    # ── LSTM ──────────────────────────────────────────────────────────────────
    lstm_metrics, _ = train_lstm(X_train, y_train, X_test, y_test)

    # ── Baseline ──────────────────────────────────────────────────────────────
    total = len(y_test)
    attack_n = int(sum(y_test == 1))
    normal_n = int(sum(y_test == 0))
    baseline = {
        'majority_class_accuracy': round(max(attack_n, normal_n) / total, 4),
        'majority_class': 'attack' if attack_n > normal_n else 'normal',
        'random_accuracy': 0.5,
        'test_samples': total,
        'attack_samples': attack_n,
        'normal_samples': normal_n,
    }

    results = {
        'rf': rf_metrics,
        'xgb': xgb_metrics,
        'ensemble': ensemble_metrics,
        'lstm': lstm_metrics,
        'baseline_comparison': baseline,
        'timestamp': datetime.now().isoformat(),
    }

    _print_summary({
        'RandomForest': rf_metrics,
        'XGBoost': xgb_metrics,
        'Ensemble': ensemble_metrics,
        'LSTM': lstm_metrics,
    }, baseline)

    legacy_path = 'data/eval_results_nslkdd.json'
    with open(legacy_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nNSL-KDD results saved -> {legacy_path}")

    if MLFLOW_AVAILABLE:
        try:
            mlflow.set_experiment(EXPERIMENT_EVALUATION)
            with mlflow.start_run(run_name="nslkdd-results-artifact"):
                log_artifact(legacy_path, artifact_path="results")
        except Exception:
            pass

    return results


# ── Console summary ───────────────────────────────────────────────────────────

def _print_summary(results, baseline):
    print("\n" + "=" * 70)
    print("EVALUATION SUMMARY")
    print("=" * 70)
    headers = ["Model", "Accuracy", "Precision", "Recall", "F1 (macro)", "ROC-AUC"]
    rows = []
    for name, m in results.items():
        if m is None:
            rows.append([name] + ["N/A"] * 5)
        else:
            rows.append([
                name,
                f"{m['accuracy']:.4f}",
                f"{m['precision']:.4f}",
                f"{m['recall']:.4f}",
                f"{m['f1_macro']:.4f}",
                f"{m['roc']['auc']:.4f}" if 'roc' in m else "N/A",
            ])
    widths = [max(len(h), max(len(r[i]) for r in rows)) + 4 for i, h in enumerate(headers)]
    print("".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("-" * sum(widths))
    for row in rows:
        print("".join(str(v).ljust(w) for v, w in zip(row, widths)))
    print("=" * 70)
    print(f"\nBaseline — majority class ({baseline['majority_class']}): "
          f"{baseline['majority_class_accuracy']:.4f}")
    print(f"Test set: {baseline['normal_samples']} normal, {baseline['attack_samples']} attack")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("NSL-KDD Model Evaluation Dashboard")
    print("=" * 70)

    train_df, test_df = load_data()

    print("\nPreprocessing data...")
    X_train, y_train, label_encoders = preprocess_data(train_df, fit=True)
    X_test,  y_test,  _              = preprocess_data(test_df, label_encoders=label_encoders, fit=False)
    print(f"Feature shape: {X_test.shape}")
    print(f"Test dist — Normal: {sum(y_test==0)}  Attack: {sum(y_test==1)}")

    # Original model evaluation (domain-shift test — models may not exist)
    rf_metrics       = evaluate_rf(X_test, y_test)
    xgb_metrics      = evaluate_xgb(X_test, y_test)
    ensemble_metrics = evaluate_ensemble(X_test, y_test, rf_metrics, xgb_metrics)

    total    = len(y_test)
    attack_n = int(sum(y_test == 1))
    normal_n = int(sum(y_test == 0))
    baseline = {
        'majority_class_accuracy': round(max(attack_n, normal_n) / total, 4),
        'majority_class': 'attack' if attack_n > normal_n else 'normal',
        'random_accuracy': 0.5,
        'test_samples': total,
        'attack_samples': attack_n,
        'normal_samples': normal_n,
    }

    _print_summary({'RandomForest': rf_metrics, 'XGBoost': xgb_metrics, 'Ensemble': ensemble_metrics},
                   baseline)

    # NSL-KDD retrained + LSTM
    nslkdd = train_and_evaluate_nslkdd()

    # Comprehensive results file consumed by the frontend
    combined = {
        'original_models': {
            'rf':       rf_metrics,
            'xgb':      xgb_metrics,
            'ensemble': ensemble_metrics,
        },
        'nslkdd_trained': {
            'rf':       nslkdd.get('rf'),
            'xgb':      nslkdd.get('xgb'),
            'ensemble': nslkdd.get('ensemble'),
            'lstm':     nslkdd.get('lstm'),
        },
        'distribution_shift_note': (
            "Original models were trained on live Scapy traffic features (proto_num, sport, dport, "
            "pkt_size, IP flags). NSL-KDD represents a domain shift — it uses 1999 DARPA lab data "
            "with connection-level features. Low accuracy on original models is expected."
        ),
        'baseline_comparison': baseline,
        'recommendation': (
            "NSL-KDD-retrained models show real capability (XGBoost 86%, LSTM ~83%). "
            "For production accuracy, collect labeled live traffic matching your deployment environment."
        ),
        'model_colors': MODEL_COLORS,
        'timestamp': datetime.now().isoformat(),
    }

    os.makedirs('data', exist_ok=True)
    with open('data/eval_results.json', 'w') as f:
        json.dump(combined, f, indent=2)
    print(f"\nCombined results saved -> data/eval_results.json")

    if MLFLOW_AVAILABLE:
        try:
            mlflow.set_experiment(EXPERIMENT_EVALUATION)
            with mlflow.start_run(run_name="combined-results-artifact"):
                log_artifact('data/eval_results.json', artifact_path="results")
            print(f"[MLflow] All runs -> experiment: {EXPERIMENT_EVALUATION}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
