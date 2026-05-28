"""
Evaluate ML models on NSL-KDD dataset.
Loads KDDTrain+.txt and KDDTest+.txt, evaluates RF, XGBoost, and Ensemble models.
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

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

# Feature columns from NSL-KDD that match our needs
# We'll add a dummy feature to reach 11 features to match the model
FEATURE_COLUMNS = [
    'protocol_type',
    'service',
    'flag',
    'src_bytes',
    'dst_bytes',
    'land',
    'wrong_fragment',
    'urgent',
    'hot',
    'num_failed_logins',
    'duration'  # Using duration as the 11th feature (placeholder for sport)
]

# NSL-KDD column names (43 columns total)
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
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

_CM_LABELS = ["normal", "attack"]


def load_data():
    """Load NSL-KDD train and test data."""
    print("Loading NSL-KDD dataset...")

    train_path = "data/KDDTrain+.txt"
    test_path = "data/KDDTest+.txt"

    if not os.path.exists(train_path) or not os.path.exists(test_path):
        raise FileNotFoundError("NSL-KDD data files not found in data/ folder. Run download_nslkdd.py first.")

    # Load data with no header (NSL-KDD files don't have headers)
    train_df = pd.read_csv(train_path, names=KDD_COLUMNS, header=None)
    test_df = pd.read_csv(test_path, names=KDD_COLUMNS, header=None)

    print(f"Train samples: {len(train_df)}, Test samples: {len(test_df)}")
    return train_df, test_df


def preprocess_data(df, label_encoders=None, fit=True):
    """
    Preprocess data: select features, encode labels, encode categorical features.

    Args:
        df: DataFrame with raw KDD data
        label_encoders: dict of fitted LabelEncoders (if fit=False)
        fit: whether to fit encoders or use existing ones

    Returns:
        X: feature matrix
        y: binary labels (0=normal, 1=attack)
        label_encoders: dict of LabelEncoders
    """
    # Select feature columns
    X_raw = df[FEATURE_COLUMNS].copy()

    # Binary classification: normal=0, attack=1
    y = df['label'].apply(lambda x: 0 if x == 'normal' else 1).values

    # Encode categorical features (protocol_type, service, flag)
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
            # Handle unseen categories by mapping to a known value
            X_raw[col] = X_raw[col].astype(str)
            unseen_mask = ~X_raw[col].isin(le.classes_)
            X_raw.loc[unseen_mask, col] = le.classes_[0]  # Map unseen to first class
            X_raw[col] = le.transform(X_raw[col])

    # Convert to numpy array
    X = X_raw.values.astype(np.float64)

    return X, y, label_encoders


def compute_metrics(y_true, y_pred):
    """Compute classification metrics."""
    return {
        'accuracy': float(accuracy_score(y_true, y_pred)),
        'precision': float(precision_score(y_true, y_pred, average='macro', zero_division=0)),
        'recall': float(recall_score(y_true, y_pred, average='macro', zero_division=0)),
        'f1_macro': float(f1_score(y_true, y_pred, average='macro', zero_division=0)),
        'confusion_matrix': confusion_matrix(y_true, y_pred).tolist()
    }


def load_model(model_path):
    """Load a pickled model."""
    if not os.path.exists(model_path):
        print(f"Warning: {model_path} not found. Skipping this model.")
        return None

    with open(model_path, 'rb') as f:
        saved = pickle.load(f)

    # Handle both dict format and bare model
    if isinstance(saved, dict):
        return saved['model']
    return saved


def _mlflow_log_eval(run_name: str, model_path: str, params: dict, metrics: dict) -> None:
    """Log a single model evaluation run to MLflow (no-op if unavailable)."""
    if not MLFLOW_AVAILABLE:
        return
    try:
        mlflow.set_experiment(EXPERIMENT_EVALUATION)
        with mlflow.start_run(run_name=run_name):
            mlflow.set_tags({"evaluation_type": "original", "model_path": model_path})
            mlflow.log_params(params)
            mlflow.log_metrics({k: v for k, v in metrics.items() if isinstance(v, (int, float))})
            log_confusion_matrix(metrics["confusion_matrix"], _CM_LABELS)
            log_artifact(model_path, artifact_path="model")
    except Exception as e:
        print(f"[MLflow] Logging failed for {run_name}: {e}")


def evaluate_rf(X_test, y_test):
    """Evaluate RandomForest model."""
    print("\nEvaluating RandomForest...")
    model = load_model('rf_model_seed.pkl')

    if model is None:
        return None

    y_pred = model.predict(X_test)
    metrics = compute_metrics(y_test, y_pred)
    print(f"  Accuracy: {metrics['accuracy']:.4f}")
    print(f"  F1 (macro): {metrics['f1_macro']:.4f}")

    _mlflow_log_eval(
        run_name="rf-original-eval",
        model_path="rf_model_seed.pkl",
        params={"model": "RandomForest", "source": "original"},
        metrics=metrics,
    )
    return metrics


def evaluate_xgb(X_test, y_test):
    """Evaluate XGBoost model."""
    print("\nEvaluating XGBoost...")

    try:
        import xgboost as xgb
    except ImportError:
        print("  XGBoost not installed. Skipping.")
        return None

    model = load_model('xgb_model.pkl')

    if model is None:
        return None

    y_pred = model.predict(X_test)
    metrics = compute_metrics(y_test, y_pred)
    print(f"  Accuracy: {metrics['accuracy']:.4f}")
    print(f"  F1 (macro): {metrics['f1_macro']:.4f}")

    _mlflow_log_eval(
        run_name="xgb-original-eval",
        model_path="xgb_model.pkl",
        params={"model": "XGBoost", "source": "original"},
        metrics=metrics,
    )
    return metrics


def evaluate_ensemble(X_test, y_test, rf_metrics, xgb_metrics):
    """Evaluate ensemble by averaging probabilities."""
    print("\nEvaluating Ensemble...")

    if rf_metrics is None or xgb_metrics is None:
        print("  Skipping: one or both base models not available")
        return None

    rf_model = load_model('rf_model_seed.pkl')
    xgb_model = load_model('xgb_model.pkl')

    if rf_model is None or xgb_model is None:
        return None

    # Get probabilities
    rf_proba = rf_model.predict_proba(X_test)
    xgb_proba = xgb_model.predict_proba(X_test)

    # Average attack probabilities (class 1)
    rf_attack_prob = rf_proba[:, 1]
    xgb_attack_prob = xgb_proba[:, 1]
    avg_attack_prob = 0.5 * rf_attack_prob + 0.5 * xgb_attack_prob

    # Convert to predictions
    y_pred = (avg_attack_prob >= 0.5).astype(int)

    metrics = compute_metrics(y_test, y_pred)
    print(f"  Accuracy: {metrics['accuracy']:.4f}")
    print(f"  F1 (macro): {metrics['f1_macro']:.4f}")

    if MLFLOW_AVAILABLE:
        try:
            mlflow.set_experiment(EXPERIMENT_EVALUATION)
            with mlflow.start_run(run_name="ensemble-original-eval"):
                mlflow.set_tags({"evaluation_type": "original", "model": "Ensemble(RF+XGB)"})
                mlflow.log_params({"ensemble_weights": "0.5/0.5", "source": "original"})
                mlflow.log_metrics({k: v for k, v in metrics.items() if isinstance(v, (int, float))})
                log_confusion_matrix(metrics["confusion_matrix"], _CM_LABELS)
        except Exception as e:
            print(f"[MLflow] Ensemble logging failed: {e}")

    return metrics


def print_summary_table(results, baseline_info):
    """Print a clean summary table."""
    print("\n" + "="*70)
    print("EVALUATION SUMMARY")
    print("="*70)

    headers = ["Model", "Accuracy", "Precision", "Recall", "F1 (macro)"]
    rows = []

    for model_name, metrics in results.items():
        if metrics is None:
            rows.append([model_name, "N/A", "N/A", "N/A", "N/A"])
        else:
            rows.append([
                model_name,
                f"{metrics['accuracy']:.4f}",
                f"{metrics['precision']:.4f}",
                f"{metrics['recall']:.4f}",
                f"{metrics['f1_macro']:.4f}"
            ])

    # Print table
    col_widths = [max(len(h), max(len(str(r[i])) for r in rows)) + 4 for i, h in enumerate(headers)]

    # Header
    header_line = "".join(h.ljust(w) for h, w in zip(headers, col_widths))
    print(header_line)
    print("-" * len(header_line))

    # Rows
    for row in rows:
        line = "".join(str(val).ljust(w) for val, w in zip(row, col_widths))
        print(line)

    print("="*70)

    # Print baseline comparison
    print("\nBASELINE COMPARISON")
    print("-"*70)
    print(f"Majority class accuracy (always predict {baseline_info['majority_class']}): {baseline_info['majority_class_accuracy']:.4f}")
    print(f"Random accuracy baseline: {baseline_info['random_accuracy']:.4f}")
    print(f"Test distribution: {baseline_info['normal_samples']} normal, {baseline_info['attack_samples']} attack")

    # Print domain shift note
    print("\n" + "="*70)
    print("DOMAIN SHIFT NOTE")
    print("="*70)
    print("Original models were trained on live Scapy traffic features")
    print("(proto_num, sport, dport, pkt_size, IP flags).")
    print("NSL-KDD represents a domain shift - it uses 1999 DARPA lab data")
    print("with connection-level features (protocol_type, service, flag,")
    print("src_bytes, dst_bytes). Low accuracy is expected due to this")
    print("feature space mismatch.")
    print("="*70)
    print("\nRECOMMENDATION")
    print("-"*70)
    print("Retrain on NSL-KDD for in-distribution benchmark,")
    print("or collect labeled live traffic for true production evaluation")
    print("="*70)


def save_results(results, y_test):
    """Save results to JSON file."""
    os.makedirs('data', exist_ok=True)

    # Calculate baseline metrics
    total_samples = len(y_test)
    attack_count = sum(y_test == 1)
    normal_count = sum(y_test == 0)
    majority_class_accuracy = max(attack_count, normal_count) / total_samples

    output = {
        'rf': results.get('rf'),
        'xgb': results.get('xgb'),
        'ensemble': results.get('ensemble'),
        'timestamp': datetime.now().isoformat(),
        'distribution_shift_note': (
            "Original models were trained on live Scapy traffic features (proto_num, sport, dport, "
            "pkt_size, IP flags). NSL-KDD represents a domain shift - it uses 1999 DARPA lab data "
            "with connection-level features (protocol_type, service, flag, src_bytes, dst_bytes). "
            "Low accuracy is expected due to this feature space mismatch."
        ),
        'baseline_comparison': {
            'majority_class_accuracy': round(majority_class_accuracy, 4),
            'majority_class': 'attack' if attack_count > normal_count else 'normal',
            'random_accuracy': 0.5,
            'test_samples': total_samples,
            'attack_samples': int(attack_count),
            'normal_samples': int(normal_count)
        },
        'recommendation': (
            "Retrain on NSL-KDD for in-distribution benchmark, "
            "or collect labeled live traffic for true production evaluation"
        )
    }

    output_path = 'data/eval_results.json'
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to {output_path}")


def train_and_evaluate_nslkdd():
    """Train new models on NSL-KDD data and evaluate them."""
    print("\n" + "="*70)
    print("TRAINING NEW MODELS ON NSL-KDD DATA")
    print("="*70)

    # Load data
    train_df, test_df = load_data()

    # Preprocess
    print("\nPreprocessing data...")
    X_train, y_train, label_encoders = preprocess_data(train_df, fit=True)
    X_test, y_test, _ = preprocess_data(test_df, label_encoders=label_encoders, fit=False)

    print(f"Train shape: {X_train.shape}, Test shape: {X_test.shape}")
    print(f"Train distribution: Normal={sum(y_train==0)}, Attack={sum(y_train==1)}")
    print(f"Test distribution: Normal={sum(y_test==0)}, Attack={sum(y_test==1)}")

    n_estimators_rf  = 100
    max_depth_rf     = 15
    n_estimators_xgb = 100
    max_depth_xgb    = 10
    learning_rate    = 0.1

    # Train RandomForest on NSL-KDD
    print("\nTraining RandomForest on NSL-KDD...")
    rf_nslkdd_metrics = None
    rf_model = None
    if SKLEARN_AVAILABLE:
        rf_model = RandomForestClassifier(
            n_estimators=n_estimators_rf,
            max_depth=max_depth_rf,
            random_state=42,
            n_jobs=-1
        )
        rf_model.fit(X_train, y_train)
        y_pred_rf = rf_model.predict(X_test)
        rf_nslkdd_metrics = compute_metrics(y_test, y_pred_rf)
        print(f"  Accuracy: {rf_nslkdd_metrics['accuracy']:.4f}")
        print(f"  F1 (macro): {rf_nslkdd_metrics['f1_macro']:.4f}")

        # Save the NSL-KDD trained model
        os.makedirs('data', exist_ok=True)
        rf_nslkdd_path = 'data/rf_model_nslkdd.pkl'
        with open(rf_nslkdd_path, 'wb') as f:
            pickle.dump(rf_model, f)
        print(f"  Saved to {rf_nslkdd_path}")

        if MLFLOW_AVAILABLE:
            try:
                mlflow.set_experiment(EXPERIMENT_EVALUATION)
                with mlflow.start_run(run_name="rf-nslkdd-train-eval"):
                    mlflow.set_tags({"evaluation_type": "nslkdd_retrained", "model": "RandomForest"})
                    mlflow.log_params({
                        "n_estimators": n_estimators_rf,
                        "max_depth":    max_depth_rf,
                        "random_state": 42,
                        "dataset":      "NSL-KDD",
                        "train_samples": len(y_train),
                        "test_samples":  len(y_test),
                    })
                    mlflow.log_metrics({
                        k: v for k, v in rf_nslkdd_metrics.items()
                        if isinstance(v, (int, float))
                    })
                    log_confusion_matrix(rf_nslkdd_metrics["confusion_matrix"], _CM_LABELS)
                    log_feature_importance(rf_model, FEATURE_COLUMNS)
                    log_artifact(rf_nslkdd_path, artifact_path="model")
            except Exception as e:
                print(f"[MLflow] RF NSL-KDD logging failed: {e}")
    else:
        print("  Sklearn not available. Skipping.")

    # Train XGBoost on NSL-KDD
    print("\nTraining XGBoost on NSL-KDD...")
    xgb_nslkdd_metrics = None
    xgb_model = None
    if XGBOOST_AVAILABLE:
        xgb_model = xgb.XGBClassifier(
            n_estimators=n_estimators_xgb,
            max_depth=max_depth_xgb,
            learning_rate=learning_rate,
            use_label_encoder=False,
            eval_metric='logloss',
            random_state=42,
            n_jobs=-1,
            verbosity=0
        )
        xgb_model.fit(X_train, y_train)
        y_pred_xgb = xgb_model.predict(X_test)
        xgb_nslkdd_metrics = compute_metrics(y_test, y_pred_xgb)
        print(f"  Accuracy: {xgb_nslkdd_metrics['accuracy']:.4f}")
        print(f"  F1 (macro): {xgb_nslkdd_metrics['f1_macro']:.4f}")

        xgb_nslkdd_path = 'data/xgb_model_nslkdd.pkl'
        with open(xgb_nslkdd_path, 'wb') as f:
            pickle.dump(xgb_model, f)
        print(f"  Saved to {xgb_nslkdd_path}")

        if MLFLOW_AVAILABLE:
            try:
                mlflow.set_experiment(EXPERIMENT_EVALUATION)
                with mlflow.start_run(run_name="xgb-nslkdd-train-eval"):
                    mlflow.set_tags({"evaluation_type": "nslkdd_retrained", "model": "XGBoost"})
                    mlflow.log_params({
                        "n_estimators":  n_estimators_xgb,
                        "max_depth":     max_depth_xgb,
                        "learning_rate": learning_rate,
                        "eval_metric":   "logloss",
                        "dataset":       "NSL-KDD",
                        "train_samples": len(y_train),
                        "test_samples":  len(y_test),
                    })
                    mlflow.log_metrics({
                        k: v for k, v in xgb_nslkdd_metrics.items()
                        if isinstance(v, (int, float))
                    })
                    log_confusion_matrix(xgb_nslkdd_metrics["confusion_matrix"], _CM_LABELS)
                    log_artifact(xgb_nslkdd_path, artifact_path="model")
            except Exception as e:
                print(f"[MLflow] XGBoost NSL-KDD logging failed: {e}")
    else:
        print("  XGBoost not available. Skipping.")

    # Ensemble (average probabilities)
    print("\nEvaluating Ensemble (NSL-KDD trained)...")
    ensemble_nslkdd_metrics = None
    if rf_nslkdd_metrics is not None and xgb_nslkdd_metrics is not None:
        rf_proba = rf_model.predict_proba(X_test)
        xgb_proba = xgb_model.predict_proba(X_test)

        rf_attack_prob = rf_proba[:, 1]
        xgb_attack_prob = xgb_proba[:, 1]
        avg_attack_prob = 0.5 * rf_attack_prob + 0.5 * xgb_attack_prob

        y_pred_ensemble = (avg_attack_prob >= 0.5).astype(int)
        ensemble_nslkdd_metrics = compute_metrics(y_test, y_pred_ensemble)
        print(f"  Accuracy: {ensemble_nslkdd_metrics['accuracy']:.4f}")
        print(f"  F1 (macro): {ensemble_nslkdd_metrics['f1_macro']:.4f}")

        if MLFLOW_AVAILABLE:
            try:
                mlflow.set_experiment(EXPERIMENT_EVALUATION)
                with mlflow.start_run(run_name="ensemble-nslkdd-eval"):
                    mlflow.set_tags({"evaluation_type": "nslkdd_retrained", "model": "Ensemble(RF+XGB)"})
                    mlflow.log_params({"ensemble_weights": "0.5/0.5", "dataset": "NSL-KDD"})
                    mlflow.log_metrics({
                        k: v for k, v in ensemble_nslkdd_metrics.items()
                        if isinstance(v, (int, float))
                    })
                    log_confusion_matrix(ensemble_nslkdd_metrics["confusion_matrix"], _CM_LABELS)
            except Exception as e:
                print(f"[MLflow] Ensemble NSL-KDD logging failed: {e}")
    else:
        print("  Skipping: one or both models not available")

    # Calculate baseline info
    total_samples = len(y_test)
    attack_count = sum(y_test == 1)
    normal_count = sum(y_test == 0)
    baseline_info = {
        'majority_class_accuracy': max(attack_count, normal_count) / total_samples,
        'majority_class': 'attack' if attack_count > normal_count else 'normal',
        'random_accuracy': 0.5,
        'test_samples': total_samples,
        'attack_samples': int(attack_count),
        'normal_samples': int(normal_count)
    }

    # Print summary
    results = {
        'RandomForest (NSL-KDD)': rf_nslkdd_metrics,
        'XGBoost (NSL-KDD)': xgb_nslkdd_metrics,
        'Ensemble (NSL-KDD)': ensemble_nslkdd_metrics
    }
    print_summary_table(results, baseline_info)

    # Save NSL-KDD results
    nslkdd_output = {
        'rf_nslkdd': rf_nslkdd_metrics,
        'xgb_nslkdd': xgb_nslkdd_metrics,
        'ensemble_nslkdd': ensemble_nslkdd_metrics,
        'timestamp': datetime.now().isoformat(),
        'note': 'Models trained on NSL-KDD dataset - in-distribution evaluation',
        'baseline_comparison': baseline_info
    }

    with open('data/eval_results_nslkdd.json', 'w') as f:
        json.dump(nslkdd_output, f, indent=2)

    print(f"\nNSL-KDD results saved to data/eval_results_nslkdd.json")
    if MLFLOW_AVAILABLE:
        try:
            mlflow.set_experiment(EXPERIMENT_EVALUATION)
            with mlflow.start_run(run_name="nslkdd-results-artifact"):
                log_artifact('data/eval_results_nslkdd.json', artifact_path="results")
        except Exception:
            pass
    print("="*70)

    return nslkdd_output


def main():
    """Main evaluation pipeline."""
    print("="*70)
    print("NSL-KDD Model Evaluation")
    print("="*70)

    # Load data
    train_df, test_df = load_data()

    # Preprocess: fit encoders on training data
    print("\nPreprocessing data...")
    X_train, y_train, label_encoders = preprocess_data(train_df, fit=True)
    X_test, y_test, _ = preprocess_data(test_df, label_encoders=label_encoders, fit=False)

    print(f"Feature shape: {X_test.shape}")
    print(f"Test label distribution: Normal={sum(y_test==0)}, Attack={sum(y_test==1)}")

    # Evaluate models (each function logs its own MLflow run)
    rf_metrics = evaluate_rf(X_test, y_test)
    xgb_metrics = evaluate_xgb(X_test, y_test)
    ensemble_metrics = evaluate_ensemble(X_test, y_test, rf_metrics, xgb_metrics)

    # Compile results
    results = {
        'RandomForest': rf_metrics,
        'XGBoost': xgb_metrics,
        'Ensemble': ensemble_metrics
    }

    # Calculate baseline info
    total_samples = len(y_test)
    attack_count = sum(y_test == 1)
    normal_count = sum(y_test == 0)
    baseline_info = {
        'majority_class_accuracy': max(attack_count, normal_count) / total_samples,
        'majority_class': 'attack' if attack_count > normal_count else 'normal',
        'random_accuracy': 0.5,
        'test_samples': total_samples,
        'attack_samples': int(attack_count),
        'normal_samples': int(normal_count)
    }

    # Print summary
    print_summary_table(results, baseline_info)

    # Save results
    save_results({
        'rf': rf_metrics,
        'xgb': xgb_metrics,
        'ensemble': ensemble_metrics
    }, y_test)

    # Run NSL-KDD retrained evaluation
    print("\nRunning NSL-KDD retrained evaluation...")
    nslkdd_results = train_and_evaluate_nslkdd()

    # Save combined results file for API
    combined_output = {
        'original_models': {
            'rf': rf_metrics,
            'xgb': xgb_metrics,
            'ensemble': ensemble_metrics
        },
        'nslkdd_trained': {
            'rf': nslkdd_results.get('rf_nslkdd'),
            'xgb': nslkdd_results.get('xgb_nslkdd'),
            'ensemble': nslkdd_results.get('ensemble_nslkdd')
        },
        'distribution_shift_note': (
            "Original models were trained on live Scapy traffic features (proto_num, sport, dport, "
            "pkt_size, IP flags). NSL-KDD represents a domain shift - it uses 1999 DARPA lab data "
            "with connection-level features (protocol_type, service, flag, src_bytes, dst_bytes). "
            "Low accuracy is expected due to this feature space mismatch."
        ),
        'baseline_comparison': baseline_info,
        'recommendation': (
            "Retrain on NSL-KDD for in-distribution benchmark, "
            "or collect labeled live traffic for true production evaluation"
        ),
        'timestamp': datetime.now().isoformat()
    }

    with open('data/eval_results.json', 'w') as f:
        json.dump(combined_output, f, indent=2)

    print(f"\nCombined results saved to data/eval_results.json")

    if MLFLOW_AVAILABLE:
        try:
            mlflow.set_experiment(EXPERIMENT_EVALUATION)
            with mlflow.start_run(run_name="combined-results-artifact"):
                log_artifact('data/eval_results.json', artifact_path="results")
            print(f"[MLflow] All runs logged to experiment: {EXPERIMENT_EVALUATION}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
