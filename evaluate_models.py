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
        'precision': float(precision_score(y_true, y_pred, average='macro')),
        'recall': float(recall_score(y_true, y_pred, average='macro')),
        'f1_macro': float(f1_score(y_true, y_pred, average='macro')),
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
    return metrics


def print_summary_table(results):
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


def save_results(results):
    """Save results to JSON file."""
    os.makedirs('data', exist_ok=True)
    
    output = {
        'rf': results.get('rf'),
        'xgb': results.get('xgb'),
        'ensemble': results.get('ensemble'),
        'timestamp': datetime.now().isoformat()
    }
    
    output_path = 'data/eval_results.json'
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\nResults saved to {output_path}")


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
    
    # Evaluate models
    rf_metrics = evaluate_rf(X_test, y_test)
    xgb_metrics = evaluate_xgb(X_test, y_test)
    ensemble_metrics = evaluate_ensemble(X_test, y_test, rf_metrics, xgb_metrics)
    
    # Compile results
    results = {
        'RandomForest': rf_metrics,
        'XGBoost': xgb_metrics,
        'Ensemble': ensemble_metrics
    }
    
    # Print summary
    print_summary_table(results)
    
    # Save results
    save_results({
        'rf': rf_metrics,
        'xgb': xgb_metrics,
        'ensemble': ensemble_metrics
    })


if __name__ == "__main__":
    main()
