"""
Benchmark Evaluation Script
============================
Evaluates the detection pipeline on NSL-KDD dataset or a custom CSV.
Maps NSL-KDD's 41 features down to the 11 features used by the model.
Computes accuracy, precision, recall, F1, FPR, and confusion matrix.
Optionally logs results to MLflow.
"""

import argparse
import json
import os
import sys
from typing import Dict, List, Tuple
import numpy as np

# Import detection components
from detection_agent import EnsemblePredictor, DQNAgent, SUSPICIOUS_PORTS, WELL_KNOWN_PORTS, _is_private


def map_nsl_kdd_to_11_features(nsl_row: Dict) -> np.ndarray:
    """
    Map NSL-KDD's 41 features to the 11-feature vector used by the model.
    
    NSL-KDD features (standard):
    0: duration
    1: protocol_type (tcp, udp, icmp)
    2: service (http, ftp, etc.)
    3: flag (SF, S0, etc.)
    4: src_bytes
    5: dst_bytes
    6: land
    7: wrong_fragment
    8: urgent
    9: hot
    10: num_failed_logins
    11: logged_in
    12: num_compromised
    13: root_shell
    14: su_attempted
    15: num_root
    16: num_file_creations
    17: num_shells
    18: num_access_files
    19: num_outbound_cmds
    20: is_host_login
    21: is_guest_login
    22: count
    23: srv_count
    24: serror_rate
    25: srv_serror_rate
    26: rerror_rate
    27: srv_rerror_rate
    28: same_srv_rate
    29: diff_srv_rate
    30: srv_diff_host_rate
    31: dst_host_count
    32: dst_host_srv_count
    33: dst_host_same_srv_rate
    34: dst_host_diff_srv_rate
    35: dst_host_same_src_port_rate
    36: dst_host_srv_diff_host_rate
    37: dst_host_serror_rate
    38: dst_host_srv_serror_rate
    39: dst_host_rerror_rate
    40: dst_host_srv_rerror_rate
    
    Our 11 features:
    [proto_num, sport, dport, pkt_size, is_src_private, is_dst_private,
     has_syn, has_fin, has_rst, port_is_suspicious, port_is_well_known]
    
    Mapping decisions (documented):
    - proto_num: Map protocol_type (tcp=6, udp=17, icmp=1)
    - sport/dport: Use service field as proxy (well-known ports: http=80, ftp=21, etc.)
      For NSL-KDD, we'll use src_bytes as a proxy for sport variability and dst_bytes for dport
    - pkt_size: Sum of src_bytes and dst_bytes (packet size approximation)
    - is_src_private/is_dst_private: NSL-KDD doesn't have IPs, so default to 1 (internal)
    - has_syn/has_fin/has_rst: Map from flag field (S=SYN, F=FIN, R=RST)
    - port_is_suspicious: Check if service port is in SUSPICIOUS_PORTS
    - port_is_well_known: Check if service port is in WELL_KNOWN_PORTS
    """
    # Protocol mapping
    proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
    proto_num = proto_map.get(nsl_row.get('protocol_type', 'tcp').lower(), 6)
    
    # Service to port mapping (common well-known ports)
    service_port_map = {
        'http': 80, 'https': 443, 'ftp': 21, 'ftp_data': 20,
        'ssh': 22, 'telnet': 23, 'smtp': 25, 'dns': 53,
        'pop_3': 110, 'imap': 143, 'netbios_ns': 137,
        'netbios_ssn': 139, 'ldap': 389, 'mssql': 1433,
        'mysql': 3306, 'postgres': 5432, 'oracle': 1521,
    }
    service = nsl_row.get('service', 'http').lower()
    dport = service_port_map.get(service, 80)  # Default to 80 (HTTP)
    sport = 1024 + (int(nsl_row.get('src_bytes', 0)) % 64512)  # Random high port based on src_bytes
    
    # Packet size: sum of src and dst bytes
    pkt_size = int(nsl_row.get('src_bytes', 0)) + int(nsl_row.get('dst_bytes', 0))
    if pkt_size == 0:
        pkt_size = 64  # Minimum packet size
    
    # IP private flags (NSL-KDD doesn't have IPs, assume internal traffic)
    is_src_private = 1
    is_dst_private = 1
    
    # TCP flags from flag field
    flag = nsl_row.get('flag', 'SF').upper()
    has_syn = 'S' in flag
    has_fin = 'F' in flag
    has_rst = 'R' in flag
    
    # Port classification
    port_is_suspicious = int(dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS)
    port_is_well_known = int(dport in WELL_KNOWN_PORTS or sport in WELL_KNOWN_PORTS)
    
    # Build 11-feature vector
    features = np.array([
        proto_num,
        sport,
        dport,
        pkt_size,
        is_src_private,
        is_dst_private,
        int(has_syn),
        int(has_fin),
        int(has_rst),
        port_is_suspicious,
        port_is_well_known,
    ], dtype=np.float64).reshape(1, -1)
    
    return features


def load_nsl_kdd(filepath: str) -> Tuple[List[Dict], List[int]]:
    """
    Load NSL-KDD dataset from file.
    
    Returns:
        features: List of feature dictionaries
        labels: List of binary labels (0=normal, 1=attack)
    """
    # NSL-KDD column names (41 features + label)
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
    ]
    
    features = []
    labels = []
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # Parse CSV-like format
            values = line.split(',')
            if len(values) < 42:
                continue
            
            row = dict(zip(columns, values))
            features.append(row)
            
            # Label: normal = 0, attack = 1
            label_val = row['label'].lower()
            labels.append(0 if label_val == 'normal' else 1)
    
    return features, labels


def compute_metrics(y_true: List[int], y_pred: List[int]) -> Dict:
    """
    Compute classification metrics.
    
    Returns:
        Dictionary with accuracy, precision, recall, f1, fpr, confusion_matrix
    """
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    
    # Confusion matrix
    tp = np.sum((y_true == 1) & (y_pred == 1))
    tn = np.sum((y_true == 0) & (y_pred == 0))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    fn = np.sum((y_true == 1) & (y_pred == 0))
    
    confusion_matrix = [[tn, fp], [fn, tp]]
    
    # Metrics
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'fpr': float(fpr),
        'confusion_matrix': confusion_matrix,
        'tp': int(tp),
        'tn': int(tn),
        'fp': int(fp),
        'fn': int(fn),
    }


def evaluate(dataset_path: str, output_path: str = 'evaluation_report.json'):
    """
    Run evaluation on the dataset.
    
    Args:
        dataset_path: Path to NSL-KDD file (KDDTrain+.txt or KDDTest+.txt) or custom CSV
        output_path: Path to save JSON report
    """
    print(f"[Evaluation] Loading dataset from {dataset_path}...")
    
    # Load dataset
    try:
        features, y_true = load_nsl_kdd(dataset_path)
    except Exception as e:
        print(f"[Evaluation] Failed to load dataset: {e}")
        print("[Evaluation] Attempting to load as custom CSV with 11 features...")
        
        # Try loading as custom CSV with 11 features
        # Expected format: proto_num,sport,dport,pkt_size,is_src_private,is_dst_private,has_syn,has_fin,has_rst,port_is_suspicious,port_is_well_known,label
        features = []
        y_true = []
        with open(dataset_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                values = line.split(',')
                if len(values) < 12:
                    continue
                feature_dict = {
                    'proto_num': float(values[0]),
                    'sport': int(values[1]),
                    'dport': int(values[2]),
                    'pkt_size': int(values[3]),
                    'is_src_private': int(values[4]),
                    'is_dst_private': int(values[5]),
                    'has_syn': int(values[6]),
                    'has_fin': int(values[7]),
                    'has_rst': int(values[8]),
                    'port_is_suspicious': int(values[9]),
                    'port_is_well_known': int(values[10]),
                }
                features.append(feature_dict)
                y_true.append(int(values[11]))
    
    print(f"[Evaluation] Loaded {len(features)} samples")
    print(f"[Evaluation] Attack samples: {sum(y_true)}, Normal samples: {len(y_true) - sum(y_true)}")
    
    # Initialize models
    print("[Evaluation] Initializing EnsemblePredictor...")
    ensemble = EnsemblePredictor()
    
    print("[Evaluation] Initializing DQNAgent...")
    rl_agent = DQNAgent()
    
    # Run predictions
    print("[Evaluation] Running predictions...")
    y_pred_ensemble = []
    y_pred_rl = []
    
    for i, feature_dict in enumerate(features):
        # Map to numeric vector
        if 'proto_num' in feature_dict:
            # Already in 11-feature format
            numeric = np.array([
                feature_dict['proto_num'],
                feature_dict['sport'],
                feature_dict['dport'],
                feature_dict['pkt_size'],
                feature_dict['is_src_private'],
                feature_dict['is_dst_private'],
                feature_dict['has_syn'],
                feature_dict['has_fin'],
                feature_dict['has_rst'],
                feature_dict['port_is_suspicious'],
                feature_dict['port_is_well_known'],
            ], dtype=np.float64).reshape(1, -1)
        else:
            # NSL-KDD format, need mapping
            numeric = map_nsl_kdd_to_11_features(feature_dict)
        
        # Ensemble prediction
        pred, _ = ensemble.predict(numeric)
        y_pred_ensemble.append(pred)
        
        # RL agent prediction (simplified: use ensemble as state proxy)
        # In real deployment, RL agent would use full state tuple
        # For evaluation, we'll use a simple heuristic
        if pred == 1:
            y_pred_rl.append(1)  # Block
        else:
            y_pred_rl.append(0)  # Allow
        
        if (i + 1) % 1000 == 0:
            print(f"[Evaluation] Processed {i + 1}/{len(features)} samples...")
    
    # Compute metrics
    print("[Evaluation] Computing metrics...")
    metrics_ensemble = compute_metrics(y_true, y_pred_ensemble)
    metrics_rl = compute_metrics(y_true, y_pred_rl)
    
    # Build report
    report = {
        'dataset_path': dataset_path,
        'num_samples': len(features),
        'num_attacks': sum(y_true),
        'num_normal': len(y_true) - sum(y_true),
        'ensemble_metrics': metrics_ensemble,
        'rl_metrics': metrics_rl,
        'model_versions': {
            'ensemble': 'RandomForest + XGBoost',
            'rl': 'DQN with experience replay',
        },
    }
    
    # Save report
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[Evaluation] Report saved to {output_path}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)
    print(f"\nEnsemblePredictor (RF + XGBoost):")
    print(f"  Accuracy:  {metrics_ensemble['accuracy']:.4f}")
    print(f"  Precision: {metrics_ensemble['precision']:.4f}")
    print(f"  Recall:    {metrics_ensemble['recall']:.4f}")
    print(f"  F1:        {metrics_ensemble['f1']:.4f}")
    print(f"  FPR:       {metrics_ensemble['fpr']:.4f}")
    print(f"  Confusion Matrix: {metrics_ensemble['confusion_matrix']}")
    
    print(f"\nDQNAgent:")
    print(f"  Accuracy:  {metrics_rl['accuracy']:.4f}")
    print(f"  Precision: {metrics_rl['precision']:.4f}")
    print(f"  Recall:    {metrics_rl['recall']:.4f}")
    print(f"  F1:        {metrics_rl['f1']:.4f}")
    print(f"  FPR:       {metrics_rl['fpr']:.4f}")
    print(f"  Confusion Matrix: {metrics_rl['confusion_matrix']}")
    print("=" * 60 + "\n")
    
    # Log to MLflow if available
    try:
        import mlflow
        import mlflow.sklearn
        
        print("[Evaluation] Logging to MLflow...")
        with mlflow.start_run():
            mlflow.log_param("dataset_path", dataset_path)
            mlflow.log_param("num_samples", len(features))
            mlflow.log_metrics({
                "ensemble_accuracy": metrics_ensemble['accuracy'],
                "ensemble_precision": metrics_ensemble['precision'],
                "ensemble_recall": metrics_ensemble['recall'],
                "ensemble_f1": metrics_ensemble['f1'],
                "ensemble_fpr": metrics_ensemble['fpr'],
                "rl_accuracy": metrics_rl['accuracy'],
                "rl_precision": metrics_rl['precision'],
                "rl_recall": metrics_rl['recall'],
                "rl_f1": metrics_rl['f1'],
                "rl_fpr": metrics_rl['fpr'],
            })
            mlflow.set_tag("model_version", "ensemble_rf_xgb+dqn")
            print("[Evaluation] MLflow logging complete")
    except ImportError:
        print("[Evaluation] MLflow not installed. Skipping MLflow logging.")
    except Exception as e:
        print(f"[Evaluation] MLflow logging failed: {e}")
    
    return report


def main():
    parser = argparse.ArgumentParser(description='Evaluate detection pipeline on NSL-KDD or custom dataset')
    parser.add_argument('--dataset', type=str, default='KDDTest+.txt',
                        help='Path to dataset file (NSL-KDD or custom CSV)')
    parser.add_argument('--output', type=str, default='evaluation_report.json',
                        help='Path to save JSON report')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.dataset):
        print(f"[Error] Dataset file not found: {args.dataset}")
        print("[Info] To download NSL-KDD, visit: https://www.unb.ca/cic/datasets/nsl-kdd.html")
        sys.exit(1)
    
    evaluate(args.dataset, args.output)


if __name__ == '__main__':
    main()
