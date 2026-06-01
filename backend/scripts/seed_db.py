"""
Seed Model Generator
====================
Generates a small synthetic RF model that can bootstrap federated learning
before any real traffic has been observed.

Usage:
    python seed_model.py
"""

import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier


def main():
    rng = np.random.RandomState(42)
    n_samples = 200
    n_features = 11  # matches the 11-feature vector used by TrafficClassifier

    # --- synthetic feature matrix ---
    # [proto, sport, dport, pkt_size, is_src_private, is_dst_private,
    #  has_syn, has_fin, has_rst, port_is_suspicious, port_is_well_known]
    X = rng.randn(n_samples, n_features)

    # Make features more realistic
    X[:, 0] = rng.choice([6, 17, 1], size=n_samples)          # protocol num
    X[:, 1] = rng.randint(1024, 65535, size=n_samples)         # sport
    X[:, 2] = rng.choice([80, 443, 53, 22, 4444, 5555, 8080], size=n_samples)  # dport
    X[:, 3] = rng.randint(40, 10000, size=n_samples)           # pkt_size
    X[:, 4] = rng.choice([0, 1], size=n_samples)               # is_src_private
    X[:, 5] = rng.choice([0, 1], size=n_samples)               # is_dst_private
    X[:, 6] = rng.choice([0, 1], size=n_samples, p=[0.7, 0.3]) # has_syn
    X[:, 7] = rng.choice([0, 1], size=n_samples, p=[0.9, 0.1]) # has_fin
    X[:, 8] = rng.choice([0, 1], size=n_samples, p=[0.9, 0.1]) # has_rst
    X[:, 9] = rng.choice([0, 1], size=n_samples, p=[0.8, 0.2]) # port_is_suspicious
    X[:, 10] = rng.choice([0, 1], size=n_samples, p=[0.5, 0.5]) # port_is_well_known

    # Labels: first half benign, second half threat
    y = np.array([0] * (n_samples // 2) + [1] * (n_samples // 2))

    # Shuffle
    perm = rng.permutation(n_samples)
    X = X[perm]
    y = y[perm]

    # Train
    clf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
    clf.fit(X, y)

    # Save
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rf_model_seed.pkl")
    with open(out_path, "wb") as f:
        pickle.dump({
            "model": clf,
            "X_buffer": X.tolist(),
            "y_buffer": y.tolist(),
        }, f)

    print(f"[seed_model] Saved seed model to {out_path}")
    print(f"[seed_model] {n_samples} samples, {n_features} features, "
          f"{clf.n_estimators} estimators")


if __name__ == "__main__":
    main()
