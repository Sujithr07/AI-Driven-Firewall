"""
train_model.py
==============
Downloads the NSL-KDD dataset, maps its features to the 11-dimensional
feature vector used by TrafficClassifier in detection_agent.py, trains a
RandomForestClassifier, and saves the model as rf_model.pkl.

Usage:
    python train_model.py
"""

import os
import pickle
import csv
import io
import urllib.request

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# ---------------------------------------------------------------------------
# Constants (must match detection_agent.py)
# ---------------------------------------------------------------------------

SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 12345, 65535, 8888, 9999}
WELL_KNOWN_PORTS = {80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 8080, 3306, 5432, 27017}

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rf_model.pkl")

# NSL-KDD dataset URLs (defcom17 mirror on GitHub)
TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
TEST_URL  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"

# Service name → port number mapping
SERVICE_TO_PORT = {
    "http": 80, "http_443": 443, "https": 443, "ssl": 443,
    "ftp": 21, "ftp_data": 20, "ssh": 22, "telnet": 23,
    "smtp": 25, "pop_3": 110, "imap4": 143,
    "domain": 53, "domain_u": 53, "dns": 53,
    "finger": 79, "auth": 113, "whois": 43,
    "sql_net": 1521, "mysql": 3306, "ldap": 389,
    "ntp_u": 123, "snmp": 161, "bgp": 179,
    "kerberos": 88, "klogin": 543, "kshell": 544,
    "netbios_ns": 137, "netbios_dgm": 138, "netbios_ssn": 139,
    "sunrpc": 111, "login": 513, "shell": 514, "exec": 512,
    "printer": 515, "nntp": 119, "courier": 530,
    "uucp": 540, "netstat": 15, "systat": 11,
    "echo": 7, "discard": 9, "daytime": 13, "chargen": 19,
    "time": 37, "hostnames": 101, "iso_tsap": 102,
    "csnet_ns": 105, "pop_2": 109, "supdup": 95,
    "gopher": 70, "rje": 77, "link": 87, "Z39_50": 210,
    "efs": 520, "ctf": 84, "mtp": 57, "name": 42,
    "remote_job": 71, "vmnet": 175, "pm_dump": 1071,
    "tftp_u": 69, "urp_i": 0, "red_i": 0, "ecr_i": 0,
    "eco_i": 0, "tim_i": 0, "urh_i": 0, "IRC": 194,
    "X11": 6000, "other": 0, "private": 0,
}

# Protocol name → IP protocol number
PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1}

# NSL-KDD flag field interpretation
SYN_FLAGS = {"S0", "S1", "S2", "S3", "SH", "RSTOS0"}
RST_FLAGS = {"REJ", "RSTO", "RSTOS0", "RSTR"}
FIN_FLAGS = {"SF"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def download_dataset(url):
    """Download dataset CSV from *url* and return a list of rows."""
    print(f"Downloading {url} ...")
    req = urllib.request.Request(url, headers={"User-Agent": "train_model.py"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read().decode("utf-8")
    reader = csv.reader(io.StringIO(data))
    rows = list(reader)
    print(f"  {len(rows)} rows downloaded.")
    return rows


def map_row_to_features(row):
    """
    Map one NSL-KDD row to the 11-feature vector expected by
    TrafficClassifier:

        [proto_num, sport, dport, pkt_size,
         is_src_private, is_dst_private,
         has_syn, has_fin, has_rst,
         port_is_suspicious, port_is_well_known]

    Returns (feature_list, label)  where label ∈ {0, 1}.
    """
    protocol_type = row[1].strip().lower()
    service       = row[2].strip().lower()
    flag          = row[3].strip()
    src_bytes     = float(row[4])
    dst_bytes     = float(row[5])

    proto_num = PROTO_MAP.get(protocol_type, 0)
    dport     = SERVICE_TO_PORT.get(service, 0)
    sport     = 0                       # not available in NSL-KDD
    pkt_size  = src_bytes + dst_bytes

    # Heuristic: attacks usually come from external sources
    label_str = row[41].strip().lower()
    is_attack = label_str != "normal"
    is_src_private = 0 if is_attack else 1
    is_dst_private = 1 if is_attack else 0

    has_syn = 1 if flag in SYN_FLAGS else 0
    has_fin = 1 if flag in FIN_FLAGS else 0
    has_rst = 1 if flag in RST_FLAGS else 0

    port_is_suspicious  = 1 if dport in SUSPICIOUS_PORTS  else 0
    port_is_well_known  = 1 if dport in WELL_KNOWN_PORTS  else 0

    features = [
        proto_num, sport, dport, pkt_size,
        is_src_private, is_dst_private,
        has_syn, has_fin, has_rst,
        port_is_suspicious, port_is_well_known,
    ]
    label = 0 if label_str == "normal" else 1
    return features, label


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # 1. Download -----------------------------------------------------------
    train_rows = download_dataset(TRAIN_URL)
    test_rows  = download_dataset(TEST_URL)

    # 2. Map features -------------------------------------------------------
    print("Mapping NSL-KDD features to 11-dim vector ...")
    X_train, y_train = [], []
    for row in train_rows:
        if len(row) < 42:
            continue
        feats, lbl = map_row_to_features(row)
        X_train.append(feats)
        y_train.append(lbl)

    X_test, y_test = [], []
    for row in test_rows:
        if len(row) < 42:
            continue
        feats, lbl = map_row_to_features(row)
        X_test.append(feats)
        y_test.append(lbl)

    X_train = np.array(X_train, dtype=np.float64)
    y_train = np.array(y_train)
    X_test  = np.array(X_test,  dtype=np.float64)
    y_test  = np.array(y_test)

    n_attack_tr = int(y_train.sum())
    n_attack_te = int(y_test.sum())
    print(f"Training set : {len(y_train)} samples  "
          f"({n_attack_tr} attack, {len(y_train) - n_attack_tr} normal)")
    print(f"Test set     : {len(y_test)} samples  "
          f"({n_attack_te} attack, {len(y_test) - n_attack_te} normal)")

    # 3. Train --------------------------------------------------------------
    print("\nTraining RandomForestClassifier (n_estimators=100, max_depth=15) ...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    # 4. Evaluate -----------------------------------------------------------
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nTest accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["normal", "attack"]))

    # 5. Save ---------------------------------------------------------------
    print(f"Saving model to {MODEL_PATH} ...")
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({
            "model": model,
            "X_buffer": [],
            "y_buffer": [],
        }, f)
    print("Done — model saved successfully.")


if __name__ == "__main__":
    main()
