"""
Federated Learning Server
=========================
Standalone Flask app that orchestrates FedAvg aggregation across FL clients.
Runs on port 6000.
"""

import threading
import time
import logging
from datetime import datetime

import numpy as np
from flask import Flask, jsonify, request
from flask_cors import CORS

logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_client_updates = {}        # client_id -> {update, n_samples, timestamp}
_global_model = None         # latest aggregated weights dict
_global_model_version = 0
_global_model_timestamp = None
_round_number = 0
_round_history = []          # list of {round, timestamp, clients, total_samples}
MIN_CLIENTS = 2


# ---------------------------------------------------------------------------
# FedAvg aggregation
# ---------------------------------------------------------------------------

def _fedavg_aggregate():
    """
    Weighted-average aggregation (FedAvg).
    Each client contribution is weighted by n_samples / total_samples.
    """
    global _global_model, _global_model_version, _global_model_timestamp, _round_number, _client_updates

    with _lock:
        if not _client_updates:
            return

        updates = list(_client_updates.values())
        client_ids = list(_client_updates.keys())
        total_samples = sum(u["n_samples"] for u in updates)
        if total_samples == 0:
            return

        # Collect all keys from every client update
        all_keys = set()
        for u in updates:
            all_keys.update(u["update"].keys())

        aggregated = {}
        for key in all_keys:
            # Determine if values are lists or dicts
            sample_val = None
            for u in updates:
                if key in u["update"]:
                    sample_val = u["update"][key]
                    break
            if sample_val is None:
                continue

            if isinstance(sample_val, list):
                length = len(sample_val)
                result = np.zeros(length, dtype=np.float64)
                for u in updates:
                    vals = u["update"].get(key)
                    if vals is None:
                        continue
                    weight = u["n_samples"] / total_samples
                    arr = np.array(vals, dtype=np.float64)
                    if len(arr) == length:
                        result += weight * arr
                aggregated[key] = result.tolist()

            elif isinstance(sample_val, dict):
                sub_keys = set()
                for u in updates:
                    d = u["update"].get(key, {})
                    if isinstance(d, dict):
                        sub_keys.update(d.keys())
                result = {sk: 0.0 for sk in sub_keys}
                for u in updates:
                    d = u["update"].get(key, {})
                    if not isinstance(d, dict):
                        continue
                    weight = u["n_samples"] / total_samples
                    for sk in sub_keys:
                        result[sk] += weight * float(d.get(sk, 0.0))
                aggregated[key] = result

            else:
                # Scalar – weighted average
                total = 0.0
                for u in updates:
                    v = u["update"].get(key, 0)
                    weight = u["n_samples"] / total_samples
                    total += weight * float(v)
                aggregated[key] = total

        _round_number += 1
        _global_model_version += 1
        _global_model_timestamp = datetime.utcnow().isoformat()
        _global_model = aggregated

        _round_history.append({
            "round": _round_number,
            "timestamp": _global_model_timestamp,
            "clients": len(updates),
            "total_samples": total_samples,
            "client_ids": client_ids,
        })

        logger.info(
            "[FLServer] Aggregation round %d complete: %d clients, %d total samples",
            _round_number, len(updates), total_samples,
        )

        _client_updates = {}


# ---------------------------------------------------------------------------
# Background scheduler
# ---------------------------------------------------------------------------

def _scheduler_loop():
    """Triggers aggregation every 60 seconds regardless of client count."""
    while True:
        time.sleep(60)
        with _lock:
            if _client_updates:
                pass  # Release lock before aggregation
            else:
                continue
        _fedavg_aggregate()


_scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
_scheduler_thread.start()


# ---------------------------------------------------------------------------
# Flask endpoints
# ---------------------------------------------------------------------------

@app.route("/fl/submit_update", methods=["POST"])
def submit_update():
    """Accept a weight update from a client."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    client_id = data.get("client_id")
    update = data.get("update")
    n_samples = data.get("n_samples", 0)
    timestamp = data.get("timestamp", datetime.utcnow().isoformat())

    if not client_id or update is None:
        return jsonify({"error": "client_id and update are required"}), 400

    with _lock:
        _client_updates[client_id] = {
            "update": update,
            "n_samples": int(n_samples),
            "timestamp": timestamp,
        }
        n_waiting = len(_client_updates)

    # Trigger aggregation when enough clients have submitted
    if n_waiting >= MIN_CLIENTS:
        _fedavg_aggregate()

    return jsonify({"status": "accepted", "clients_waiting": n_waiting})


@app.route("/fl/global_model", methods=["GET"])
def global_model():
    """Return the latest aggregated global model."""
    with _lock:
        if _global_model is None:
            return jsonify({"weights": None, "version": 0, "timestamp": None})
        return jsonify({
            "weights": _global_model,
            "version": _global_model_version,
            "timestamp": _global_model_timestamp,
        })


@app.route("/fl/status", methods=["GET"])
def fl_status():
    """Return current FL server status."""
    with _lock:
        waiting_clients = []
        for cid, info in _client_updates.items():
            waiting_clients.append({
                "client_id": cid,
                "n_samples": info["n_samples"],
                "timestamp": info["timestamp"],
            })
        return jsonify({
            "round_number": _round_number,
            "clients_waiting": len(_client_updates),
            "min_clients": MIN_CLIENTS,
            "has_global_model": _global_model is not None,
            "global_model_version": _global_model_version,
            "recent_rounds": _round_history[-5:],
            "waiting_clients": waiting_clients,
        })


@app.route("/fl/rounds", methods=["GET"])
def fl_rounds():
    """Return the full round history."""
    with _lock:
        return jsonify({"rounds": list(_round_history)})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("=" * 60)
    print("FL SERVER running on http://127.0.0.1:6000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=6000, debug=False)
