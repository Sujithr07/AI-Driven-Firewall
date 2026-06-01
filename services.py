"""
Long-lived service singletons (detection agent, response agent, traffic
classifier) and the callbacks that wire them to persistence and SocketIO.

Importing this module constructs the agents and starts the response agent's
self-healing loop, mirroring the original startup behaviour of ``app.py``.
"""

import json
import os
import time

import requests as http_requests

from detection_agent import DetectionAgent, TrafficClassifier
from response_agent import ResponseAgent
from log_embedder import embedder
from extensions import socketio
from db.client import supabase
from db.models import _insert_detection_log

# Federated Learning config
FL_SERVER_URL = os.getenv("FL_SERVER_URL", "http://localhost:6000")

# Shared RF classifier instance used by the simulation endpoint
_traffic_classifier = TrafficClassifier()

# Track app start time to reset metrics on launch (milliseconds, to match timestamps)
APP_START_TIME = time.time() * 1000


# ---------------------------------------------------------------------------
# Agent callbacks
# ---------------------------------------------------------------------------

def _save_detection_to_db(detection):
    """Callback to persist detection agent results to SQLite."""
    try:
        _insert_detection_log({
            'timestamp': detection['timestamp'],
            'src_ip': detection['src_ip'],
            'dst_ip': detection['dst_ip'],
            'protocol': detection['protocol'],
            'sport': detection['sport'],
            'dport': detection['dport'],
            'size': detection['size'],
            'flags': detection.get('flags', ''),
            'rf_prediction': detection['rf_prediction'],
            'rf_confidence': detection['rf_confidence'],
            'rl_state': detection['rl_state'],
            'rl_action': detection['rl_action'],
            'rl_reward': detection['rl_reward'],
            'was_exploration': int(detection['was_exploration']),
            'is_malicious': int(detection['is_malicious']),
            'severity': detection['severity'],
            'reason': detection['reason'],
            'epsilon': detection['epsilon'],
            'response_action': detection.get('response_action', 'none'),
            'response_rule_type': detection.get('response_rule_type', 'none'),
        })
        embedder.add_logs([detection])
    except Exception as e:
        print(f"[DetectionAgent DB] Error saving detection: {e}")


def _emit_detection_via_socketio(detection):
    """Callback to emit detection events via SocketIO."""
    try:
        socketio.emit("new_detection", detection)
        if detection.get("severity") == "High":
            socketio.emit("high_severity_alert", {
                "src_ip": detection["src_ip"],
                "reason": detection["reason"],
                "timestamp": detection["timestamp"]
            })
    except Exception as e:
        print(f"[DetectionAgent SocketIO] Error emitting detection: {e}")


def _save_response_action_to_db(action_record):
    """Callback to persist response agent actions to the database."""
    try:
        supabase.table('response_actions').insert({
            'action_id': action_record.get('action_id', ''),
            'timestamp': action_record.get('timestamp', time.time()),
            'src_ip': action_record.get('ip', ''),
            'rule_type': action_record.get('rule_type', ''),
            'confidence': action_record.get('confidence', 0),
            'reason': action_record.get('reason', ''),
            'command': json.dumps(action_record.get('command', [])),
            'undo_command': json.dumps(action_record.get('undo_command', [])),
            'reversed': 1 if action_record.get('reversed', False) else 0,
            'reversed_at': action_record.get('reversed_at'),
            'dry_run': 1,
        }).execute()
    except Exception as e:
        print(f"[ResponseAgent DB] Error saving response action: {e}")


# ---------------------------------------------------------------------------
# Agent construction
# ---------------------------------------------------------------------------

response_agent = ResponseAgent(dry_run=True, db_callback=_save_response_action_to_db)
response_agent.start_self_healing()

# Health-check FL server before enabling federated learning
_fl_url = FL_SERVER_URL
try:
    _fl_resp = http_requests.get(f"{_fl_url}/health", timeout=3)
    if _fl_resp.status_code != 200:
        raise ConnectionError(f"HTTP {_fl_resp.status_code}")
    print(f"[FL] FL server reachable at {_fl_url}")
except Exception as _fl_err:
    print(f"WARNING: FL server not reachable at {_fl_url}. "
          f"Federated learning will be disabled. ({_fl_err})")
    _fl_url = None

detection_agent = DetectionAgent(
    db_callback=_save_detection_to_db,
    socketio_callback=_emit_detection_via_socketio,
    fl_server_url=_fl_url,
    client_id=os.getenv("FL_CLIENT_ID", None),
    response_agent=response_agent,
)
