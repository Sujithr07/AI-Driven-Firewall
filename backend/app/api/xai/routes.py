"""XAI (Explainable AI), threat-explanation, and model-evaluation endpoints."""

import json
import os

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from app.ml.detection import threat_explainer
from app.db.client import supabase
from app.core.extensions import socketio

xai_bp = Blueprint('xai', __name__)

SUSPICIOUS_PORTS_XAI = {4444, 1337, 31337, 6666, 6667, 6668, 6669, 8888, 9999, 2222, 1234, 12345}
WELL_KNOWN_PORTS_XAI = {80, 443, 22, 53, 25, 21, 110, 143, 3306, 5432, 8080, 8443}

_XAI_FEATURE_NAMES = [
    'proto_num', 'sport', 'dport', 'packet_size', 'src_is_private',
    'dst_is_private', 'has_syn', 'has_fin', 'has_rst',
    'port_is_suspicious', 'port_is_well_known',
]

from app.core.config import MODELS_DIR as _MODELS_DIR, DATA_DIR as _DATA_DIR


def _is_private_ip(ip):
    if not ip:
        return 0
    return 1 if (ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.')) else 0


def _reconstruct_features(d):
    """Reconstruct the 11 numeric features from a detection record."""
    protocol = (d.get('protocol') or '').upper()
    proto_num = 6 if protocol == 'TCP' else (17 if protocol == 'UDP' else (1 if protocol == 'ICMP' else 0))
    sport = int(d.get('sport') or 0)
    dport = int(d.get('dport') or 0)
    packet_size = int(d.get('size') or 0)
    src_is_private = _is_private_ip(d.get('src_ip'))
    dst_is_private = _is_private_ip(d.get('dst_ip'))
    flags = d.get('flags') or ''
    has_syn = 1 if ('S' in flags and 'A' not in flags) else 0
    has_fin = 1 if 'F' in flags else 0
    has_rst = 1 if 'R' in flags else 0
    port_is_suspicious = 1 if dport in SUSPICIOUS_PORTS_XAI else 0
    port_is_well_known = 1 if dport in WELL_KNOWN_PORTS_XAI else 0
    return {
        'proto_num': proto_num, 'sport': sport, 'dport': dport,
        'packet_size': packet_size, 'src_is_private': src_is_private,
        'dst_is_private': dst_is_private, 'has_syn': has_syn, 'has_fin': has_fin,
        'has_rst': has_rst, 'port_is_suspicious': port_is_suspicious,
        'port_is_well_known': port_is_well_known,
    }


def _rule_based_importance(feats):
    """Fallback importance when SHAP/model unavailable."""
    return {
        'port_is_suspicious': 0.35 if feats['port_is_suspicious'] == 1 else 0.0,
        'has_syn': 0.25 if feats['has_syn'] == 1 else 0.0,
        'src_is_private': -0.18 if feats['src_is_private'] == 1 else 0.08,
        'proto_num': 0.08 if feats['proto_num'] == 1 else 0.04,
        'packet_size': 0.12 if feats['packet_size'] > 8000 else 0.03,
        'port_is_well_known': -0.10 if feats['port_is_well_known'] == 1 else 0.05,
        'dport': 0.06,
        'sport': 0.02,
        'has_fin': 0.04 if feats['has_fin'] == 1 else 0.0,
        'has_rst': 0.07 if feats['has_rst'] == 1 else 0.0,
        'dst_is_private': 0.05,
    }


def _compute_counterfactual(d, feats):
    rf_pred = d.get('rf_prediction', '')
    if rf_pred == 'attack' and feats['port_is_suspicious'] == 1:
        return f"If port {feats['dport']} were a well-known port like 443, this packet would likely have been ALLOWED (port_suspicious contribution removed)"
    elif rf_pred == 'attack' and feats['has_syn'] == 1:
        return "If this packet had ACK set alongside SYN (normal handshake), the SYN scan signal would be removed and it would likely be ALLOWED"
    elif rf_pred == 'attack' and feats['src_is_private'] == 0:
        return f"If this packet had originated from a private internal IP instead of {d.get('src_ip', '?')}, the external threat signal would be removed"
    else:
        return "No clear single-feature counterfactual — this decision required multiple threat signals"


def _enrich_detection_xai(d):
    """Add SHAP values, top feature, and counterfactual to a detection dict."""
    feats = _reconstruct_features(d)
    feature_vector = [feats[name] for name in _XAI_FEATURE_NAMES]

    shap_values = None
    try:
        import pickle
        import numpy as np
        model_path = os.path.join(_MODELS_DIR, 'rf_model.pkl')
        with open(model_path, 'rb') as f:
            rf_model = pickle.load(f)
        import shap
        explainer = shap.TreeExplainer(rf_model)
        sv = explainer.shap_values(np.array([feature_vector]))
        # For binary classifier, shap_values may be a list of 2 arrays
        if isinstance(sv, list):
            vals = sv[1][0]  # class 1 (attack) contributions
        else:
            vals = sv[0]
        shap_values = {name: round(float(vals[i]), 4) for i, name in enumerate(_XAI_FEATURE_NAMES)}
    except Exception:
        shap_values = _rule_based_importance(feats)

    # Top feature
    top_feat = max(shap_values, key=lambda k: abs(shap_values[k]))
    top_contrib = shap_values[top_feat]

    d['shap_values'] = shap_values
    d['top_feature'] = top_feat
    d['top_feature_contribution'] = round(top_contrib, 4)
    d['counterfactual'] = _compute_counterfactual(d, feats)
    return d


@xai_bp.route('/api/xai/explain', methods=['GET'])
@jwt_required()
def xai_explain():
    """Return recent detections enriched with SHAP explanations."""
    limit = request.args.get('limit', 20, type=int)
    result = supabase.table('detection_logs').select('*').order('timestamp', desc=True).limit(limit).execute()
    detections = result.data or []
    enriched = [_enrich_detection_xai(d) for d in detections]
    return jsonify({"detections": enriched})


@xai_bp.route('/api/xai/feature-stats', methods=['GET'])
@jwt_required()
def xai_feature_stats():
    """Return average absolute SHAP-style importance across last 200 records."""
    result = supabase.table('detection_logs').select('*').order('timestamp', desc=True).limit(200).execute()
    records = result.data or []
    if not records:
        return jsonify({"averages": {}, "count": 0})

    totals = {name: 0.0 for name in _XAI_FEATURE_NAMES}
    for d in records:
        feats = _reconstruct_features(d)
        try:
            import pickle
            import numpy as np
            model_path = os.path.join(_MODELS_DIR, 'rf_model.pkl')
            with open(model_path, 'rb') as f:
                rf_model = pickle.load(f)
            import shap
            explainer = shap.TreeExplainer(rf_model)
            fv = [feats[name] for name in _XAI_FEATURE_NAMES]
            sv = explainer.shap_values(np.array([fv]))
            if isinstance(sv, list):
                vals = sv[1][0]
            else:
                vals = sv[0]
            sv_dict = {name: float(vals[i]) for i, name in enumerate(_XAI_FEATURE_NAMES)}
        except Exception:
            sv_dict = _rule_based_importance(feats)
        for name in _XAI_FEATURE_NAMES:
            totals[name] += abs(sv_dict[name])

    count = len(records)
    averages = {name: round(totals[name] / count, 4) for name in _XAI_FEATURE_NAMES}
    return jsonify({"averages": averages, "count": count})


@xai_bp.route('/api/explain-threat', methods=['POST'])
def explain_threat():
    """Generate AI-powered explanation for a threat detection event.
    Pass stream_id for real-time token streaming via llm_stream SocketIO events."""
    data = request.get_json()
    stream_id = data.get('stream_id')
    event = {
        'src_ip': data.get('src_ip', 'unknown'),
        'dst_ip': data.get('dst_ip', 'unknown'),
        'protocol': data.get('protocol', 'unknown'),
        'sport': data.get('sport', 'unknown'),
        'dport': data.get('dport', 'unknown'),
        'reason': data.get('reason', 'unknown'),
        'rf_confidence': data.get('rf_confidence', 'unknown'),
        'action': data.get('action', 'unknown'),
        'severity': data.get('severity', 'unknown'),
        'is_malicious': data.get('is_malicious', 'unknown'),
    }
    cache_key = (event['src_ip'], event['reason'], event['action'])
    is_cached = cache_key in threat_explainer._explanation_cache

    try:
        if stream_id:
            full_text = ''
            for token in threat_explainer.stream_explain_threat(event):
                full_text += token
                socketio.emit('llm_stream', {'stream_id': stream_id, 'token': token, 'done': False})
            socketio.emit('llm_stream', {'stream_id': stream_id, 'token': '', 'done': True})
            return jsonify({'explanation': full_text, 'cached': is_cached}), 200

        explanation = threat_explainer.explain_threat(event)
        return jsonify({'explanation': explanation, 'cached': is_cached}), 200

    except Exception as e:
        print(f"Error in explain_threat endpoint: {e}")
        fallback_msg = f"Unable to generate explanation. Threat: {event['reason']} from {event['src_ip']}."
        if stream_id:
            socketio.emit('llm_stream', {'stream_id': stream_id, 'token': fallback_msg, 'done': True})
        return jsonify({'explanation': fallback_msg, 'cached': False}), 200


@xai_bp.route('/api/eval-results', methods=['GET'])
def get_eval_results():
    """Get model evaluation results from data/eval_results.json."""
    eval_results_path = os.path.join(_DATA_DIR, 'eval_results.json')

    if not os.path.exists(eval_results_path):
        return jsonify({"status": "not_run"}), 200

    try:
        with open(eval_results_path, 'r') as f:
            data = json.load(f)
        return jsonify(data), 200
    except Exception as e:
        print(f"Error reading eval results: {e}")
