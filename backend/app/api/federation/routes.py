"""Federated learning proxy endpoints."""

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
import requests as http_requests

from app.services import detection_agent, FL_SERVER_URL

federation_bp = Blueprint('federation', __name__)


@federation_bp.route('/api/fl/status', methods=['GET'])
@jwt_required()
def fl_local_status():
    """Get local FL client status and FL server status."""
    local_status = detection_agent.fl_client.get_status() if detection_agent.fl_client else None
    server_status = None
    try:
        resp = http_requests.get(f"{FL_SERVER_URL}/fl/status", timeout=3)
        resp.raise_for_status()
        server_status = resp.json()
    except Exception:
        server_status = None
    return jsonify({"local": local_status, "server": server_status})


@federation_bp.route('/api/fl/rounds', methods=['GET'])
@jwt_required()
def fl_rounds_proxy():
    """Proxy FL server rounds history."""
    try:
        resp = http_requests.get(f"{FL_SERVER_URL}/fl/rounds", timeout=3)
        resp.raise_for_status()
        return jsonify(resp.json())
    except Exception:
        return jsonify({"rounds": [], "error": "FL server unreachable"})
