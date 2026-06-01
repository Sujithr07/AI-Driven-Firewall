"""Log retrieval, integrity verification, export, RAG query, and embedding endpoints."""

import hashlib
import json as _json
import time
from datetime import datetime

from flask import Blueprint, Response, jsonify, request
from flask_jwt_extended import jwt_required

from app.rag import rag_agent
from app.rag.chain import stream_answer
from app.db.client import supabase
from app.db.models import _compute_entry_hash
from app.rag.log_embedder import embedder
from app.core.extensions import socketio

logs_bp = Blueprint('logs', __name__)


@logs_bp.route('/api/logs', methods=['GET'])
@jwt_required()
def get_logs():
    """Get immutable security logs with pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    severity_filter = request.args.get('severity', None)
    decision_filter = request.args.get('decision', None)

    offset = (page - 1) * per_page

    try:
        query = supabase.table('security_logs').select('*', count='exact')

        if severity_filter:
            query = query.eq('severity', severity_filter)

        if decision_filter:
            query = query.eq('decision', decision_filter)

        result = query.order('timestamp', desc=True).range(offset, offset + per_page - 1).execute()

        logs = result.data
        total = result.count if hasattr(result, 'count') else len(logs)

        return jsonify({
            'logs': logs,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page if total > 0 else 0
            }
        })
    except Exception as e:
        print(f"Error in get_logs: {e}")
        return jsonify({
            'logs': [],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': 0,
                'pages': 0
            },
            'error': str(e)
        }), 500


@logs_bp.route('/api/logs/verify', methods=['GET'])
@jwt_required()
def verify_log_chain():
    """Verify the SHA-256 hash chain of security_logs."""
    try:
        result = supabase.table('security_logs').select('*').order('id', desc=False).execute()
        rows = result.data

        if not rows:
            return jsonify({
                'chain_valid': True,
                'total_entries': 0,
                'tampered_entries': [],
                'first_tampered_id': None,
                'message': 'No logs yet — chain is clean',
                'verified_at': time.time(),
            })

        tampered = []
        prev_hash = 'GENESIS'

        for row in rows:
            if row.get('prev_hash') != prev_hash:
                tampered.append({'id': row['id'], 'reason': f"prev_hash mismatch: expected {prev_hash!r}, got {row.get('prev_hash')!r}"})

            expected = _compute_entry_hash(row, prev_hash)
            if expected != row.get('entry_hash'):
                tampered.append({'id': row['id'], 'reason': f"entry_hash mismatch: expected {expected!r}, got {row.get('entry_hash')!r}"})

            prev_hash = row['entry_hash'] if row.get('entry_hash') is not None else prev_hash

        return jsonify({
            'chain_valid': len(tampered) == 0,
            'total_entries': len(rows),
            'tampered_entries': tampered,
            'first_tampered_id': tampered[0]['id'] if tampered else None,
            'message': '✅ Chain intact — no tampering detected' if not tampered else f'⚠️ TAMPERING DETECTED in {len(tampered)} entries',
            'verified_at': time.time(),
        })
    except Exception as e:
        print(f"Error in verify_log_chain: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@logs_bp.route('/api/logs/export', methods=['GET'])
@jwt_required()
def export_audit_log():
    """Export all security logs as a signed JSON file."""
    try:
        result = supabase.table('security_logs').select('*').order('id', desc=False).execute()
        rows = result.data

        hash_concat = ''.join(r.get('entry_hash', '') for r in rows)
        master_hash = hashlib.sha256(hash_concat.encode('utf-8')).hexdigest()

        now = datetime.utcnow()
        export_data = {
            'exported_at': now.isoformat() + 'Z',
            'total_entries': len(rows),
            'master_hash': master_hash,
            'logs': rows,
        }

        filename = f"security_logs_{now.strftime('%Y%m%d_%H%M%S')}.json"
        return Response(
            _json.dumps(export_data, indent=2, default=str),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename={filename}'},
        )
    except Exception as e:
        print(f"Error in export_audit_log: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@logs_bp.route('/api/log-query', methods=['POST'])
@jwt_required()
def log_query():
    """Query logs using RAG with Gemini. Pass stream_id for real-time token streaming via llm_stream SocketIO events."""
    try:
        data = request.get_json()
        question = data.get('question', '')
        stream_id = data.get('stream_id')
        if not question:
            return jsonify({'error': 'Question is required'}), 400

        if stream_id:
            sources, token_gen = stream_answer(question)
            full_answer = ''
            for token in token_gen:
                full_answer += token
                socketio.emit('llm_stream', {'stream_id': stream_id, 'token': token, 'done': False})
            socketio.emit('llm_stream', {'stream_id': stream_id, 'token': '', 'done': True, 'sources': sources})
            return jsonify({'answer': full_answer, 'sources': sources, 'query': question}), 200

        result = rag_agent.answer_log_query(question)
        return jsonify(result), 200
    except Exception as e:
        print(f"Error in log_query: {e}")
        if stream_id:
            socketio.emit('llm_stream', {'stream_id': stream_id, 'token': '', 'done': True, 'error': str(e), 'sources': []})
        return jsonify({'error': str(e)}), 500


@logs_bp.route('/api/embed-existing-logs', methods=['POST'])
@jwt_required()
def embed_existing_logs():
    """Load recent detections from database and bulk-add them to the embedder."""
    try:
        # Load recent detection logs from database
        result = supabase.table('detection_logs').select('*').order('timestamp', desc=True).limit(500).execute()
        logs = result.data

        if not logs:
            return jsonify({'message': 'No logs found to embed'}), 200

        # Convert to format expected by embedder
        embed_logs = []
        for log in logs:
            embed_logs.append({
                'timestamp': log.get('timestamp', ''),
                'src_ip': log.get('src_ip', ''),
                'protocol': log.get('protocol', ''),
                'reason': log.get('reason', ''),
                'action': log.get('rl_action', ''),
                'severity': log.get('severity', '')
            })

        embedder.add_logs(embed_logs)

        # Save the index
        embedder.save()

        return jsonify({
            'message': f'Embedded {len(embed_logs)} logs',
            'count': len(embed_logs)
        }), 200
    except Exception as e:
        print(f"Error in embed_existing_logs: {e}")
        return jsonify({'error': str(e)}), 500
