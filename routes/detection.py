"""Detection agent, response agent, visualization, and security-chat endpoints."""

import base64
import io

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from db.client import supabase
from services import detection_agent, response_agent
from agents.security_agent import run_agent

detection_bp = Blueprint('detection', __name__)


# --- Detection Agent API Endpoints ---

@detection_bp.route('/api/agent/start', methods=['POST'])
@jwt_required()
def start_agent():
    """Start the detection agent."""
    data = request.get_json() or {}
    use_simulation = data.get('simulation', True)
    interface = data.get('interface', None)
    result = detection_agent.start(interface=interface, use_simulation=use_simulation)
    return jsonify(result)


@detection_bp.route('/api/agent/stop', methods=['POST'])
@jwt_required()
def stop_agent():
    """Stop the detection agent."""
    result = detection_agent.stop()
    return jsonify(result)


@detection_bp.route('/api/agent/status', methods=['GET'])
@jwt_required()
def agent_status():
    """Get detection agent status and RL stats."""
    status = detection_agent.get_status()
    status["response_stats"] = response_agent.get_status() if response_agent else None
    return jsonify(status)


@detection_bp.route('/api/agent/detections', methods=['GET'])
@jwt_required()
def agent_detections():
    """Get recent detections from the agent."""
    limit = request.args.get('limit', 50, type=int)
    detections = detection_agent.get_recent_detections(limit=limit)
    return jsonify({'detections': detections})


@detection_bp.route('/api/agent/qtable', methods=['GET'])
@jwt_required()
def agent_qtable():
    """Get Q-table summary."""
    summary = detection_agent.rl_agent.get_q_table_summary()
    stats = detection_agent.rl_agent.get_stats()
    return jsonify({'q_table': summary, 'stats': stats})


@detection_bp.route('/api/agent/detections/history', methods=['GET'])
@jwt_required()
def agent_detection_history():
    """Get detection history from database with pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (page - 1) * per_page

    try:
        query = supabase.table('detection_logs').select('*', count='exact')
        result = query.order('timestamp', desc=True).range(offset, offset + per_page - 1).execute()

        return jsonify({
            'detections': result.data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': result.count if hasattr(result, 'count') else len(result.data),
                'pages': ((result.count if hasattr(result, 'count') else len(result.data)) + per_page - 1) // per_page,
            }
        })
    except Exception as e:
        print(f"Error in agent_detection_history: {e}")
        return jsonify({'detections': [], 'pagination': {'page': 1, 'per_page': per_page, 'total': 0, 'pages': 0}}), 500


# --- Response Agent API Endpoints ---

@detection_bp.route('/api/response/status', methods=['GET'])
@jwt_required()
def response_status():
    """Get response agent status."""
    return jsonify(response_agent.get_status())


@detection_bp.route('/api/response/history', methods=['GET'])
@jwt_required()
def response_history():
    """Get response action history from database."""
    try:
        result = supabase.table('response_actions').select('*').order('timestamp', desc=True).limit(50).execute()
        return jsonify({'history': result.data})
    except Exception as e:
        print(f"Error in response_history: {e}")
        return jsonify({'history': [], 'error': str(e)}), 500


@detection_bp.route('/api/response/rollback/<action_id>', methods=['POST'])
@jwt_required()
def response_rollback(action_id):
    """Rollback a response action."""
    success = response_agent.rollback(action_id)
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Action not found or already reversed'}), 404


@detection_bp.route('/api/response/unblock', methods=['POST'])
@jwt_required()
def response_unblock():
    """Manually unblock an IP."""
    data = request.get_json() or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'success': False, 'error': 'IP address required'}), 400
    response_agent._auto_unblock(ip, 'manual_unblock')
    return jsonify({'success': True, 'ip': ip})


@detection_bp.route('/api/response/fp-tracker', methods=['GET'])
@jwt_required()
def response_fp_tracker():
    """Get false positive tracker data."""
    result = {}
    for ip, readings in response_agent.fp_tracker.items():
        avg = sum(readings) / len(readings) if readings else 0
        result[ip] = {
            'ip': ip,
            'readings': readings,
            'average': round(avg, 4),
            'likely_false_positive': avg < 0.4 and len(readings) > 5,
        }
    return jsonify(result)


# =====================================================================
# VISUALIZATION ENDPOINT (matplotlib + seaborn)
# =====================================================================

def _fig_to_base64(fig):
    """Convert a matplotlib figure to a base64-encoded PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=120, bbox_inches='tight',
                facecolor='#0d1117', edgecolor='none')
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()
    return encoded


@detection_bp.route('/api/agent/visualizations', methods=['GET'])
@jwt_required()
def agent_visualizations():
    """Generate matplotlib/seaborn visualization charts from live detection data."""
    import logging
    logger = logging.getLogger(__name__)

    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import seaborn as sns
    except ImportError as e:
        logger.error(f"Visualization import failed: {e}")
        return jsonify({"error": f"Missing dependency: {e}", "charts": []}), 500

    # Dark theme
    try:
        plt.rcParams.update({
            'figure.facecolor': '#0d1117',
            'axes.facecolor': '#161b22',
            'axes.edgecolor': '#30363d',
            'axes.labelcolor': '#c9d1d9',
            'text.color': '#c9d1d9',
            'xtick.color': '#8b949e',
            'ytick.color': '#8b949e',
            'grid.color': '#21262d',
            'legend.facecolor': '#161b22',
            'legend.edgecolor': '#30363d',
        })
    except Exception as e:
        logger.warning(f"Could not set plot style: {e}")

    try:
        with detection_agent._lock:
            dets = list(detection_agent.detections)
    except Exception as e:
        logger.error(f"Failed to fetch detections: {e}")
        return jsonify({"error": f"Failed to fetch detections: {str(e)}", "charts": []}), 500

    if not dets:
        logger.info("No detections available for visualization")
        return jsonify({"charts": [], "message": "No detections yet - start the detection agent first"})

    charts = []

    # --- 1. Confidence Distribution (attack vs normal) ---
    try:
        attack_confs = [d['rf_confidence'] for d in dets if d['is_malicious']]
        normal_confs = [d['rf_confidence'] for d in dets if not d['is_malicious']]

        fig, ax = plt.subplots(figsize=(6, 3.5))
        if normal_confs:
            sns.kdeplot(normal_confs, ax=ax, color='#00ff7f', fill=True, alpha=0.3, label='Normal', bw_adjust=0.8)
        if attack_confs:
            sns.kdeplot(attack_confs, ax=ax, color='#ff4444', fill=True, alpha=0.3, label='Attack', bw_adjust=0.8)
        ax.set_xlabel('RF Confidence')
        ax.set_ylabel('Density')
        ax.set_title('Confidence Distribution: Attack vs Normal')
        ax.legend()
        ax.set_xlim(0, 1)
        charts.append({"title": "Confidence Distribution", "image": _fig_to_base64(fig)})
        plt.close(fig)
        logger.info("Generated Confidence Distribution chart")
    except Exception as e:
        logger.warning(f"Confidence Distribution chart failed: {e}")

    # --- 2. Attack Timeline ---
    try:
        window = 20
        labels_binary = [1 if d['is_malicious'] else 0 for d in dets]
        if len(labels_binary) >= window:
            rolling = []
            for i in range(len(labels_binary) - window + 1):
                rolling.append(sum(labels_binary[i:i + window]) / window * 100)

            fig, ax = plt.subplots(figsize=(6, 3.5))
            ax.plot(rolling, color='#ff4444', linewidth=1.5)
            ax.fill_between(range(len(rolling)), rolling, alpha=0.15, color='#ff4444')
            ax.axhline(y=30, color='#f0883e', linestyle='--', alpha=0.5, label='30% threshold')
            ax.set_xlabel('Detection Window')
            ax.set_ylabel('Attack Rate (%)')
            ax.set_title(f'Attack Rate (rolling {window}-packet window)')
            ax.legend()
            ax.set_ylim(0, 100)
            charts.append({"title": "Attack Timeline", "image": _fig_to_base64(fig)})
            plt.close(fig)
            logger.info("Generated Attack Timeline chart")
    except Exception as e:
        logger.warning(f"Attack Timeline chart failed: {e}")

    # --- 3. Protocol Breakdown (pie) ---
    try:
        from collections import Counter
        proto_counts = Counter(d['protocol'] for d in dets)
        labels_p = list(proto_counts.keys())
        sizes = list(proto_counts.values())
        colors_p = sns.color_palette("Set2", len(labels_p))

        fig, ax = plt.subplots(figsize=(5, 4))
        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels_p, autopct='%1.0f%%',
            colors=colors_p, textprops={'color': '#c9d1d9', 'fontsize': 9},
            startangle=90,
        )
        for t in autotexts:
            t.set_fontsize(8)
        ax.set_title('Protocol Distribution')
        charts.append({"title": "Protocol Distribution", "image": _fig_to_base64(fig)})
        plt.close(fig)
        logger.info("Generated Protocol Distribution chart")
    except Exception as e:
        logger.warning(f"Protocol Distribution chart failed: {e}")

    # --- 4. Response Action Distribution (bar) ---
    try:
        from collections import Counter
        ra_counts = Counter(d.get('response_action', 'none') for d in dets)
        labels_r = list(ra_counts.keys())
        values_r = list(ra_counts.values())
        color_map = {
            'hard_block': '#ff4444', 'rate_limit': '#f0883e',
            'quarantine': '#d29922', 'temp_block': '#a371f7',
            'allowed': '#00ff7f', 'already_blocked': '#8b949e',
            'none': '#484f58',
        }
        bar_colors = [color_map.get(l, '#58a6ff') for l in labels_r]

        fig, ax = plt.subplots(figsize=(6, 3.5))
        ax.bar(labels_r, values_r, color=bar_colors, edgecolor='#30363d', linewidth=0.5)
        ax.set_ylabel('Count')
        ax.set_title('Response Action Distribution')
        plt.xticks(rotation=30, ha='right', fontsize=8)
        charts.append({"title": "Response Actions", "image": _fig_to_base64(fig)})
        plt.close(fig)
        logger.info("Generated Response Actions chart")
    except Exception as e:
        logger.warning(f"Response Actions chart failed: {e}")

    # --- 5. RL Reward Over Time ---
    try:
        rewards = [d['rl_reward'] for d in dets]
        if len(rewards) >= 10:
            cumulative = []
            s = 0
            for r in rewards:
                s += r
                cumulative.append(s)

            fig, ax = plt.subplots(figsize=(6, 3.5))
            ax.plot(cumulative, color='#58a6ff', linewidth=1.5, label='Cumulative Reward')
            ax.axhline(y=0, color='#8b949e', linestyle='--', alpha=0.4)
            ax.set_xlabel('Detection #')
            ax.set_ylabel('Cumulative Reward')
            ax.set_title('RL Agent Cumulative Reward')
            ax.legend()
            charts.append({"title": "RL Reward Trend", "image": _fig_to_base64(fig)})
            plt.close(fig)
            logger.info("Generated RL Reward Trend chart")
    except Exception as e:
        logger.warning(f"RL Reward Trend chart failed: {e}")

    # --- 6. Top Source IPs Heatmap ---
    try:
        from collections import Counter
        ip_attack = Counter(d['src_ip'] for d in dets if d['is_malicious'])
        top_ips = ip_attack.most_common(10)
        if top_ips:
            ip_labels = [ip for ip, _ in top_ips]
            ip_counts = [cnt for _, cnt in top_ips]

            fig, ax = plt.subplots(figsize=(6, 3.5))
            ax.barh(ip_labels[::-1], ip_counts[::-1], color='#ff4444', edgecolor='#30363d')
            ax.set_xlabel('Attack Count')
            ax.set_title('Top Attacker IPs')
            charts.append({"title": "Top Attacker IPs", "image": _fig_to_base64(fig)})
            plt.close(fig)
            logger.info("Generated Top Attacker IPs chart")
    except Exception as e:
        logger.warning(f"Top Attacker IPs chart failed: {e}")

    return jsonify({"charts": charts})


# --- Security Analyst Chat Agent ---

@detection_bp.route('/api/agent/chat', methods=['POST'])
@jwt_required()
def agent_chat():
    """Multi-turn security analyst agent with tool calling and conversation memory."""
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        session_id = data.get('session_id', 'default')
        if not message:
            return jsonify({'error': 'message is required'}), 400
        result = run_agent(message, session_id)
        return jsonify(result), 200
    except Exception as e:
        print(f"Error in agent_chat: {e}")
        return jsonify({'error': str(e)}), 500
