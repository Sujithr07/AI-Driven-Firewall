"""Dashboard, metrics, network-traffic stats, and traffic simulation endpoints."""

import random
import time
from datetime import datetime

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.db.client import supabase
from app.db.models import _insert_security_log
from app.rag.log_embedder import embedder
from app.services import _traffic_classifier, APP_START_TIME

dashboard_bp = Blueprint('dashboard', __name__)

# In-memory cache for real-time data (for faster access)
LOG_DATABASE = []
MAX_LOG_ENTRIES = 100

# Traffic profiles - weighted for realistic distribution (more safe traffic, fewer threats)
TRAFFIC_PROFILES = [
    # Safe traffic (more common - 60% of traffic)
    { 'protocol': 'HTTPS', 'port': 443, 'size': 512, 'description': 'Standard secure web traffic.', 'threatModifier': -0.15, 'weight': 25 },
    { 'protocol': 'DNS', 'port': 53, 'size': 128, 'description': 'Standard domain name resolution.', 'threatModifier': -0.25, 'weight': 20 },
    { 'protocol': 'HTTPS', 'port': 443, 'size': 1024, 'description': 'Secure web browsing session.', 'threatModifier': -0.1, 'weight': 15 },
    { 'protocol': 'SSH', 'port': 22, 'size': 256, 'description': 'Secure shell connection attempt.', 'threatModifier': 0.05, 'weight': 10 },

    # Moderate risk (30% of traffic)
    { 'protocol': 'HTTP', 'port': 80, 'size': 2048, 'description': 'Standard web traffic (unencrypted).', 'threatModifier': 0.15, 'weight': 8 },
    { 'protocol': 'RDP', 'port': 3389, 'size': 4096, 'description': 'Remote desktop session packet.', 'threatModifier': 0.25, 'weight': 7 },
    { 'protocol': 'FTP', 'port': 21, 'size': 2048, 'description': 'File transfer protocol connection.', 'threatModifier': 0.3, 'weight': 5 },

    # High risk (10% of traffic)
    { 'protocol': 'HTTP', 'port': 80, 'size': 8192, 'description': 'Large unencrypted data transfer.', 'threatModifier': 0.45, 'weight': 3 },
    { 'protocol': 'ICMP', 'port': 0, 'size': 1024, 'description': 'Unusual, rapid large ICMP packets.', 'threatModifier': 0.65, 'weight': 2 },
    { 'protocol': 'SMB', 'port': 445, 'size': 16384, 'description': 'Massive file transfer attempt on common exploit port.', 'threatModifier': 0.85, 'weight': 1 },
]

USER_CONTEXT_POOL = {
    'identities': ['admin', 'developer', 'guest', 'unknown', 'service_account'],
    'devices': ['compliant', 'unpatched', 'compromised', 'mobile'],
    'resources': ['low', 'medium', 'high', 'critical'],
}

# IP pools for simulation
SOURCE_IPS = ['192.168.1.10', '192.168.1.20', '10.0.0.5', '172.16.0.15', '203.0.113.42']
DEST_IPS = ['8.8.8.8', '1.1.1.1', '192.168.1.1', '10.0.0.1', '172.16.0.1']


# --- Core AI/ZT Logic ---

def classify_traffic(traffic):
    """Use the real RandomForest model for threat classification."""
    import numpy as np

    # Map simulation profile to the 11-feature vector expected by the RF model
    proto_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'HTTPS': 6, 'HTTP': 6,
                 'SSH': 6, 'DNS': 17, 'FTP': 6, 'RDP': 6, 'SMB': 6}
    proto_num = proto_map.get(traffic['protocol'], 0)
    dport = traffic['port']
    sport = random.randint(1024, 65535)
    pkt_size = traffic['size']

    from detection_agent import SUSPICIOUS_PORTS, WELL_KNOWN_PORTS
    port_is_suspicious = int(dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS)
    port_is_well_known = int(dport in WELL_KNOWN_PORTS or sport in WELL_KNOWN_PORTS)

    numeric = np.array([
        proto_num,   # protocol number
        sport,       # source port
        dport,       # dest port
        pkt_size,    # packet size
        1,           # is_src_private (simulation assumes internal source)
        0,           # is_dst_private
        0,           # has_syn
        0,           # has_fin
        0,           # has_rst
        port_is_suspicious,
        port_is_well_known,
    ], dtype=np.float64).reshape(1, -1)

    pred, confidence = _traffic_classifier.predict(numeric)
    final_score = confidence if pred == 1 else 1.0 - confidence

    # Apply the profile's threat modifier as a small bias so traffic variety
    # still influences the score even with a deterministic model.
    final_score = min(1.0, max(0.0, final_score + traffic.get('threatModifier', 0) * 0.15))

    if final_score >= 0.75:
        return {'finalScore': final_score, 'classification': 'BLOCKED_HIGH_THREAT'}
    if final_score >= 0.45:
        return {'finalScore': final_score, 'classification': 'QUARANTINE_SUSPICIOUS'}
    return {'finalScore': final_score, 'classification': 'CLEAN_LOW_THREAT'}


def enforce_zero_trust(ai_result, user_context, traffic_profile):
    """Zero Trust Policy Engine (Context-Aware Enforcement)."""
    final_score = ai_result['finalScore']
    classification = ai_result['classification']

    identity = user_context['identity']
    device = user_context['device']
    resource = user_context['resource']

    required_trust_level = { 'low': 0.3, 'medium': 0.5, 'high': 0.7, 'critical': 0.9 }[resource]

    user_trust_score = 0
    if identity in ['admin', 'developer']:
        user_trust_score += 0.4
    if device == 'compliant':
        user_trust_score += 0.4

    if device == 'compromised':
        user_trust_score -= 0.5
    if identity in ['unknown', 'guest']:
        user_trust_score -= 0.3

    aggregated_trust = user_trust_score - final_score

    if classification == 'BLOCKED_HIGH_THREAT' and final_score >= 0.75:
        return {
            'decision': 'Blocked',
            'severity': 'High',
            'reason': f"AI Engine: Severe zero-day anomaly detected ({traffic_profile['protocol']}:{traffic_profile['port']}). **ABSOLUTE BLOCK** enforced.",
        }

    if aggregated_trust < required_trust_level:
        action = 'Blocked' if (resource == 'critical' or device == 'compromised') else 'Quarantined'
        severity = 'High' if action == 'Blocked' else 'Medium'
        return {
            'decision': action,
            'severity': severity,
            'reason': f"ZT Policy: Insufficient trust for {resource.upper()} access (Trust:{aggregated_trust:.2f} < Required:{required_trust_level:.2f}). Device: {device}.",
        }

    return {
        'decision': 'Allowed',
        'severity': 'Allowed',
        'reason': "Trust verified. User/Device Compliant. AI Score Low. Access **GRANTED** under continuous monitoring.",
    }


def update_network_stats(decision):
    """Update network statistics"""
    try:
        # Get or create today's stats
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp() * 1000
        result = supabase.table('network_stats').select('*').gte('timestamp', today_start).order('timestamp', desc=True).limit(1).execute()

        if result.data and len(result.data) > 0:
            stats = result.data[0]
            supabase.table('network_stats').update({
                'total_packets': stats['total_packets'] + 1,
                'allowed_count': stats['allowed_count'] + (1 if decision == 'Allowed' else 0),
                'blocked_count': stats['blocked_count'] + (1 if decision == 'Blocked' else 0),
                'quarantined_count': stats['quarantined_count'] + (1 if decision == 'Quarantined' else 0)
            }).eq('id', stats['id']).execute()
        else:
            supabase.table('network_stats').insert({
                'timestamp': time.time() * 1000,
                'total_packets': 1,
                'allowed_count': 1 if decision == 'Allowed' else 0,
                'blocked_count': 1 if decision == 'Blocked' else 0,
                'quarantined_count': 1 if decision == 'Quarantined' else 0
            }).execute()
    except Exception as e:
        print(f"Error updating network stats: {e}")
        # Don't fail the request if stats update fails


def calculate_metrics():
    """Calculate dashboard metrics"""
    try:
        # Get counts from database - only count threats since app started
        high_severity_result = supabase.table('security_logs').select('*', count='exact').eq('severity', 'High').gte('timestamp', APP_START_TIME).execute()
        active_threats = high_severity_result.count if hasattr(high_severity_result, 'count') else len(high_severity_result.data)

        blocked_result = supabase.table('security_logs').select('*', count='exact').eq('decision', 'Blocked').gte('timestamp', APP_START_TIME).execute()
        blocked_attacks = blocked_result.count if hasattr(blocked_result, 'count') else len(blocked_result.data)

        # Get network traffic stats - calculate from security logs since app start
        traffic_result = supabase.table('security_logs').select('size').gte('timestamp', APP_START_TIME).execute()
        recent_packets = len(traffic_result.data)
        total_bytes = sum(log.get('size', 0) for log in traffic_result.data)

        # Calculate traffic in Gbps (bytes to Gbps conversion)
        # Assuming average packet size if no size data, otherwise use actual data
        if recent_packets > 0:
            avg_packet_size = total_bytes / recent_packets if total_bytes else 1500
            traffic_gbps = (recent_packets * avg_packet_size * 8) / (1024**3)  # Convert to Gbps (bits)
        else:
            traffic_gbps = 0.0

        system_health = max(0, min(100, 100 - (active_threats * 0.5)))

        # Get recent alerts and format them properly - only from current session
        # Get High severity alerts
        high_alerts = supabase.table('security_logs').select('*').eq('severity', 'High').gte('timestamp', APP_START_TIME).order('timestamp', desc=True).limit(5).execute()
        # Get Medium severity alerts
        medium_alerts = supabase.table('security_logs').select('*').eq('severity', 'Medium').gte('timestamp', APP_START_TIME).order('timestamp', desc=True).limit(5).execute()

        # Combine and sort by timestamp
        all_alerts = (high_alerts.data or []) + (medium_alerts.data or [])
        all_alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        db_alerts = all_alerts[:5]

        # Format alerts to match expected structure
        alerts = []
        for log in db_alerts:
            alerts.append({
                'timestamp': log['timestamp'],
                'reason': log['reason'],
                'severity': log['severity'],
                'userContext': {
                    'identity': log['user_identity'],
                    'device': log['user_device'],
                    'resource': log['user_resource']
                },
                'user_identity': log['user_identity'],  # Keep both formats for compatibility
                'user_device': log['user_device'],
                'user_resource': log['user_resource']
            })

        # Add recent response actions as alerts
        try:
            recent_responses = supabase.table('response_actions').select('*').order('timestamp', desc=True).limit(3).execute()
            for r in (recent_responses.data or []):
                rt = r.get('rule_type', '')
                alerts.append({
                    'type': f"IP {rt.replace('_', ' ').upper()}",
                    'source': r.get('src_ip', ''),
                    'severity': 'High' if rt == 'hard_block' else 'Medium',
                    'time': 'just now',
                })
        except Exception:
            pass

        return {
            'activeThreats': active_threats,
            'blockedAttacks': blocked_attacks,
            'networkTraffic': f"{traffic_gbps:.2f} Gbps",
            'systemHealth': f"{system_health:.1f}%",
            'alerts': alerts[:3]
        }
    except Exception as e:
        print(f"Error in calculate_metrics: {e}")
        import traceback
        traceback.print_exc()
        return {
            'activeThreats': 0,
            'blockedAttacks': 0,
            'networkTraffic': '0.00 Gbps',
            'systemHealth': '100%',
            'alerts': []
        }


# --- Endpoints ---

@dashboard_bp.route('/api/traffic/simulate', methods=['POST'])
@jwt_required()
def simulate_traffic():
    """Generates a single new traffic log entry and saves to database"""
    try:
        # Get the authenticated user who triggered this simulation
        authenticated_user = get_jwt_identity()

        # Weighted random selection for realistic traffic distribution
        total_weight = sum(profile.get('weight', 1) for profile in TRAFFIC_PROFILES)
        rand = random.uniform(0, total_weight)
        cumulative = 0
        traffic_profile = TRAFFIC_PROFILES[0]  # Default fallback

        for profile in TRAFFIC_PROFILES:
            cumulative += profile.get('weight', 1)
            if rand <= cumulative:
                traffic_profile = profile
                break

        # Remove weight from profile before processing (it's not part of the data model)
        traffic_profile = {k: v for k, v in traffic_profile.items() if k != 'weight'}
        user_context = {
            'identity': random.choice(USER_CONTEXT_POOL['identities']),
            'device': random.choice(USER_CONTEXT_POOL['devices']),
            'resource': random.choice(USER_CONTEXT_POOL['resources']),
        }

        ai_result = classify_traffic(traffic_profile)
        decision = enforce_zero_trust(ai_result, user_context, traffic_profile)

        source_ip = random.choice(SOURCE_IPS)
        dest_ip = random.choice(DEST_IPS)
        timestamp = time.time() * 1000

        new_log_entry = {
            'timestamp': timestamp,
            'traffic': traffic_profile,
            'userContext': user_context,
            'aiResult': ai_result,
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            **decision
        }

        # Save to database (hash-chained)
        _insert_security_log({
            'timestamp': timestamp,
            'protocol': traffic_profile['protocol'],
            'port': traffic_profile['port'],
            'size': traffic_profile['size'],
            'description': traffic_profile['description'],
            'user_identity': user_context['identity'],
            'user_device': user_context['device'],
            'user_resource': user_context['resource'],
            'ai_score': ai_result['finalScore'],
            'decision': decision['decision'],
            'severity': decision['severity'],
            'reason': decision['reason'],
            'source_ip': source_ip,
            'destination_ip': dest_ip
        })

        # Add to in-memory cache
        LOG_DATABASE.insert(0, new_log_entry)
        if len(LOG_DATABASE) > MAX_LOG_ENTRIES:
            LOG_DATABASE.pop()

        # Add to embedder for RAG search
        embedder.add_logs([{
            'timestamp': timestamp,
            'src_ip': source_ip,
            'protocol': traffic_profile['protocol'],
            'reason': decision['reason'],
            'action': decision['decision'],
            'severity': decision['severity']
        }])

        # Update network stats
        update_network_stats(decision['decision'])

        dashboard_metrics = calculate_metrics()
        return jsonify({
            'logEntry': new_log_entry,
            'metrics': dashboard_metrics
        })
    except Exception as e:
        print(f"Error in simulate_traffic: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'logEntry': None,
            'metrics': calculate_metrics()
        }), 500


@dashboard_bp.route('/api/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_data():
    """Returns all necessary dashboard data"""
    try:
        # Get the authenticated user
        authenticated_user = get_jwt_identity()
        print(f"Dashboard accessed by user: {authenticated_user}")

        metrics = calculate_metrics()

        # Get recent logs from database - show all logs for comprehensive view
        # but prioritize recent ones from current session
        result = supabase.table('security_logs').select('*').order('timestamp', desc=True).limit(50).execute()
        db_logs = result.data

        # Convert to dict format
        current_log = []
        for log in db_logs:
            current_log.append({
                'timestamp': log['timestamp'],
                'traffic': {
                    'protocol': log['protocol'],
                    'port': log['port'],
                    'size': log['size'],
                    'description': log['description']
                },
                'userContext': {
                    'identity': log['user_identity'],
                    'device': log['user_device'],
                    'resource': log['user_resource']
                },
            'aiResult': {
                'finalScore': log['ai_score'],
                'classification': 'BLOCKED_HIGH_THREAT' if log['ai_score'] >= 0.75 else 'QUARANTINE_SUSPICIOUS' if log['ai_score'] >= 0.45 else 'CLEAN_LOW_THREAT'
            },
                'decision': log['decision'],
                'severity': log['severity'],
                'reason': log['reason'],
                'source_ip': log['source_ip'],
                'destination_ip': log['destination_ip']
            })

        return jsonify({
            'metrics': metrics,
            'currentLog': current_log
        })
    except Exception as e:
        print(f"Error in get_dashboard_data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'metrics': {
                'activeThreats': 0,
                'blockedAttacks': 0,
                'networkTraffic': '0.00 Gbps',
                'systemHealth': '100%',
                'alerts': []
            },
            'currentLog': []
        }), 500


@dashboard_bp.route('/api/network/traffic', methods=['GET'])
@jwt_required()
def get_network_traffic():
    """Get detailed network traffic statistics"""
    try:
        # Get all logs for aggregation (Supabase doesn't support complex GROUP BY in client)
        # We'll fetch and aggregate in Python
        result = supabase.table('security_logs').select('*').execute()
        all_logs = result.data

        # Aggregate by protocol
        protocol_stats = {}
        for log in all_logs:
            protocol = log['protocol']
            if protocol not in protocol_stats:
                protocol_stats[protocol] = {'protocol': protocol, 'count': 0, 'total_size': 0, 'blocked': 0, 'allowed': 0}
            protocol_stats[protocol]['count'] += 1
            protocol_stats[protocol]['total_size'] += log.get('size', 0)
            if log['decision'] == 'Blocked':
                protocol_stats[protocol]['blocked'] += 1
            elif log['decision'] == 'Allowed':
                protocol_stats[protocol]['allowed'] += 1

        protocol_stats = sorted(protocol_stats.values(), key=lambda x: x['count'], reverse=True)

        # Aggregate by port
        port_stats = {}
        for log in all_logs:
            port = log['port']
            protocol = log['protocol']
            key = f"{port}_{protocol}"
            if key not in port_stats:
                port_stats[key] = {'port': port, 'protocol': protocol, 'count': 0}
            port_stats[key]['count'] += 1

        port_stats = sorted(port_stats.values(), key=lambda x: x['count'], reverse=True)[:20]

        # Get hourly stats for last 24 hours
        time_threshold = max(APP_START_TIME, (time.time() - 86400) * 1000)
        recent_logs = [log for log in all_logs if log['timestamp'] >= time_threshold]

        hourly_stats = {}
        for log in recent_logs:
            # Convert timestamp to hour key
            dt = datetime.fromtimestamp(log['timestamp'] / 1000)
            hour_key = dt.strftime('%Y-%m-%d %H:00:00')
            if hour_key not in hourly_stats:
                hourly_stats[hour_key] = {'hour': hour_key, 'count': 0, 'blocked': 0}
            hourly_stats[hour_key]['count'] += 1
            if log['decision'] == 'Blocked':
                hourly_stats[hour_key]['blocked'] += 1

        hourly_stats = sorted(hourly_stats.values(), key=lambda x: x['hour'], reverse=True)[:24]

        return jsonify({
            'protocolStats': protocol_stats or [],
            'portStats': port_stats or [],
            'hourlyStats': hourly_stats or []
        })
    except Exception as e:
        print(f"Error in get_network_traffic: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'protocolStats': [],
            'portStats': [],
            'hourlyStats': [],
            'error': str(e)
        }), 500
