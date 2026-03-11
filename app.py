import hashlib
import json
import json as _json
import os
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import time
import random
import requests as http_requests
import io
import base64

from detection_agent import DetectionAgent, TrafficClassifier
from response_agent import ResponseAgent

# Load environment variables
load_dotenv()

# --- Backend Data and Configuration ---

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-in-production'  # Change this in production!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_ALGORITHM'] = 'HS256'

# Enable CORS for the frontend running on a different port
CORS(app, supports_credentials=True)

# Initialize JWT
jwt = JWTManager(app)

# Federated Learning config
FL_SERVER_URL = os.getenv("FL_SERVER_URL", "http://localhost:6000")

# Shared RF classifier instance used by the simulation endpoint
_traffic_classifier = TrafficClassifier()


# ---------------------------------------------------------------------------
# Lightweight Supabase-compatible wrapper around SQLite
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'firewall.db')


class _Result:
    """Mimics Supabase execute() result."""
    def __init__(self, data, count=None):
        self.data = data
        self.count = count if count is not None else len(data)


class _QueryBuilder:
    """Chainable query builder that mirrors the Supabase Python client API."""

    def __init__(self, table: str, db_path: str):
        self._table = table
        self._db = db_path
        self._mode = 'select'
        self._columns = '*'
        self._filters = []          # list of (col, op, val)
        self._order_col = None
        self._order_desc = False
        self._limit_val = None
        self._offset = None
        self._end = None
        self._insert_data = None
        self._update_data = None
        self._count_mode = False

    # --- mode setters ---
    def select(self, columns='*', count=None):
        self._mode = 'select'
        self._columns = columns
        if count == 'exact':
            self._count_mode = True
        return self

    def insert(self, data):
        self._mode = 'insert'
        self._insert_data = data
        return self

    def update(self, data):
        self._mode = 'update'
        self._update_data = data
        return self

    # --- filters ---
    def eq(self, col, val):
        self._filters.append((col, '=', val))
        return self

    def gte(self, col, val):
        self._filters.append((col, '>=', val))
        return self

    # --- ordering / pagination ---
    def order(self, col, desc=False):
        self._order_col = col
        self._order_desc = desc
        return self

    def limit(self, n):
        self._limit_val = n
        return self

    def range(self, start, end):
        self._offset = start
        self._end = end
        self._limit_val = end - start + 1
        return self

    # --- execute ---
    def execute(self):
        conn = sqlite3.connect(self._db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            if self._mode == 'insert':
                return self._do_insert(cur, conn)
            elif self._mode == 'update':
                return self._do_update(cur, conn)
            else:
                return self._do_select(cur, conn)
        finally:
            conn.close()

    # --- private helpers ---
    def _where_clause(self):
        if not self._filters:
            return '', []
        parts, vals = [], []
        for col, op, val in self._filters:
            parts.append(f'"{col}" {op} ?')
            vals.append(val)
        return ' WHERE ' + ' AND '.join(parts), vals

    def _do_select(self, cur, conn):
        cols = '*' if self._columns in ('*', None) else ', '.join(
            f'"{c.strip()}"' for c in self._columns.replace('*', '').split(',') if c.strip()
        ) or '*'
        sql = f'SELECT {cols} FROM "{self._table}"'
        where, params = self._where_clause()
        sql += where
        if self._order_col:
            direction = 'DESC' if self._order_desc else 'ASC'
            sql += f' ORDER BY "{self._order_col}" {direction}'
        if self._limit_val is not None:
            sql += f' LIMIT {self._limit_val}'
        if self._offset is not None:
            sql += f' OFFSET {self._offset}'
        cur.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]

        count = len(rows)
        if self._count_mode:
            count_sql = f'SELECT COUNT(*) FROM "{self._table}"' + where
            cur.execute(count_sql, params)
            count = cur.fetchone()[0]

        return _Result(rows, count)

    def _do_insert(self, cur, conn):
        data = self._insert_data
        keys = list(data.keys())
        placeholders = ', '.join(['?'] * len(keys))
        col_names = ', '.join(f'"{k}"' for k in keys)
        cur.execute(
            f'INSERT INTO "{self._table}" ({col_names}) VALUES ({placeholders})',
            [data[k] for k in keys],
        )
        conn.commit()
        data['id'] = cur.lastrowid
        return _Result([data])

    def _do_update(self, cur, conn):
        data = self._update_data
        set_parts = [f'"{k}" = ?' for k in data]
        set_vals = list(data.values())
        where, wvals = self._where_clause()
        cur.execute(
            f'UPDATE "{self._table}" SET {", ".join(set_parts)}' + where,
            set_vals + wvals,
        )
        conn.commit()
        return _Result([])


class _LocalDB:
    """Drop-in replacement for the Supabase client – exposes .table(name)."""

    def __init__(self, db_path: str):
        self._db = db_path

    def table(self, name: str):
        return _QueryBuilder(name, self._db)


def _init_sqlite():
    """Create tables in the local SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            size INTEGER NOT NULL,
            description TEXT,
            user_identity TEXT,
            user_device TEXT,
            user_resource TEXT,
            ai_score REAL,
            decision TEXT NOT NULL,
            severity TEXT NOT NULL,
            reason TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            entry_hash TEXT,
            prev_hash TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS network_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            total_packets INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            allowed_count INTEGER DEFAULT 0,
            blocked_count INTEGER DEFAULT 0,
            quarantined_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS detection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            sport INTEGER,
            dport INTEGER,
            size INTEGER,
            flags TEXT,
            rf_prediction TEXT,
            rf_confidence REAL,
            rl_state TEXT,
            rl_action TEXT,
            rl_reward REAL,
            was_exploration INTEGER,
            is_malicious INTEGER,
            severity TEXT,
            reason TEXT,
            epsilon REAL,
            entry_hash TEXT,
            prev_hash TEXT,
            response_action TEXT DEFAULT 'none',
            response_rule_type TEXT DEFAULT 'none',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS response_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id TEXT UNIQUE,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            confidence REAL,
            reason TEXT,
            command TEXT,
            undo_command TEXT,
            reversed INTEGER DEFAULT 0,
            reversed_at REAL,
            dry_run INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TRIGGER IF NOT EXISTS prevent_security_log_update
        BEFORE UPDATE ON security_logs
        BEGIN
            SELECT RAISE(ABORT, 'IMMUTABLE: security_logs cannot be modified after insertion');
        END;

        CREATE TRIGGER IF NOT EXISTS prevent_security_log_delete
        BEFORE DELETE ON security_logs
        BEGIN
            SELECT RAISE(ABORT, 'IMMUTABLE: security_logs cannot be deleted');
        END;

        CREATE TRIGGER IF NOT EXISTS prevent_detection_log_update
        BEFORE UPDATE ON detection_logs
        BEGIN
            SELECT RAISE(ABORT, 'IMMUTABLE: detection_logs cannot be modified after insertion');
        END;

        CREATE TRIGGER IF NOT EXISTS prevent_detection_log_delete
        BEFORE DELETE ON detection_logs
        BEGIN
            SELECT RAISE(ABORT, 'IMMUTABLE: detection_logs cannot be deleted');
        END;
    """)
    # Add entry_hash and prev_hash columns if they don't exist yet
    for tbl in ('security_logs', 'detection_logs'):
        existing = {row[1] for row in cur.execute(f'PRAGMA table_info("{tbl}")').fetchall()}
        if 'entry_hash' not in existing:
            cur.execute(f'ALTER TABLE "{tbl}" ADD COLUMN entry_hash TEXT')
        if 'prev_hash' not in existing:
            cur.execute(f'ALTER TABLE "{tbl}" ADD COLUMN prev_hash TEXT')
    # Add response columns to detection_logs if missing
    det_cols = {row[1] for row in cur.execute('PRAGMA table_info("detection_logs")').fetchall()}
    if 'response_action' not in det_cols:
        cur.execute('ALTER TABLE "detection_logs" ADD COLUMN response_action TEXT DEFAULT \'none\'')
    if 'response_rule_type' not in det_cols:
        cur.execute('ALTER TABLE "detection_logs" ADD COLUMN response_rule_type TEXT DEFAULT \'none\'')
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Hash-chain helpers for immutable logs
# ---------------------------------------------------------------------------

def _compute_entry_hash(data: dict, prev_hash: str) -> str:
    """Compute SHA-256 hash of log data chained to the previous hash."""
    filtered = {k: v for k, v in data.items() if k not in ('entry_hash', 'prev_hash', 'id')}
    payload = prev_hash + _json.dumps(filtered, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def _get_latest_hash(table: str) -> str:
    """Return the entry_hash of the most recent row, or 'GENESIS'."""
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(f'SELECT entry_hash FROM "{table}" ORDER BY id DESC LIMIT 1')
        row = cur.fetchone()
        if row and row[0] is not None:
            return row[0]
        return 'GENESIS'
    finally:
        conn.close()


def _insert_security_log(log_data: dict) -> dict:
    """Insert a security log with hash-chain integrity."""
    prev_hash = _get_latest_hash('security_logs')
    entry_hash = _compute_entry_hash(log_data, prev_hash)
    full_data = {**log_data, 'prev_hash': prev_hash, 'entry_hash': entry_hash}
    supabase.table('security_logs').insert(full_data).execute()
    return full_data


def _insert_detection_log(log_data: dict) -> dict:
    """Insert a detection log with hash-chain integrity."""
    prev_hash = _get_latest_hash('detection_logs')
    entry_hash = _compute_entry_hash(log_data, prev_hash)
    full_data = {**log_data, 'prev_hash': prev_hash, 'entry_hash': entry_hash}
    supabase.table('detection_logs').insert(full_data).execute()
    return full_data


# --- Try Supabase first, fall back to local SQLite ---
USE_SUPABASE = False
supabase = None

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')

if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client, Client as _SupaClient
        _client = create_client(SUPABASE_URL, SUPABASE_KEY)
        # Quick connectivity test (timeout handled by httpx defaults)
        _client.table('users').select('id').limit(1).execute()
        supabase = _client
        USE_SUPABASE = True
        print("[DB] Connected to Supabase successfully!")
    except Exception as exc:
        print(f"[DB] Supabase unavailable ({exc}). Falling back to local SQLite.")

if not USE_SUPABASE:
    _init_sqlite()
    supabase = _LocalDB(DB_PATH)
    print(f"[DB] Using local SQLite database at {DB_PATH}")


def init_db():
    """Initialize database - check if admin user exists, create if not"""
    try:
        # Check if default admin user exists
        result = supabase.table('users').select('*').eq('username', 'Me').execute()
        
        if not result.data:
            # Create default admin user
            admin_password = generate_password_hash('user123')
            supabase.table('users').insert({
                'username': 'Me',
                'email': 'me@firewall.local',
                'password_hash': admin_password,
                'role': 'admin'
            }).execute()
            print("Default admin user created!")
        else:
            print("Admin user already exists!")
    except Exception as e:
        print(f"Error initializing database: {e}")
        print("Make sure you have created the tables in Supabase. See supabase_migration.sql for SQL schema.")

# Initialize database on startup
init_db()

# Track app start time to reset metrics on launch
APP_START_TIME = time.time() * 1000  # Store in milliseconds to match timestamp format


# ---------------------------------------------------------------------------
# Detection Agent Setup
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
    except Exception as e:
        print(f"[DetectionAgent DB] Error saving detection: {e}")


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
    fl_server_url=_fl_url,
    client_id=os.getenv("FL_CLIENT_ID", None),
    response_agent=response_agent,
)

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


# --- Authentication Endpoints ---

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        # Check if user exists
        username_result = supabase.table('users').select('*').eq('username', username).execute()
        email_result = supabase.table('users').select('*').eq('email', email).execute()
        
        if username_result.data or email_result.data:
            return jsonify({'error': 'User already exists'}), 400
        
        # Create user
        password_hash = generate_password_hash(password)
        supabase.table('users').insert({
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'role': 'user'
        }).execute()
        
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        print(f"Error in register: {e}")
        return jsonify({'error': 'Failed to create user'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login and get JWT token"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    
    try:
        result = supabase.table('users').select('*').eq('username', username).execute()
        
        if not result.data or len(result.data) == 0:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user = result.data[0]
        
        if not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create access token
        access_token = create_access_token(identity=username)
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            }
        }), 200
    except Exception as e:
        print(f"Error in login: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user info"""
    username = get_jwt_identity()
    
    try:
        result = supabase.table('users').select('username, email, role').eq('username', username).execute()
        
        if not result.data or len(result.data) == 0:
            return jsonify({'error': 'User not found'}), 404
        
        user = result.data[0]
        
        return jsonify({
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        }), 200
    except Exception as e:
        print(f"Error in get_current_user: {e}")
        return jsonify({'error': 'Failed to get user info'}), 500


# --- Protected API Endpoints ---

@app.route('/api/traffic/simulate', methods=['POST'])
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

@app.route('/api/dashboard', methods=['GET'])
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

@app.route('/api/network/traffic', methods=['GET'])
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

@app.route('/api/logs', methods=['GET'])
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

@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    """Get all users (admin only)"""
    username = get_jwt_identity()
    
    try:
        result = supabase.table('users').select('role').eq('username', username).execute()
        
        if not result.data or len(result.data) == 0 or result.data[0]['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        users_result = supabase.table('users').select('id, username, email, role, created_at').execute()
        users = users_result.data
        
        return jsonify({'users': users})
    except Exception as e:
        print(f"Error in get_users: {e}")
        return jsonify({'error': 'Failed to get users'}), 500

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


# --- Log Integrity Verification & Export Endpoints ---

@app.route('/api/logs/verify', methods=['GET'])
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
                'message': 'No logs yet \u2014 chain is clean',
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
            'message': '\u2705 Chain intact \u2014 no tampering detected' if not tampered else f'\u26a0\ufe0f TAMPERING DETECTED in {len(tampered)} entries',
            'verified_at': time.time(),
        })
    except Exception as e:
        print(f"Error in verify_log_chain: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs/export', methods=['GET'])
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


# --- Detection Agent API Endpoints ---

@app.route('/api/agent/start', methods=['POST'])
@jwt_required()
def start_agent():
    """Start the detection agent."""
    data = request.get_json() or {}
    use_simulation = data.get('simulation', True)
    interface = data.get('interface', None)
    result = detection_agent.start(interface=interface, use_simulation=use_simulation)
    return jsonify(result)


@app.route('/api/agent/stop', methods=['POST'])
@jwt_required()
def stop_agent():
    """Stop the detection agent."""
    result = detection_agent.stop()
    return jsonify(result)


@app.route('/api/agent/status', methods=['GET'])
@jwt_required()
def agent_status():
    """Get detection agent status and RL stats."""
    status = detection_agent.get_status()
    status["response_stats"] = response_agent.get_status() if response_agent else None
    return jsonify(status)


@app.route('/api/agent/detections', methods=['GET'])
@jwt_required()
def agent_detections():
    """Get recent detections from the agent."""
    limit = request.args.get('limit', 50, type=int)
    detections = detection_agent.get_recent_detections(limit=limit)
    return jsonify({'detections': detections})


@app.route('/api/agent/qtable', methods=['GET'])
@jwt_required()
def agent_qtable():
    """Get Q-table summary."""
    summary = detection_agent.rl_agent.get_q_table_summary()
    stats = detection_agent.rl_agent.get_stats()
    return jsonify({'q_table': summary, 'stats': stats})


@app.route('/api/fl/status', methods=['GET'])
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


@app.route('/api/fl/rounds', methods=['GET'])
@jwt_required()
def fl_rounds_proxy():
    """Proxy FL server rounds history."""
    try:
        resp = http_requests.get(f"{FL_SERVER_URL}/fl/rounds", timeout=3)
        resp.raise_for_status()
        return jsonify(resp.json())
    except Exception:
        return jsonify({"rounds": [], "error": "FL server unreachable"})


@app.route('/api/agent/detections/history', methods=['GET'])
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


# --- Server Initialization ---


# --- Response Agent API Endpoints ---

@app.route('/api/response/status', methods=['GET'])
@jwt_required()
def response_status():
    """Get response agent status."""
    return jsonify(response_agent.get_status())


@app.route('/api/response/history', methods=['GET'])
@jwt_required()
def response_history():
    """Get response action history from database."""
    try:
        result = supabase.table('response_actions').select('*').order('timestamp', desc=True).limit(50).execute()
        return jsonify({'history': result.data})
    except Exception as e:
        print(f"Error in response_history: {e}")
        return jsonify({'history': [], 'error': str(e)}), 500


@app.route('/api/response/rollback/<action_id>', methods=['POST'])
@jwt_required()
def response_rollback(action_id):
    """Rollback a response action."""
    success = response_agent.rollback(action_id)
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Action not found or already reversed'}), 404


@app.route('/api/response/unblock', methods=['POST'])
@jwt_required()
def response_unblock():
    """Manually unblock an IP."""
    data = request.get_json() or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'success': False, 'error': 'IP address required'}), 400
    response_agent._auto_unblock(ip, 'manual_unblock')
    return jsonify({'success': True, 'ip': ip})


@app.route('/api/response/fp-tracker', methods=['GET'])
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


@app.route('/api/agent/visualizations', methods=['GET'])
@jwt_required()
def agent_visualizations():
    """Generate matplotlib/seaborn visualization charts from live detection data."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import seaborn as sns

    # Dark theme
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

    with detection_agent._lock:
        dets = list(detection_agent.detections)

    if not dets:
        return jsonify({"charts": [], "message": "No detections yet"})

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
    except Exception:
        pass

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
    except Exception:
        pass

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
    except Exception:
        pass

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
    except Exception:
        pass

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
    except Exception:
        pass

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
    except Exception:
        pass

    return jsonify({"charts": charts})


# =====================================================================
# XAI (Explainable AI) ENDPOINTS
# =====================================================================

SUSPICIOUS_PORTS_XAI = {4444, 1337, 31337, 6666, 6667, 6668, 6669, 8888, 9999, 2222, 1234, 12345}
WELL_KNOWN_PORTS_XAI = {80, 443, 22, 53, 25, 21, 110, 143, 3306, 5432, 8080, 8443}

_XAI_FEATURE_NAMES = [
    'proto_num', 'sport', 'dport', 'packet_size', 'src_is_private',
    'dst_is_private', 'has_syn', 'has_fin', 'has_rst',
    'port_is_suspicious', 'port_is_well_known',
]


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
        model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rf_model.pkl')
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


@app.route('/api/xai/explain', methods=['GET'])
@jwt_required()
def xai_explain():
    """Return recent detections enriched with SHAP explanations."""
    limit = request.args.get('limit', 20, type=int)
    result = supabase.table('detection_logs').select('*').order('timestamp', desc=True).limit(limit).execute()
    detections = result.data or []
    enriched = [_enrich_detection_xai(d) for d in detections]
    return jsonify({"detections": enriched})


@app.route('/api/xai/feature-stats', methods=['GET'])
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
            model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rf_model.pkl')
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


if __name__ == '__main__':
    print("=======================================================================")
    print("FLASK BACKEND RUNNING: Access the API at http://127.0.0.1:5000")
    print("Default admin credentials: username='Me', password='user123'")
    print("=======================================================================")
    print("Detection Agent: Use POST /api/agent/start to begin packet inspection")
    print("=======================================================================")
    app.run(debug=True, port=5000)
