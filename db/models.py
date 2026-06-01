"""
Data models and persistence helpers.

Contains the hash-chain integrity logic for the immutable log tables
(``security_logs`` and ``detection_logs``), the insert helpers that maintain
that chain, and the one-time admin-user seeding routine.
"""

import hashlib
import json as _json
import os
import secrets
import sqlite3

from werkzeug.security import generate_password_hash, check_password_hash

from db.client import supabase, DB_PATH


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


# ---------------------------------------------------------------------------
# Admin user seeding
# ---------------------------------------------------------------------------

def init_db():
    """Initialize database — seed an admin user if none exists."""
    admin_user = os.getenv('ADMIN_USERNAME', 'admin')
    admin_pass = os.getenv('ADMIN_PASSWORD', '')
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@firewall.local')

    if not admin_pass:
        # Auto-generate and persist
        admin_pass = secrets.token_urlsafe(16)
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
        with open(env_path, 'r') as f:
            content = f.read()
        if 'ADMIN_PASSWORD=' in content:
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if line.startswith('ADMIN_PASSWORD='):
                    lines[i] = f'ADMIN_PASSWORD={admin_pass}'
                    break
            with open(env_path, 'w') as f:
                f.write('\n'.join(lines) + '\n')
        else:
            with open(env_path, 'a') as f:
                f.write(f'\nADMIN_PASSWORD={admin_pass}\n')
        print(f'[Init] Generated admin password and saved to .env')

    try:
        result = supabase.table('users').select('*').eq('username', admin_user).execute()
        if not result.data:
            supabase.table('users').insert({
                'username': admin_user,
                'email': admin_email,
                'password_hash': generate_password_hash(admin_pass),
                'role': 'admin'
            }).execute()
            print(f'Default admin user "{admin_user}" created.')
        else:
            # Update password hash if it doesn't match current env password
            existing = result.data[0]
            if not check_password_hash(existing.get('password_hash', ''), admin_pass):
                supabase.table('users').update({
                    'password_hash': generate_password_hash(admin_pass),
                    'email': admin_email,
                }).eq('username', admin_user).execute()
                print(f'Admin user "{admin_user}" password updated from .env.')
            else:
                print('Admin user already exists.')
    except Exception as e:
        print(f'Error initializing database: {e}')
