"""
Database client wrapper.

Provides a lightweight Supabase-compatible query builder backed by SQLite,
and selects the active backend (Supabase if configured and reachable,
otherwise local SQLite). The module-level ``supabase`` object is the
single shared client used throughout the application.
"""

import os
import sqlite3

from app.core.config import DB_PATH


# ---------------------------------------------------------------------------
# Lightweight Supabase-compatible wrapper around SQLite
# ---------------------------------------------------------------------------

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
        self._filters = []
        self._order_col = None
        self._order_desc = False
        self._limit_val = None
        self._offset = None
        self._end = None
        self._insert_data = None
        self._update_data = None
        self._count_mode = False

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

    def eq(self, col, val):
        self._filters.append((col, '=', val))
        return self

    def gte(self, col, val):
        self._filters.append((col, '>=', val))
        return self

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
    """Drop-in replacement for the Supabase client."""

    def __init__(self, db_path: str):
        self._db = db_path

    def table(self, name: str):
        return _QueryBuilder(name, self._db)


def _init_sqlite():
    """Create tables in the local SQLite database."""
    from app.core.config import DATA_DIR
    os.makedirs(DATA_DIR, exist_ok=True)
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
            src_ip TEXT, dst_ip TEXT, protocol TEXT,
            sport INTEGER, dport INTEGER, size INTEGER, flags TEXT,
            rf_prediction TEXT, rf_confidence REAL,
            rl_state TEXT, rl_action TEXT, rl_reward REAL,
            was_exploration INTEGER, is_malicious INTEGER,
            severity TEXT, reason TEXT, epsilon REAL,
            entry_hash TEXT, prev_hash TEXT,
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
            confidence REAL, reason TEXT,
            command TEXT, undo_command TEXT,
            reversed INTEGER DEFAULT 0,
            reversed_at REAL,
            dry_run INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TRIGGER IF NOT EXISTS prevent_security_log_update
        BEFORE UPDATE ON security_logs
        BEGIN SELECT RAISE(ABORT, 'IMMUTABLE: security_logs cannot be modified after insertion'); END;
        CREATE TRIGGER IF NOT EXISTS prevent_security_log_delete
        BEFORE DELETE ON security_logs
        BEGIN SELECT RAISE(ABORT, 'IMMUTABLE: security_logs cannot be deleted'); END;
        CREATE TRIGGER IF NOT EXISTS prevent_detection_log_update
        BEFORE UPDATE ON detection_logs
        BEGIN SELECT RAISE(ABORT, 'IMMUTABLE: detection_logs cannot be modified after insertion'); END;
        CREATE TRIGGER IF NOT EXISTS prevent_detection_log_delete
        BEFORE DELETE ON detection_logs
        BEGIN SELECT RAISE(ABORT, 'IMMUTABLE: detection_logs cannot be deleted'); END;
    """)
    for tbl in ('security_logs', 'detection_logs'):
        existing = {row[1] for row in cur.execute(f'PRAGMA table_info("{tbl}")').fetchall()}
        if 'entry_hash' not in existing:
            cur.execute(f'ALTER TABLE "{tbl}" ADD COLUMN entry_hash TEXT')
        if 'prev_hash' not in existing:
            cur.execute(f'ALTER TABLE "{tbl}" ADD COLUMN prev_hash TEXT')
    det_cols = {row[1] for row in cur.execute('PRAGMA table_info("detection_logs")').fetchall()}
    if 'response_action' not in det_cols:
        cur.execute('ALTER TABLE "detection_logs" ADD COLUMN response_action TEXT DEFAULT \'none\'')
    if 'response_rule_type' not in det_cols:
        cur.execute('ALTER TABLE "detection_logs" ADD COLUMN response_rule_type TEXT DEFAULT \'none\'')
    conn.commit()
    conn.close()


def _create_client():
    supabase_url = os.getenv('SUPABASE_URL')
    supabase_key = os.getenv('SUPABASE_KEY')
    if supabase_url and supabase_key:
        try:
            from supabase import create_client
            client = create_client(supabase_url, supabase_key)
            client.table('users').select('id').limit(1).execute()
            print("[DB] Connected to Supabase successfully!")
            return client, True
        except Exception as exc:
            print(f"[DB] Supabase unavailable ({exc}). Falling back to local SQLite.")
    _init_sqlite()
    print(f"[DB] Using local SQLite database at {DB_PATH}")
    return _LocalDB(DB_PATH), False


supabase, USE_SUPABASE = _create_client()
