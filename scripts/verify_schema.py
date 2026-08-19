"""
PHASE 34.2 — Production Schema Verification Script
===================================================
Connects to the database specified by DATABASE_URL (or falls back to local
SQLite) and compares the live schema against the expected models.py schema.

Run locally:
    python scripts/verify_schema.py

Run against production (via Render Shell):
    DATABASE_URL=<your-render-postgres-url> python scripts/verify_schema.py

Output sections:
    A. Tables found vs expected
    B. Missing tables
    C. Column audit per table
    D. Missing columns
    E. Extra columns (not in model)
    F. Schema drift summary
    G. Dashboard 500 root cause verdict
"""

import os
import sys

# Allow import of app-level modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Expected schema (mirrors models.py exactly) ──────────────────────────────

EXPECTED = {
    'user': {
        'id':            {'type': 'integer',    'nullable': False},
        'username':      {'type': 'varchar',    'nullable': False},
        'password_hash': {'type': 'varchar',    'nullable': False},
        'created_at':    {'type': 'timestamp',  'nullable': True},
    },
    'share': {
        'id':            {'type': 'integer',    'nullable': False},
        'filename':      {'type': 'varchar',    'nullable': False},
        'original_name': {'type': 'varchar',    'nullable': False},
        'mime_type':     {'type': 'varchar',    'nullable': True},   # added Phase 26.3
        'upload_time':   {'type': 'timestamp',  'nullable': True},
        'expiry_time':   {'type': 'timestamp',  'nullable': False},
        'download_count':{'type': 'integer',    'nullable': True},
        'public_url':    {'type': 'varchar',    'nullable': False},
        'user_id':       {'type': 'integer',    'nullable': True},
        'version':       {'type': 'integer',    'nullable': True},   # added V2
    },
    'transfer': {
        'id':            {'type': 'integer',    'nullable': False},
        'share_id':      {'type': 'integer',    'nullable': False},
        'timestamp':     {'type': 'timestamp',  'nullable': True},
    },
    'cipher': {
        'id':            {'type': 'integer',    'nullable': False},
        'content':       {'type': 'text',       'nullable': False},
        'public_id':     {'type': 'varchar',    'nullable': False},
        'burn_on_read':  {'type': 'boolean',    'nullable': True},
        'is_read':       {'type': 'boolean',    'nullable': True},
        'created_at':    {'type': 'timestamp',  'nullable': True},
        'sender_alias':  {'type': 'varchar',    'nullable': True},   # added Phase 25.2
    },
    'setting': {
        'key':           {'type': 'varchar',    'nullable': False},
        'value':         {'type': 'varchar',    'nullable': False},
    },
    'user_setting': {
        'id':            {'type': 'integer',    'nullable': False},
        'user_id':       {'type': 'integer',    'nullable': False},
        'key':           {'type': 'varchar',    'nullable': False},
        'value':         {'type': 'varchar',    'nullable': False},
    },
    'login_attempt': {
        'ip':            {'type': 'varchar',    'nullable': False},
        'attempts':      {'type': 'integer',    'nullable': True},
        'last_attempt':  {'type': 'timestamp',  'nullable': True},
    },
    'registration_attempt': {
        'ip':            {'type': 'varchar',    'nullable': False},
        'attempts':      {'type': 'integer',    'nullable': True},
        'last_attempt':  {'type': 'timestamp',  'nullable': True},
    },
}

# ── Database connection ───────────────────────────────────────────────────────

def get_connection():
    db_url = os.environ.get('DATABASE_URL', '')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)

    if 'postgresql' in db_url:
        import psycopg2
        conn = psycopg2.connect(db_url)
        return conn, 'postgresql'
    else:
        # Fall back to local SQLite
        import sqlite3
        db_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'qr_app.db'
        )
        conn = sqlite3.connect(db_path)
        return conn, 'sqlite'

# ── Column introspection ──────────────────────────────────────────────────────

def get_tables_postgresql(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_type = 'BASE TABLE'
        ORDER BY table_name
    """)
    return {row[0] for row in cur.fetchall()}

def get_columns_postgresql(conn, table):
    cur = conn.cursor()
    cur.execute("""
        SELECT column_name,
               data_type,
               is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = %s
        ORDER BY ordinal_position
    """, (table,))
    return {
        row[0]: {
            'type': row[1].lower().split('(')[0].strip(),
            'nullable': row[2] == 'YES'
        }
        for row in cur.fetchall()
    }

def get_tables_sqlite(conn):
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    return {row[0] for row in cur.fetchall()}

def get_columns_sqlite(conn, table):
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    rows = cur.fetchall()
    # PRAGMA returns: cid, name, type, notnull, dflt_value, pk
    result = {}
    for row in rows:
        col_name = row[1]
        raw_type = row[2].lower().split('(')[0].strip()
        not_null  = bool(row[3])
        result[col_name] = {
            'type': raw_type,
            'nullable': not not_null
        }
    return result

# ── Type normalisation (PostgreSQL type names vs SQLAlchemy logical names) ────

PG_TYPE_MAP = {
    'integer':                   'integer',
    'bigint':                    'integer',
    'smallint':                  'integer',
    'character varying':         'varchar',
    'varchar':                   'varchar',
    'text':                      'text',
    'boolean':                   'boolean',
    'timestamp without time zone':'timestamp',
    'timestamp with time zone':  'timestamp',
    'timestamp':                 'timestamp',
    'date':                      'date',
}

SQLITE_TYPE_MAP = {
    'integer':   'integer',
    'int':       'integer',
    'varchar':   'varchar',
    'text':      'text',
    'boolean':   'boolean',
    'bool':      'boolean',
    'datetime':  'timestamp',
    'timestamp': 'timestamp',
    'real':      'real',
    'float':     'real',
    'blob':      'blob',
}

def normalise(raw_type, engine):
    t = raw_type.lower().split('(')[0].strip()
    if engine == 'postgresql':
        return PG_TYPE_MAP.get(t, t)
    return SQLITE_TYPE_MAP.get(t, t)

# ── Reporting ─────────────────────────────────────────────────────────────────

SEP = '─' * 72

def banner(title):
    print(f'\n{SEP}')
    print(f'  {title}')
    print(SEP)

def ok(msg):   print(f'  ✓  {msg}')
def warn(msg): print(f'  ⚠  {msg}')
def fail(msg): print(f'  ✗  {msg}')
def info(msg): print(f'     {msg}')

# ── Main audit ────────────────────────────────────────────────────────────────

def main():
    print('\n' + '═' * 72)
    print('  OBSIDIAN SECURE — PHASE 34.2 SCHEMA VERIFICATION')
    print('═' * 72)

    try:
        conn, engine = get_connection()
        print(f'\n  Connected to: {engine.upper()}')
    except Exception as e:
        print(f'\n  FATAL: Could not connect to database: {e}')
        sys.exit(1)

    # ── A. Table presence ────────────────────────────────────────────────────

    banner('A. TABLE PRESENCE')

    if engine == 'postgresql':
        live_tables = get_tables_postgresql(conn)
    else:
        live_tables = get_tables_sqlite(conn)

    expected_tables = set(EXPECTED.keys())
    missing_tables  = expected_tables - live_tables
    extra_tables    = live_tables - expected_tables - {'alembic_version'}

    print(f'\n  Expected tables : {sorted(expected_tables)}')
    print(f'  Live tables     : {sorted(live_tables)}')

    if missing_tables:
        for t in sorted(missing_tables):
            fail(f'MISSING TABLE: {t}')
    else:
        ok('All expected tables are present')

    if extra_tables:
        for t in sorted(extra_tables):
            warn(f'Extra table (not in model): {t}')

    # ── B–E. Column audit per table ──────────────────────────────────────────

    missing_cols = {}   # table → list of missing column names
    extra_cols   = {}   # table → list of extra column names
    type_drifts  = {}   # table → list of (col, expected_type, live_type)

    for table in sorted(expected_tables):
        banner(f'B–E. COLUMN AUDIT: {table}')

        if table in missing_tables:
            fail(f'Table does not exist — skipping column check')
            missing_cols[table] = list(EXPECTED[table].keys())
            continue

        if engine == 'postgresql':
            live_cols = get_columns_postgresql(conn, table)
        else:
            live_cols = get_columns_sqlite(conn, table)

        exp_cols = EXPECTED[table]

        table_missing = []
        table_extra   = []
        table_drifts  = []

        for col, meta in exp_cols.items():
            if col not in live_cols:
                fail(f'MISSING COLUMN: {col}  (expected type: {meta["type"]})')
                table_missing.append(col)
            else:
                live_type = normalise(live_cols[col]['type'], engine)
                exp_type  = meta['type']
                if live_type != exp_type:
                    warn(f'TYPE DRIFT  : {col}  expected={exp_type}  live={live_type}')
                    table_drifts.append((col, exp_type, live_type))
                else:
                    ok(f'{col}  ({live_type})')

        for col in live_cols:
            if col not in exp_cols:
                info(f'Extra column (not in model): {col}  type={live_cols[col]["type"]}')
                table_extra.append(col)

        if table_missing: missing_cols[table] = table_missing
        if table_extra:   extra_cols[table]   = table_extra
        if table_drifts:  type_drifts[table]  = table_drifts

    # ── F. Schema drift summary ──────────────────────────────────────────────

    banner('F. SCHEMA DRIFT SUMMARY')

    if not missing_tables and not missing_cols and not type_drifts:
        ok('Production schema matches models.py exactly. No drift detected.')
    else:
        if missing_tables:
            fail(f'Missing tables: {sorted(missing_tables)}')
        for tbl, cols in missing_cols.items():
            fail(f'Table "{tbl}" missing columns: {cols}')
        for tbl, drifts in type_drifts.items():
            for col, exp, live in drifts:
                warn(f'Table "{tbl}" column "{col}": expected {exp}, live {live}')

    # ── G. Dashboard 500 root cause verdict ──────────────────────────────────

    banner('G. DASHBOARD 500 ROOT CAUSE VERDICT')

    critical_missing = []
    if 'login_attempt' in missing_tables:
        critical_missing.append('login_attempt table — 500 on GET /login')
    if 'registration_attempt' in missing_tables:
        critical_missing.append('registration_attempt table — 500 on POST /register')
    if 'user_setting' in missing_tables:
        critical_missing.append('user_setting table — 500 on all authenticated routes')
    if 'share' in missing_cols and 'version' in missing_cols.get('share', []):
        critical_missing.append(
            'share.version column — 500 on GET /dashboard '
            '(SQLAlchemy ORM maps column, column absent in DB, '
            'ProgrammingError: column share.version does not exist)'
        )
    if 'share' in missing_cols and 'mime_type' in missing_cols.get('share', []):
        critical_missing.append(
            'share.mime_type column — 500 on GET /download/<filename> '
            'and potential 500 on /dashboard if ORM mapping fails'
        )
    if 'cipher' in missing_cols and 'sender_alias' in missing_cols.get('cipher', []):
        critical_missing.append(
            'cipher.sender_alias column — 500 on POST /cipher/create '
            'and GET /decrypt/<id>'
        )

    if critical_missing:
        fail('DASHBOARD 500 IS CAUSED BY SCHEMA DRIFT:')
        for item in critical_missing:
            fail(f'  → {item}')
        print()
        fail('Root cause confirmed: missing columns in production PostgreSQL.')
        fail('The schema migration ran but did not successfully apply all columns.')
        fail('Each missing column will produce:')
        info('  sqlalchemy.exc.ProgrammingError: column <table>.<col> does not exist')
    else:
        ok('No schema drift detected that would cause the dashboard 500.')
        ok('If a 500 is still occurring, check:')
        info('  1. Template rendering errors (inspect Render logs for TemplateSyntaxError)')
        info('  2. Application logic errors (inspect full traceback in Render logs)')
        info('  3. SECRET_KEY instability (session errors)')

    print(f'\n{SEP}')
    print('  Verification complete.')
    print(f'{SEP}\n')

    conn.close()

if __name__ == '__main__':
    main()
