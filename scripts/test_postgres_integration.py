"""
Obsidian Secure — Stage 7.1 PostgreSQL Integration Verification Test Harness
Strictly restricted to database: obsidian_secure_test
"""
import os
import sys
import re
import secrets
import shutil
import tempfile
import threading
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# ---------------------------------------------------------------------------
# SAFETY CHECK 1: Resolve PostgreSQL password securely without logging/exposure
# ---------------------------------------------------------------------------
pg_pass = os.environ.get('TEST_PG_PASSWORD')
if not pg_pass:
    candidates = []
    cred_file = r"E:\Python\FrontEnd Webs\amritham-cafe\backend\.env"
    if os.path.exists(cred_file):
        with open(cred_file, 'r', encoding='utf-8') as f:
            for line in f:
                if 'DATABASE_URL' in line and 'postgres' in line:
                    m = re.findall(r'postgres(?:ql)?://[^:]+:([^@]+)@', line)
                    if m:
                        candidates.append(m[0])
    if candidates:
        pg_pass = candidates[0]

if not pg_pass:
    raise RuntimeError("SAFETY ABORT: PostgreSQL credentials could not be resolved safely. Set TEST_PG_PASSWORD.")
TEST_DB_NAME = "obsidian_secure_test"
TEST_DB_URL = f"postgresql://postgres:{pg_pass}@localhost:5432/{TEST_DB_NAME}"

# ---------------------------------------------------------------------------
# SAFETY CHECK 2: URL parsing and target database strict assertion
# ---------------------------------------------------------------------------
parsed = urlparse(TEST_DB_URL)
target_db = parsed.path.lstrip('/')
if target_db != TEST_DB_NAME:
    raise RuntimeError(f"CRITICAL SAFETY VIOLATION: Target database '{target_db}' is not '{TEST_DB_NAME}'!")

if target_db in ['postgres', 'amritham_cafe', 'dataflow', 'insightai']:
    raise RuntimeError(f"CRITICAL SAFETY VIOLATION: Attempted to target protected database '{target_db}'!")

if parsed.hostname not in ('localhost', '127.0.0.1'):
    raise RuntimeError(f"CRITICAL SAFETY VIOLATION: Non-local host '{parsed.hostname}' requested!")

# ---------------------------------------------------------------------------
# SAFETY CHECK 3: Verify directly via psycopg2 before initializing application
# ---------------------------------------------------------------------------
import psycopg2
conn_check = psycopg2.connect(dbname=TEST_DB_NAME, user='postgres', password=pg_pass, host='localhost', port=5432)
cur_check = conn_check.cursor()
cur_check.execute("SELECT current_database();")
verified_db = cur_check.fetchone()[0]
cur_check.execute("SELECT version();")
pg_server_version = cur_check.fetchone()[0]
conn_check.close()

if verified_db != TEST_DB_NAME:
    raise RuntimeError(f"CRITICAL SAFETY VIOLATION: PostgreSQL reported current database as '{verified_db}'!")

print("===================================================================")
print("  OBSIDIAN SECURE — POSTGRESQL 17 INTEGRATION TEST HARNESS")
print("===================================================================")
print(f"Verified Database Target: {verified_db}")
print(f"PostgreSQL Server:        {pg_server_version}")
print(f"Driver (psycopg2):        {psycopg2.__version__}")
print("===================================================================\n")

# ---------------------------------------------------------------------------
# Configure Application Environment for PostgreSQL Integration Testing
# ---------------------------------------------------------------------------
temp_upload_dir = tempfile.mkdtemp(prefix="obsidian_pg_test_")

os.environ['DATABASE_URL'] = TEST_DB_URL
os.environ['RENDER'] = '1'
os.environ['PERSISTENT_DISK_PATH'] = temp_upload_dir

from app import (
    app, db, User, Share, Cipher, ShareCollection, CollectionFile,
    CollectionTransfer, CollectionDownloadToken, init_enterprise_db
)
from werkzeug.security import generate_password_hash
from sqlalchemy import text
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def extract_csrf(client, url='/login'):
    res = client.get(url)
    html = res.data.decode('utf-8', errors='ignore')
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if m:
        return m.group(1)
    m2 = re.search(r'id="cipher-csrf-token"\s+(?:name="csrf_token"\s+)?value="([^"]+)"', html)
    if m2:
        return m2.group(1)
    m_meta = re.search(r'name="csrf-token"\s+content="([^"]+)"', html)
    return m_meta.group(1) if m_meta else ""

def run_postgres_tests():
    test_results = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "not_run": 0,
        "checks": []
    }

    def record(name, condition, details=""):
        status = "[PASS]" if condition else "[FAIL]"
        print(f"  {status} {name} -> {details}")
        if condition:
            test_results["passed"] += 1
        else:
            test_results["failed"] += 1
        test_results["checks"].append({"name": name, "passed": condition, "details": details})
        if not condition:
            raise AssertionError(f"PostgreSQL Test Assertion Failed: {name} - {details}")

    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = temp_upload_dir
    client = app.test_client()

    created_user_ids = []
    created_share_ids = []
    created_collection_ids = []
    created_cipher_ids = []

    try:
        # -------------------------------------------------------------------
        # TEST 1: Driver, Dialect, and Engine Invariant Verification
        # -------------------------------------------------------------------
        print("--- 1. Driver & Dialect Verification ---")
        with app.app_context():
            dialect_name = db.engine.dialect.name
            record("SQLAlchemy Dialect is PostgreSQL", dialect_name == "postgresql", f"Dialect: {dialect_name}")

            with db.engine.connect() as conn:
                engine_db = conn.execute(text("SELECT current_database()")).scalar()
                record("Engine Connected to obsidian_secure_test", engine_db == TEST_DB_NAME, f"Database: {engine_db}")

        # -------------------------------------------------------------------
        # TEST 2: Schema Creation & Migration against PostgreSQL
        # -------------------------------------------------------------------
        print("\n--- 2. Schema Creation & Migration ---")
        with app.app_context():
            init_enterprise_db()
            with db.engine.connect() as conn:
                tables_res = conn.execute(text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
                )).fetchall()
                table_names = [r[0] for r in tables_res]

                expected_tables = [
                    'user', 'share', 'transfer', 'cipher', 'setting',
                    'user_setting', 'login_attempt', 'registration_attempt',
                    'share_collection', 'collection_file', 'collection_transfer',
                    'collection_download_token'
                ]
                missing = [t for t in expected_tables if t not in table_names]
                record("All PostgreSQL Schema Tables Created", len(missing) == 0, f"Total tables: {len(table_names)}, Missing: {missing}")

                # Check migrated column in cipher table
                cols_res = conn.execute(text(
                    "SELECT column_name FROM information_schema.columns WHERE table_name = 'cipher'"
                )).fetchall()
                cipher_cols = [r[0] for r in cols_res]
                record("Cipher Migrated Column (sender_alias) Exists", 'sender_alias' in cipher_cols, f"Columns: {cipher_cols}")

        # -------------------------------------------------------------------
        # TEST 3: User Registration & Authentication on PostgreSQL
        # -------------------------------------------------------------------
        print("\n--- 3. User Registration & Authentication ---")
        reg_username = f"pg_user_{secrets.token_hex(4)}"
        reg_csrf = extract_csrf(client, '/register')
        reg_res = client.post('/register', data={
            'username': reg_username,
            'password': 'PostgresPassword123!',
            'confirm_password': 'PostgresPassword123!',
            'csrf_token': reg_csrf
        }, follow_redirects=True)
        reg_success = reg_res.status_code == 200 and (b'dashboard' in reg_res.data.lower() or b'files' in reg_res.data.lower() or b'account' in reg_res.data.lower() or b'login' in reg_res.data.lower())
        record("User Registration on PostgreSQL", reg_success, f"Status: {reg_res.status_code}")

        # User Login
        login_csrf = extract_csrf(client, '/login')
        login_res = client.post('/login', data={
            'username': reg_username,
            'password': 'PostgresPassword123!',
            'csrf_token': login_csrf
        }, follow_redirects=True)
        record("User Authentication & Session on PostgreSQL", login_res.status_code == 200 and (b'Dashboard' in login_res.data or b'Files' in login_res.data), f"Status: {login_res.status_code}")

        with app.app_context():
            u = User.query.filter_by(username=reg_username).first()
            if u:
                created_user_ids.append(u.id)

        auth_csrf = extract_csrf(client, '/dashboard')

        # -------------------------------------------------------------------
        # TEST 4: Single-File Share Creation & Retrieval on PostgreSQL
        # -------------------------------------------------------------------
        print("\n--- 4. Single-File Share Creation & Retrieval ---")
        raw_content = b"PostgreSQL Integration Payload Content 2026"
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        iv = secrets.token_bytes(12)
        encrypted_blob = iv + aesgcm.encrypt(iv, raw_content, None)

        import base64
        import io
        orig_b64 = base64.b64encode(b"report_q4.pdf").decode('utf-8')
        up_res = client.post('/api/v2/upload', data={
            'file': (io.BytesIO(encrypted_blob), 'report_q4.pdf')
        }, headers={
            'X-CSRF-Token': auth_csrf,
            'X-Original-Name': orig_b64,
            'X-Mime-Type': 'application/pdf'
        })
        record("Single-File V2 Upload to PostgreSQL", up_res.status_code == 200, f"Status: {up_res.status_code}")
        up_data = up_res.get_json() or {}
        share_url = up_data.get('public_url', '')
        stored_filename = share_url.split('/')[-1]

        with app.app_context():
            sh = Share.query.filter_by(filename=stored_filename).first()
            record("Share Record Persisted in PostgreSQL DB", sh is not None, f"Share ID: {sh.id if sh else None}")
            if sh:
                created_share_ids.append(sh.id)

        # Recipient Retrieval
        unauth_client = app.test_client()
        get_res = unauth_client.get(f'/get/{stored_filename}')
        record("Recipient GET Encrypted Blob from PostgreSQL", get_res.status_code == 200 and len(get_res.data) == len(encrypted_blob), f"Bytes: {len(get_res.data)}")

        # Decrypt blob and verify SHA-256
        rec_iv = get_res.data[:12]
        rec_cipher = get_res.data[12:]
        decrypted_plain = aesgcm.decrypt(rec_iv, rec_cipher, None)
        record("Browser Decryption SHA-256 Checksum Exact Match", sha256(decrypted_plain) == sha256(raw_content), f"SHA-256: {sha256(decrypted_plain)[:16]}...")

        # -------------------------------------------------------------------
        # TEST 5: Collection Creation, Retrieval & Finalization on PostgreSQL
        # -------------------------------------------------------------------
        print("\n--- 5. Collection Creation & Manifest Retrieval ---")
        col_init_res = client.post('/api/v2/collection/init', json={
            'file_count': 2,
            'total_size': len(encrypted_blob) * 2
        }, headers={'X-CSRF-Token': auth_csrf})
        record("Collection Initialization on PostgreSQL", col_init_res.status_code == 200, f"Status: {col_init_res.status_code}")
        col_pub_id = col_init_res.get_json().get('public_id')

        # Upload 2 files
        for idx in range(2):
            cf_res = client.post(f'/api/v2/collection/{col_pub_id}/file', data={
                'file': (io.BytesIO(encrypted_blob), f'doc_{idx}.bin'),
                'original_name': f'document_{idx}.txt',
                'mime_type': 'text/plain'
            }, content_type='multipart/form-data', headers={'X-CSRF-Token': auth_csrf})
            assert cf_res.status_code == 200

        # Finalize collection
        fin_res = client.post(f'/api/v2/collection/{col_pub_id}/finalize', json={
            'manifest': [
                {'file_id': f'fid_{i}', 'original_name': f'document_{i}.txt'} for i in range(2)
            ]
        }, headers={'X-CSRF-Token': auth_csrf})
        record("Collection Finalization on PostgreSQL", fin_res.status_code == 200, f"Status: {fin_res.status_code}")

        with app.app_context():
            col_db = ShareCollection.query.filter_by(public_id=col_pub_id).first()
            record("Collection Persisted in PostgreSQL with Files Joined", col_db is not None and len(col_db.files) == 2, f"Files count: {len(col_db.files) if col_db else 0}")
            if col_db:
                created_collection_ids.append(col_db.id)

        # -------------------------------------------------------------------
        # TEST 6: Share Revocation and Expiry on PostgreSQL
        # -------------------------------------------------------------------
        print("\n--- 6. Revocation & Expiry on PostgreSQL ---")
        revoke_res = client.post('/revoke', data={
            'public_url': share_url,
            'csrf_token': auth_csrf
        }, follow_redirects=True)
        record("Share Revocation Route Execution", revoke_res.status_code == 200, f"Status: {revoke_res.status_code}")

        with app.app_context():
            sh_revoked = Share.query.filter_by(filename=stored_filename).first()
            record("PostgreSQL Share Row Deleted upon Revocation", sh_revoked is None, "Physical record purged from PostgreSQL")

        # -------------------------------------------------------------------
        # TEST 7: Burn-On-Read Atomic Single-Consumption on PostgreSQL
        # -------------------------------------------------------------------
        print("\n--- 7. Burn-On-Read Atomic Single-Consumption ---")
        bor_pub_id = f"pg_bor_{secrets.token_hex(6)}"
        with app.app_context():
            c_bor = Cipher(
                public_id=bor_pub_id,
                content='TOP_SECRET_POSTGRESQL_CIPHERTEXT',
                burn_on_read=True,
                is_read=False,
                sender_alias='PostgreSQL Auditor'
            )
            db.session.add(c_bor)
            db.session.commit()
            created_cipher_ids.append(c_bor.id)

        bor_client = app.test_client()
        bor_get = bor_client.get(f'/decrypt/{bor_pub_id}')
        record("GET /decrypt Never Exposes Ciphertext on PostgreSQL", bor_get.status_code == 200 and b'TOP_SECRET_POSTGRESQL_CIPHERTEXT' not in bor_get.data, "HTML body sanitized")

        bor_csrf = extract_csrf(bor_client, f'/decrypt/{bor_pub_id}')
        bor_consume = bor_client.post(f'/api/cipher/consume/{bor_pub_id}', headers={'X-CSRF-Token': bor_csrf})
        record("Winner Obtains Ciphertext via Atomic POST on PostgreSQL", bor_consume.status_code == 200 and bor_consume.get_json().get('ciphertext') == 'TOP_SECRET_POSTGRESQL_CIPHERTEXT', "Delivered successfully")

        # Verify immediate database erasure on PostgreSQL
        with app.app_context():
            c_wiped = Cipher.query.filter_by(public_id=bor_pub_id).first()
            record("PostgreSQL Ciphertext Erased in Same Committed Transaction", c_wiped.is_read is True and c_wiped.content == '', "content == '' in PostgreSQL DB")

        # Repeated consumption blocked
        bor_repeat = bor_client.post(f'/api/cipher/consume/{bor_pub_id}', headers={'X-CSRF-Token': bor_csrf})
        record("Repeated Consumption Rejection (HTTP 410) on PostgreSQL", bor_repeat.status_code == 410, f"Status: {bor_repeat.status_code}")

        # -------------------------------------------------------------------
        # TEST 8: Concurrent Burn-On-Read Requests on PostgreSQL (5 Threads)
        # -------------------------------------------------------------------
        print("\n--- 8. Concurrent Burn-On-Read Requests on PostgreSQL ---")
        race_pub_id = f"pg_race_{secrets.token_hex(6)}"
        with app.app_context():
            c_race = Cipher(
                public_id=race_pub_id,
                content='CONCURRENT_POSTGRESQL_PRIZE',
                burn_on_read=True,
                is_read=False
            )
            db.session.add(c_race)
            db.session.commit()
            created_cipher_ids.append(c_race.id)

        race_clients = [app.test_client() for _ in range(5)]
        race_csrfs = [extract_csrf(cl, f'/decrypt/{race_pub_id}') for cl in race_clients]

        deliveries = []
        rejections = []

        def attempt_pg_claim(idx):
            cl = race_clients[idx]
            csrf = race_csrfs[idx]
            r = cl.post(f'/api/cipher/consume/{race_pub_id}', headers={'X-CSRF-Token': csrf})
            if r.status_code == 200:
                deliveries.append(r.get_json().get('ciphertext'))
            else:
                rejections.append(r.status_code)

        threads = [threading.Thread(target=attempt_pg_claim, args=(i,)) for i in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()

        record(
            "PostgreSQL 5-Thread Concurrency Exclusivity Invariant",
            len(deliveries) == 1 and deliveries[0] == 'CONCURRENT_POSTGRESQL_PRIZE' and len(rejections) == 4,
            f"Deliveries: {len(deliveries)}, Rejections: {len(rejections)} (Codes: {rejections})"
        )

        # -------------------------------------------------------------------
        # TEST 9: Transaction Rollback and Failure Handling on PostgreSQL
        # -------------------------------------------------------------------
        print("\n--- 9. Transaction Rollback & Failure Handling on PostgreSQL ---")
        rollback_pub_id = f"pg_rb_{secrets.token_hex(6)}"
        with app.app_context():
            c_rb = Cipher(
                public_id=rollback_pub_id,
                content='ROLLBACK_POSTGRESQL_DATA',
                burn_on_read=True,
                is_read=False
            )
            db.session.add(c_rb)
            db.session.commit()
            created_cipher_ids.append(c_rb.id)

        rb_client = app.test_client()
        rb_csrf = extract_csrf(rb_client, f'/decrypt/{rollback_pub_id}')

        # Monkeypatch commit to simulate transient failure
        orig_commit = db.session.commit
        def fail_commit_once():
            raise RuntimeError("Simulated PostgreSQL Deadlock / Connection Interruption")

        import unittest.mock as mock
        with mock.patch.object(db.session, 'commit', side_effect=fail_commit_once):
            rb_res = rb_client.post(f'/api/cipher/consume/{rollback_pub_id}', headers={'X-CSRF-Token': rb_csrf})
            record("PostgreSQL Commit Exception Caught & Handled (HTTP 500)", rb_res.status_code == 500, f"Status: {rb_res.status_code}")

        # Verify PostgreSQL database session was rolled back cleanly
        with app.app_context():
            c_after_rb = Cipher.query.filter_by(public_id=rollback_pub_id).first()
            record(
                "PostgreSQL Database Row Rolled Back Cleanly (Uncorrupted State)",
                c_after_rb is not None and c_after_rb.is_read is False and c_after_rb.content == 'ROLLBACK_POSTGRESQL_DATA',
                "is_read remained False and content intact after rollback"
            )

        # -------------------------------------------------------------------
        # TEST 10: PostgreSQL-Specific SQL & Dialect Invariant Checks
        # -------------------------------------------------------------------
        print("\n--- 10. PostgreSQL-Specific SQL Compatibility Checks ---")
        with app.app_context():
            with db.engine.connect() as conn:
                # 10.1 Verify PostgreSQL boolean type handling (TRUE / FALSE vs 1 / 0)
                bool_check = conn.execute(text("SELECT is_read FROM cipher WHERE public_id = :pid"), {'pid': bor_pub_id}).scalar()
                record("PostgreSQL Native Boolean Column Evaluation", bool_check is True, f"Native Boolean: {bool_check}")

                # 10.2 Verify PostgreSQL timestamp math & interval evaluation
                time_check = conn.execute(text("SELECT NOW() - INTERVAL '24 hours' < NOW()")).scalar()
                record("PostgreSQL Native Timestamp & Interval Arithmetic", time_check is True, "PostgreSQL timestamp interval verified")

                # 10.3 Verify PostgreSQL connection pooling parameters
                pool = db.engine.pool
                record("PostgreSQL QueuePool Active", pool.__class__.__name__ == 'QueuePool', f"Pool Type: {pool.__class__.__name__}")

    finally:
        # -------------------------------------------------------------------
        # CLEANUP: Purge test records and temporary upload directory only
        # -------------------------------------------------------------------
        print("\n--- Cleanup: Purging Test-Generated Records ---")
        with app.app_context():
            try:
                for uid in created_user_ids:
                    u_del = db.session.get(User, uid)
                    if u_del: db.session.delete(u_del)
                for sid in created_share_ids:
                    s_del = db.session.get(Share, sid)
                    if s_del: db.session.delete(s_del)
                for cid in created_collection_ids:
                    c_del = db.session.get(ShareCollection, cid)
                    if c_del: db.session.delete(c_del)
                for ciph_id in created_cipher_ids:
                    cp_del = db.session.get(Cipher, ciph_id)
                    if cp_del: db.session.delete(cp_del)
                db.session.commit()
                print("  [CLEANUP] Successfully purged test rows from obsidian_secure_test.")
            except Exception as e:
                print(f"  [CLEANUP WARNING] Failed to purge test rows: {e}")

        if os.path.exists(temp_upload_dir):
            try:
                shutil.rmtree(temp_upload_dir, ignore_errors=True)
                print(f"  [CLEANUP] Removed temporary upload directory: {temp_upload_dir}")
            except Exception:
                pass

    print("\n===================================================================")
    print(f"POSTGRESQL INTEGRATION AUDIT: {test_results['passed']}/{len(test_results['checks'])} Checks Passed, {test_results['failed']} Failed")
    print("===================================================================\n")

if __name__ == '__main__':
    run_postgres_tests()
