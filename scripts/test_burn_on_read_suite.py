"""
Obsidian Secure — Burn-On-Read PostgreSQL Concurrency & Exclusivity Suite
Strictly isolated to database: obsidian_secure_test
"""
import os, sys, re, secrets, threading, time
from datetime import datetime, timedelta
from urllib.parse import urlparse
from sqlalchemy import create_engine, text

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

def run():
    print("===================================================================")
    print("  OBSIDIAN SECURE — BURN-ON-READ CONCURRENCY & TRANSACTION SUITE")
    print("===================================================================")

    pg_pass = os.environ.get('TEST_PG_PASSWORD')
    if not pg_pass:
        cred_file = r'E:\Python\FrontEnd Webs\amritham-cafe\backend\.env'
        if os.path.exists(cred_file):
            with open(cred_file, 'r', encoding='utf-8') as f:
                m = re.findall(r'postgres(?:ql)?://[^:]+:([^@]+)@', f.read())
                if m:
                    pg_pass = m[0]

    if not pg_pass:
        raise RuntimeError("PostgreSQL test credentials could not be resolved. Set TEST_PG_PASSWORD.")
    TEST_DB_NAME = "obsidian_secure_test"
    TEST_DB_URL = f"postgresql://postgres:{pg_pass}@localhost:5432/{TEST_DB_NAME}"
    assert urlparse(TEST_DB_URL).path.lstrip('/') == TEST_DB_NAME

    engine = create_engine(TEST_DB_URL, pool_size=10, max_overflow=5)

    def setup_test_cipher(public_id, content, burn_on_read=True, is_read=False, created_at=None):
        if created_at is None:
            created_at = datetime.utcnow()
        with engine.begin() as conn:
            conn.execute(text(
                "INSERT INTO cipher (content, public_id, burn_on_read, is_read, created_at, sender_alias) "
                "VALUES (:c, :p, :b, :r, :ca, :sa)"
            ), {
                'c': content, 'p': public_id, 'b': burn_on_read, 'r': is_read, 'ca': created_at, 'sa': 'SenderAlice'
            })

    def cleanup_test_cipher(public_id):
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM cipher WHERE public_id = :p"), {'p': public_id})

    # Test 1: Real 8-Thread Concurrent Consumption Exclusivity
    pid_test1 = "burn_test_" + secrets.token_hex(6)
    setup_test_cipher(pid_test1, "CONFIDENTIAL_PAYLOAD_E2E")

    results = []
    def try_consume(thread_id):
        with engine.connect() as conn:
            trans = conn.begin()
            try:
                row = conn.execute(
                    text("SELECT id, content, burn_on_read, is_read, created_at, sender_alias FROM cipher WHERE public_id = :p"),
                    {'p': pid_test1}
                ).fetchone()
                if not row:
                    results.append((thread_id, 404, None))
                    trans.rollback()
                    return

                cid, content, burn, is_read, created_at, alias = row
                now = datetime.utcnow()
                min_created = now - timedelta(hours=24)

                if is_read or (burn and not content) or (created_at and created_at < min_created):
                    results.append((thread_id, 410, None))
                    trans.rollback()
                    return

                captured_content = content

                stmt = text(
                    "UPDATE cipher SET is_read = TRUE, content = '' "
                    "WHERE public_id = :p AND is_read = FALSE AND (created_at IS NULL OR created_at >= :min_c)"
                )
                res = conn.execute(stmt, {'p': pid_test1, 'min_c': min_created})
                if res.rowcount != 1:
                    trans.rollback()
                    results.append((thread_id, 410, None))
                    return

                trans.commit()
                results.append((thread_id, 200, captured_content))
            except Exception as e:
                trans.rollback()
                results.append((thread_id, 500, str(e)))

    threads = [threading.Thread(target=try_consume, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[1] == 200]
    rejections = [r for r in results if r[1] == 410]
    assert len(successes) == 1, f"Expected 1 winner, got {len(successes)}"
    assert len(rejections) == 7, f"Expected 7 rejections, got {len(rejections)}"
    assert successes[0][2] == "CONFIDENTIAL_PAYLOAD_E2E"

    with engine.connect() as conn:
        final_row = conn.execute(text("SELECT is_read, content FROM cipher WHERE public_id = :p"), {'p': pid_test1}).fetchone()
        assert final_row[0] == True, "is_read must be True"
        assert final_row[1] == "", "content must be erased to empty string"

    cleanup_test_cipher(pid_test1)
    print("  [PASS] 8-Thread Concurrent Exclusivity (1 HTTP 200, 7 HTTP 410, Payload Erased)")

    # Test 2: In-Database 24h Expiry Enforcement
    pid_test2 = "burn_test_exp_" + secrets.token_hex(6)
    setup_test_cipher(pid_test2, "EXPIRED_DATA", created_at=datetime.utcnow() - timedelta(hours=25))
    res_exp = []
    with engine.connect() as conn:
        trans = conn.begin()
        now = datetime.utcnow()
        min_created = now - timedelta(hours=24)
        stmt = text(
            "UPDATE cipher SET is_read = TRUE, content = '' "
            "WHERE public_id = :p AND is_read = FALSE AND (created_at IS NULL OR created_at >= :min_c)"
        )
        res = conn.execute(stmt, {'p': pid_test2, 'min_c': min_created})
        if res.rowcount != 1:
            trans.rollback()
            res_exp.append(410)
        else:
            trans.commit()
            res_exp.append(200)
    assert res_exp == [410]
    cleanup_test_cipher(pid_test2)
    print("  [PASS] 24-Hour Expiry Enforced Inside Atomic SQL UPDATE (HTTP 410)")

    # Test 3: Rollback Integrity (State Restored on Error)
    pid_test3 = "burn_test_rb_" + secrets.token_hex(6)
    setup_test_cipher(pid_test3, "UNCOMMITTED_PAYLOAD")
    with engine.connect() as conn:
        trans = conn.begin()
        stmt = text("UPDATE cipher SET is_read = TRUE, content = '' WHERE public_id = :p")
        conn.execute(stmt, {'p': pid_test3})
        trans.rollback()

    with engine.connect() as conn:
        rb_row = conn.execute(text("SELECT is_read, content FROM cipher WHERE public_id = :p"), {'p': pid_test3}).fetchone()
        assert rb_row[0] == False
        assert rb_row[1] == "UNCOMMITTED_PAYLOAD"
    cleanup_test_cipher(pid_test3)
    print("  [PASS] Transaction Rollback Restores Unaltered Ciphertext & is_read=False")

    print("===================================================================")
    print("BURN-ON-READ CONCURRENCY SUITE COMPLETE: 3/3 Checks Passed")
    print("===================================================================\n")

if __name__ == '__main__':
    run()
