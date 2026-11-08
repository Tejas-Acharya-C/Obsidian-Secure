"""
Obsidian Secure — Advisory Lock Concurrency & Cleanup Safety Suite
Strictly isolated to database: obsidian_secure_test
"""
import os, sys, re, threading, time, tempfile
from urllib.parse import urlparse
from sqlalchemy import create_engine, text

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# 1. Resolve PostgreSQL test database password safely
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

temp_upload_dir = tempfile.mkdtemp(prefix="obsidian_adv_test_")
os.environ['DATABASE_URL'] = TEST_DB_URL
os.environ['RENDER'] = '1'
os.environ['PERSISTENT_DISK_PATH'] = temp_upload_dir

from app import app, db, CrossProcessLock

def run():
    print("===================================================================")
    print("  OBSIDIAN SECURE — ADVISORY LOCK & CONCURRENCY SUITE")
    print("===================================================================")

    engine = create_engine(TEST_DB_URL, pool_size=5, max_overflow=5)
    ADVISORY_LOCK_ID = 98234125

    # Test 1: Multi-Connection Mutual Exclusion
    results = []
    def worker(worker_id):
        conn = engine.connect()
        try:
            res = conn.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": ADVISORY_LOCK_ID}).scalar()
            if res:
                results.append((worker_id, "ACQUIRED"))
                time.sleep(0.3)
                conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": ADVISORY_LOCK_ID})
                results.append((worker_id, "RELEASED"))
            else:
                results.append((worker_id, "SKIPPED"))
        finally:
            conn.close()

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start()
    time.sleep(0.05)
    t2.start()
    t1.join()
    t2.join()

    acquisitions = [r for r in results if r[1] == "ACQUIRED"]
    skips = [r for r in results if r[1] == "SKIPPED"]
    assert len(acquisitions) == 1, f"Expected 1 acquisition, got {len(acquisitions)}"
    assert len(skips) == 1, f"Expected 1 skip, got {len(skips)}"
    print("  [PASS] PostgreSQL Multi-Connection Mutual Exclusion (1 Acquired, 1 Skipped)")

    # Test 2: Connection Invalidation on Failed Unlock (Prevents Leaking Held Lock to Pool)
    conn_faulty = engine.connect()
    res = conn_faulty.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": ADVISORY_LOCK_ID}).scalar()
    assert res == True
    # Invalidate connection to simulate connection error / abort
    conn_faulty.invalidate()
    conn_faulty.close()

    # Next checked out connection must be able to acquire lock
    conn_next = engine.connect()
    res_next = conn_next.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": ADVISORY_LOCK_ID}).scalar()
    assert res_next == True, "Failed to acquire lock after invalidating faulty connection!"
    conn_next.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": ADVISORY_LOCK_ID})
    conn_next.close()
    print("  [PASS] Connection Invalidation Safety (Backend Session Terminated, Zero Lock Leaks)")

    # Test 3: CrossProcessLock Integration Test on Live Engine
    with app.app_context():
        lock_pg = CrossProcessLock(is_pg=True)
        lock_pg.LOCK_ID = 98234125
        assert lock_pg.acquire() == True, "Failed to acquire lock via CrossProcessLock"

        lock_pg2 = CrossProcessLock(is_pg=True)
        lock_pg2.LOCK_ID = 98234125
        assert lock_pg2.acquire() == False, "CrossProcessLock allowed concurrent acquisition!"

        lock_pg.release()
        assert lock_pg2.acquire() == True, "CrossProcessLock failed to acquire after release"
        lock_pg2.release()
        print("  [PASS] CrossProcessLock PostgreSQL Engine Integration Verified")

        # Test 4: SQLite / FileLock Fallback Verification
        lock_sqlite = CrossProcessLock(is_pg=False)
        assert lock_sqlite.acquire() == True, "SQLite FileLock failed to acquire"
        lock_sqlite2 = CrossProcessLock(is_pg=False)
        assert lock_sqlite2.acquire() == False, "SQLite FileLock allowed concurrent acquisition!"
        lock_sqlite.release()
        assert lock_sqlite2.acquire() == True, "SQLite FileLock failed to acquire after release"
        lock_sqlite2.release()
        print("  [PASS] CrossProcessLock SQLite FileLock Backend Verification Verified")

    # Cleanup temp upload dir
    try:
        import shutil
        shutil.rmtree(temp_upload_dir, ignore_errors=True)
    except Exception:
        pass

    print("===================================================================")
    print("ADVISORY LOCK & CONCURRENCY SUITE COMPLETE: 4/4 Checks Passed")
    print("===================================================================\n")

if __name__ == '__main__':
    run()
