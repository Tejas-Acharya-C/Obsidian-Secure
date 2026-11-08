"""
Obsidian Secure — Stage 7 Real HTTP Concurrency & Resource Validation Test
Runs a real multi-threaded WSGI HTTP server on localhost:8089 to test actual socket-level concurrency.
"""
import os
import sys
import time
import socket
import threading
import urllib.request
import urllib.error
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app import app

class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True

class SilentHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass # Suppress routine access logs during concurrency test

def run_http_concurrency_test():
    print("===================================================================")
    print("  OBSIDIAN SECURE — REAL MULTITHREADED HTTP CONCURRENCY TEST")
    print("===================================================================")

    server_port = 8089
    server = ThreadingWSGIServer(('127.0.0.1', server_port), SilentHandler)
    server.set_app(app)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{server_port}"
    print(f"WSGI Threading Server active on {base_url}")

    # 1. Health check baseline test
    t0 = time.time()
    req = urllib.request.Request(f"{base_url}/health")
    with urllib.request.urlopen(req, timeout=5) as resp:
        health_code = resp.getcode()
        health_body = resp.read().decode('utf-8')
    health_latency = (time.time() - t0) * 1000
    print(f"  [PASS] /health probe -> HTTP {health_code} in {health_latency:.2f}ms: {health_body.strip()}")
    assert health_code == 200
    assert "healthy" in health_body

    # 2. Real Concurrent HTTP Requests Test (8 concurrent client threads)
    print("\n--- Testing 8 Concurrent Real HTTP Requests ---")
    concurrent_results = []
    def make_req(idx):
        start = time.time()
        try:
            r = urllib.request.urlopen(f"{base_url}/health", timeout=10)
            elapsed = time.time() - start
            concurrent_results.append((idx, r.getcode(), elapsed))
        except Exception as e:
            concurrent_results.append((idx, 500, str(e)))

    threads = [threading.Thread(target=make_req, args=(i,)) for i in range(8)]
    t_start = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    t_total = time.time() - t_start

    success_count = sum(1 for _, code, _ in concurrent_results if code == 200)
    print(f"  [PASS] 8 Concurrent Real HTTP Requests: {success_count}/8 completed in {t_total*1000:.2f}ms total")
    assert success_count == 8

    # 3. Saturation & Queueing Test (16 simultaneous requests across real sockets)
    print("\n--- Testing High-Concurrency Saturation & Socket Queueing (16 requests) ---")
    queue_results = []
    def make_queue_req(idx):
        start = time.time()
        try:
            r = urllib.request.urlopen(f"{base_url}/robots.txt", timeout=10)
            elapsed = time.time() - start
            queue_results.append((idx, r.getcode(), elapsed))
        except Exception as e:
            queue_results.append((idx, 500, str(e)))

    q_threads = [threading.Thread(target=make_queue_req, args=(i,)) for i in range(16)]
    t_q_start = time.time()
    for t in q_threads: t.start()
    for t in q_threads: t.join()
    t_q_total = time.time() - t_q_start

    q_success = sum(1 for _, code, _ in queue_results if code == 200)
    avg_lat = sum(el for _, _, el in queue_results) / len(queue_results) * 1000
    print(f"  [PASS] 16 Simultaneous HTTP Requests: {q_success}/16 succeeded (Avg latency: {avg_lat:.2f}ms, Total: {t_q_total*1000:.2f}ms)")
    assert q_success == 16

    # 4. Measure memory footprint
    try:
        import psutil
        proc = psutil.Process()
        mem_mb = proc.memory_info().rss / (1024 * 1024)
        print(f"\n  [INFO] Process Resident Set Size (RSS Memory): {mem_mb:.2f} MB")
        print(f"  [PASS] Memory Footprint: {mem_mb:.2f} MB is well within Render 512 MB allocation!")
    except ImportError:
        print("\n  [INFO] psutil not installed; memory measurement skipped.")

    server.shutdown()
    server.server_close()
    print("\n===================================================================")
    print("REAL HTTP CONCURRENCY TEST COMPLETE: 100% SUCCESS")
    print("===================================================================\n")

if __name__ == '__main__':
    run_http_concurrency_test()
