import os
import sys
import time
import json
import base64
import subprocess
import threading
import urllib.request
import websocket
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE_DIR)

from app import app, db
from models import User, Share, ShareCollection, CollectionFile, Cipher
from flask import request, redirect
from flask_login import login_user

# Add temporary dev login route for authenticated dashboard / active-shares pages
if not any(r.rule == '/_dev_login_test' for r in app.url_map.iter_rules()):
    @app.route('/_dev_login_test')
    def dev_login_test():
        user = User.query.filter_by(username='audit_user').first()
        if user:
            login_user(user)
        next_url = request.args.get('next', '/dashboard')
        return redirect(next_url)

PORT = 5058
CDP_PORT = 9223
BASE_URL = f"http://127.0.0.1:{PORT}"
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

VIEWPORTS = [
    (320, 640),
    (360, 640),
    (375, 667),
    (390, 844),
    (430, 932),
    (768, 1024),
    (1024, 768),
    (1280, 800),
    (1440, 900),
    (1920, 1080),
]

PAGES = [
    ("landing", "/"),
    ("login", "/login"),
    ("register", "/register"),
    ("dashboard", "/_dev_login_test?next=/dashboard"),
    ("active_shares", "/_dev_login_test?next=/active-shares"),
    ("recipient_single", "/download/financial_audit_2026.pdf#key=demo_key_123"),
    ("recipient_collection", "/collection/pkg_audit_demo#key=demo_key_123"),
    ("cipher_reader", "/decrypt/cipher_audit_demo#key=demo_key_123"),
]

def seed_database():
    with app.app_context():
        user = User.query.filter_by(username='audit_user').first()
        if not user:
            user = User(username='audit_user', password_hash=generate_password_hash('AuditPassword123!'))
            db.session.add(user)
            db.session.commit()

        share = Share.query.filter_by(filename='financial_audit_2026.pdf').first()
        if not share:
            share = Share(
                filename='financial_audit_2026.pdf',
                original_name='financial_audit_2026.pdf',
                mime_type='application/pdf',
                upload_time=datetime.utcnow() - timedelta(hours=2),
                expiry_time=datetime.utcnow() + timedelta(days=2),
                download_count=3,
                public_url=f'{BASE_URL}/download/financial_audit_2026.pdf',
                user_id=user.id,
                version=2
            )
            db.session.add(share)

        share2 = Share.query.filter_by(filename='security_key_backup.kdbx').first()
        if not share2:
            share2 = Share(
                filename='security_key_backup.kdbx',
                original_name='security_key_backup.kdbx',
                mime_type='application/octet-stream',
                upload_time=datetime.utcnow() - timedelta(minutes=45),
                expiry_time=datetime.utcnow() + timedelta(hours=1),
                download_count=1,
                public_url=f'{BASE_URL}/download/security_key_backup.kdbx',
                user_id=user.id,
                version=2
            )
            db.session.add(share2)

        col = ShareCollection.query.filter_by(public_id='pkg_audit_demo').first()
        if not col:
            col = ShareCollection(
                public_id='pkg_audit_demo',
                user_id=user.id,
                created_at=datetime.utcnow() - timedelta(hours=1),
                expiry_time=datetime.utcnow() + timedelta(days=2),
                download_count=2,
                is_revoked=False,
                is_finalized=True,
                total_size=3850000,
                file_count=2,
                public_url=f'{BASE_URL}/collection/pkg_audit_demo'
            )
            db.session.add(col)
            db.session.commit()

            f1 = CollectionFile(
                collection_id=col.id,
                file_id='file_audit_1',
                stored_filename='cf1.bin',
                original_name='client_ledger_q4_2026.xlsx',
                file_size=1500000,
                mime_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
            f2 = CollectionFile(
                collection_id=col.id,
                file_id='file_audit_2',
                stored_filename='cf2.bin',
                original_name='executive_summary_report.pdf',
                file_size=2350000,
                mime_type='application/pdf'
            )
            db.session.add_all([f1, f2])

        cip = Cipher.query.filter_by(public_id='cipher_audit_demo').first()
        if not cip:
            cip = Cipher(
                public_id='cipher_audit_demo',
                content='U2FsdGVkX18AuditDemoCiphertextPayload==',
                burn_on_read=True,
                is_read=False,
                sender_alias='Obsidian Lead Architect'
            )
            db.session.add(cip)

        db.session.commit()
        print("Database seeded successfully.")

def run_flask():
    app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False)

def main():
    seed_database()

    # Start Flask
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    time.sleep(2)

    try:
        urllib.request.urlopen(f"{BASE_URL}/")
        print(f"Flask running at {BASE_URL}")
    except Exception as e:
        print(f"Flask start failed: {e}")
        return

    # Start Chrome with remote debugging
    chrome_proc = subprocess.Popen([
        CHROME_PATH,
        "--headless=new",
        "--disable-gpu",
        f"--remote-debugging-port={CDP_PORT}",
        "--remote-allow-origins=*",
        "about:blank"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    try:
        req = urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json")
        tabs = json.loads(req.read().decode())
        ws_url = tabs[0]["webSocketDebuggerUrl"]
        print(f"Connected to CDP debugger at {ws_url}")
        ws = websocket.create_connection(ws_url)

        _msg_id = 0
        def send_cdp(method, params=None):
            nonlocal _msg_id
            _msg_id += 1
            payload = {"id": _msg_id, "method": method}
            if params is not None:
                payload["params"] = params
            ws.send(json.dumps(payload))
            while True:
                resp = json.loads(ws.recv())
                if resp.get("id") == _msg_id:
                    return resp.get("result", {})

        send_cdp("Page.enable")
        send_cdp("Network.enable")

        results = []
        total = len(VIEWPORTS) * len(PAGES)
        count = 0
        start_time = time.time()

        print(f"Running CDP audit across {len(VIEWPORTS)} viewports x {len(PAGES)} pages ({total} combinations)...")

        for width, height in VIEWPORTS:
            # Emulate precise viewport
            is_mobile = width < 768
            send_cdp("Emulation.setDeviceMetricsOverride", {
                "width": width,
                "height": height,
                "deviceScaleFactor": 1,
                "mobile": is_mobile
            })

            for page_name, path in PAGES:
                count += 1
                url = f"{BASE_URL}{path}"
                send_cdp("Page.navigate", {"url": url})
                time.sleep(0.4)  # Allow rendering to settle

                # Measure exact metrics
                eval_res = send_cdp("Runtime.evaluate", {
                    "expression": """
                    (function() {
                        var iw = window.innerWidth;
                        var sw = document.documentElement.scrollWidth;
                        var cw = document.documentElement.clientWidth;
                        var ov = (sw > cw) ? (sw - cw) : 0;
                        return JSON.stringify({
                            innerWidth: iw,
                            scrollWidth: sw,
                            clientWidth: cw,
                            overflowPx: ov
                        });
                    })()
                    """,
                    "returnByValue": True
                })

                val_str = eval_res.get("value", "{}")
                try:
                    metrics = json.loads(val_str)
                except Exception:
                    metrics = {"innerWidth": width, "scrollWidth": width, "clientWidth": width, "overflowPx": 0}

                # Capture full screenshot
                screenshot_res = send_cdp("Page.captureScreenshot", {"format": "png"})
                img_data = screenshot_res.get("data", "")
                output_file = os.path.join(SCREENSHOT_DIR, f"{page_name}_{width}px.png")
                if img_data:
                    with open(output_file, "wb") as img_f:
                        img_f.write(base64.b64decode(img_data))

                exists = os.path.exists(output_file)
                size = os.path.getsize(output_file) if exists else 0

                results.append({
                    "page": page_name,
                    "width": width,
                    "height": height,
                    "inner_width": metrics.get("innerWidth", width),
                    "client_width": metrics.get("clientWidth", width),
                    "scroll_width": metrics.get("scrollWidth", width),
                    "overflow_px": metrics.get("overflowPx", 0),
                    "has_horizontal_overflow": metrics.get("overflowPx", 0) > 0,
                    "success": exists and size > 0,
                    "size_bytes": size,
                    "file": output_file
                })

                if count % 10 == 0 or count == total:
                    print(f"  CDP Progress: {count}/{total} checked ({time.time() - start_time:.1f}s)")

        ws.close()

        # Save manifest
        manifest_path = os.path.join(SCREENSHOT_DIR, "manifest.json")
        with open(manifest_path, "w") as mf:
            json.dump(results, mf, indent=2)

        duration = time.time() - start_time
        overflow_count = sum(1 for r in results if r["has_horizontal_overflow"])
        print(f"\nAudit Complete: {len(results)}/{total} captured in {duration:.1f}s.")
        print(f"Total pages with horizontal overflow: {overflow_count}")

        if overflow_count > 0:
            print("\n--- OVERFLOW DETAILS ---")
            for r in results:
                if r["has_horizontal_overflow"]:
                    print(f"  [OVERFLOW] {r['page']} @ {r['width']}px: clientWidth={r['client_width']}px, scrollWidth={r['scroll_width']}px (+{r['overflow_px']}px)")

    finally:
        chrome_proc.terminate()

if __name__ == '__main__':
    main()
