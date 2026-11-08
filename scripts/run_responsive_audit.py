import os
import sys
import time
import subprocess
import threading
import json
import re
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE_DIR)

from app import app, db
from models import User, Share, ShareCollection, CollectionFile, Cipher
from flask import request, redirect
from flask_login import login_user

# Add temporary test route if not already added
if not any(r.rule == '/_dev_login_test' for r in app.url_map.iter_rules()):
    @app.route('/_dev_login_test')
    def dev_login_test():
        user = User.query.filter_by(username='audit_user').first()
        if user:
            login_user(user)
        next_url = request.args.get('next', '/dashboard')
        return redirect(next_url)

# Inject layout measurement tag for headless audit
@app.after_request
def inject_layout_audit(response):
    if response.content_type.startswith('text/html') and response.status_code == 200:
        data = response.get_data(as_text=True)
        diag = """
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var sw = document.documentElement.scrollWidth;
            var cw = document.documentElement.clientWidth;
            var ov = (sw > cw) ? (sw - cw) : 0;
            var tag = document.createElement('meta');
            tag.name = 'layout-audit';
            tag.setAttribute('data-sw', sw);
            tag.setAttribute('data-cw', cw);
            tag.setAttribute('data-overflow', ov);
            document.head.appendChild(tag);
        });
        </script>
        """
        if '</head>' in data:
            response.set_data(data.replace('</head>', diag + '</head>'))
    return response

PORT = 5055
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

def run_server():
    app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False)

def main():
    seed_database()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(2)

    import urllib.request
    try:
        resp = urllib.request.urlopen(f"{BASE_URL}/")
        print(f"Server alive on {BASE_URL}, status: {resp.status}")
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        return

    user_data_dir = os.path.join(BASE_DIR, "screenshots", "chrome_profile")
    os.makedirs(user_data_dir, exist_ok=True)

    results = []
    total = len(VIEWPORTS) * len(PAGES)
    count = 0

    print(f"Beginning screenshot capture and layout audit: {total} combinations...")
    start_time = time.time()

    for width, height in VIEWPORTS:
        for page_name, path in PAGES:
            count += 1
            url = f"{BASE_URL}{path}"
            output_file = os.path.join(SCREENSHOT_DIR, f"{page_name}_{width}px.png")

            # 1. Capture screenshot and dump DOM
            cmd = [
                CHROME_PATH,
                "--headless=new",
                "--disable-gpu",
                "--hide-scrollbars",
                f"--user-data-dir={user_data_dir}",
                f"--window-size={width},{height}",
                f"--screenshot={output_file}",
                "--dump-dom",
                url
            ]

            res = subprocess.run(cmd, capture_output=True, text=True)
            dom_text = res.stdout or ""

            # 2. Extract layout audit meta tag
            sw = width
            cw = width
            overflow = 0

            m_sw = re.search(r'data-sw=["\'](\d+)["\']', dom_text)
            m_cw = re.search(r'data-cw=["\'](\d+)["\']', dom_text)
            m_ov = re.search(r'data-overflow=["\'](\d+)["\']', dom_text)

            if m_sw: sw = int(m_sw.group(1))
            if m_cw: cw = int(m_cw.group(1))
            if m_ov: overflow = int(m_ov.group(1))

            exists = os.path.exists(output_file)
            size = os.path.getsize(output_file) if exists else 0

            results.append({
                "page": page_name,
                "width": width,
                "height": height,
                "scroll_width": sw,
                "client_width": cw,
                "overflow_px": overflow,
                "has_horizontal_overflow": overflow > 0,
                "success": exists and size > 0,
                "size_bytes": size,
                "file": output_file
            })

            if count % 10 == 0 or count == total:
                print(f"Progress: {count}/{total} checked ({time.time() - start_time:.1f}s)")

    duration = time.time() - start_time
    success_count = sum(1 for r in results if r["success"])
    overflow_count = sum(1 for r in results if r["has_horizontal_overflow"])
    print(f"\nAudit Complete: {success_count}/{total} screenshots captured in {duration:.1f}s.")
    print(f"Layout overflow checks: {overflow_count} pages with horizontal overflow detected.")

    with open(os.path.join(SCREENSHOT_DIR, "manifest.json"), "w") as f:
        json.dump(results, f, indent=2)

    if overflow_count > 0:
        print("\n--- OVERFLOW WARNINGS ---")
        for r in results:
            if r["has_horizontal_overflow"]:
                print(f"  Page: {r['page']} at {r['width']}px -> scrollWidth: {r['scroll_width']}px (Overflow: +{r['overflow_px']}px)")

if __name__ == '__main__':
    main()
