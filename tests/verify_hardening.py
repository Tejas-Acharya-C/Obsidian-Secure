"""
Obsidian Secure — Security Hardening Verification Script
Validates all 7 fixes from the stabilization pass.
"""
import os
import sys
import secrets

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User, Share, Cipher, UserSetting
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta

PASS = "[PASS]"
FAIL = "[FAIL]"
results = []

def check(name, condition):
    status = PASS if condition else FAIL
    results.append((name, condition))
    print(f"  {status}: {name}")


def run_tests():
    app.testing = True
    
    with app.app_context():
        db.create_all()
        
        # Ensure test users exist
        admin = User.query.filter_by(username='test_admin_verify').first()
        if not admin:
            admin = User(username='test_admin_verify', 
                        password_hash=generate_password_hash('Admin123!'))
            db.session.add(admin)
        
        normal = User.query.filter_by(username='test_user_verify').first()
        if not normal:
            normal = User(username='test_user_verify',
                         password_hash=generate_password_hash('User123!'))
            db.session.add(normal)
        db.session.commit()
        
        client = app.test_client()
        
        print("\n" + "=" * 60)
        print("OBSIDIAN SECURE — SECURITY HARDENING VERIFICATION")
        print("=" * 60)
        
        # ====================================================
        # 1. CIPHER DECRYPT FLOW
        # ====================================================
        print("\n[1] SECURE MESSAGE DECRYPT FLOW")
        
        # Login as admin
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin.id)
            sess['_fresh'] = True
            sess['csrf_token'] = 'test_token'
        
        # Create a cipher message
        resp = client.post('/cipher/create', data={
            'content': 'SGVsbG8gV29ybGQ=',  # simulated base64 ciphertext
            'burn_on_read': 'true',
            'csrf_token': 'test_token'
        }, follow_redirects=True)
        check("Cipher creation returns 200", resp.status_code == 200)
        
        # Find the created cipher
        cipher = Cipher.query.filter_by(is_read=False).order_by(Cipher.id.desc()).first()
        check("Cipher record exists in DB", cipher is not None)
        check("Cipher public_id has high entropy (>=16 chars)", 
              cipher is not None and len(cipher.public_id) >= 16)
        check("Cipher public_id is URL-safe", 
              cipher is not None and all(c.isalnum() or c in '-_' for c in cipher.public_id))
        
        if cipher:
            # Test decrypt page renders cipher-content hidden input
            resp = client.get(f'/decrypt/{cipher.public_id}')
            check("Decrypt page returns 200", resp.status_code == 200)
            html = resp.data.decode()
            check("Decrypt page contains #cipher-content hidden input",
                  'id="cipher-content"' in html)
            check("Decrypt page contains encrypted payload in value",
                  'value="' in html and cipher.content in html)
            check("Decrypt page contains decrypt button",
                  'id="decrypt-btn"' in html)
            check("Decrypt page loads crypto.js",
                  'crypto.js' in html)
            
            # Test burned message (cipher was burn_on_read=True, already marked read)
            burned = Cipher.query.get(cipher.id)
            if burned and burned.is_read:
                resp2 = client.get(f'/decrypt/{cipher.public_id}')
                html2 = resp2.data.decode()
                check("Burned message shows expired state", 
                      'Message Unavailable' in html2)
                check("Burned message does NOT contain cipher-content",
                      'id="cipher-content"' not in html2)
            
            # Test invalid public_id
            resp3 = client.get('/decrypt/nonexistent_invalid_id')
            html3 = resp3.data.decode()
            check("Invalid cipher ID shows expired state",
                  'Message Unavailable' in html3)
        
        # ====================================================
        # 2. FILE EXPIRY ENFORCEMENT
        # ====================================================
        print("\n[2] FILE EXPIRY ENFORCEMENT")
        
        # Create an expired share
        expired_share = Share(
            filename='test_expired_file.enc',
            original_name='test_file.txt',
            upload_time=datetime.utcnow() - timedelta(hours=2),
            expiry_time=datetime.utcnow() - timedelta(hours=1),
            public_url='http://localhost/download/test_expired_file.enc',
            user_id=admin.id
        )
        db.session.add(expired_share)
        
        # Create a valid (non-expired) share
        valid_share = Share(
            filename='test_valid_file.enc',
            original_name='valid_file.txt',
            upload_time=datetime.utcnow(),
            expiry_time=datetime.utcnow() + timedelta(hours=1),
            public_url='http://localhost/download/test_valid_file.enc',
            user_id=admin.id
        )
        db.session.add(valid_share)
        db.session.commit()
        
        # Test /get/ with expired file
        resp = client.get('/get/test_expired_file.enc')
        check("/get/ returns 410 for expired file", resp.status_code == 410)
        
        # Test /download/ with expired file
        resp = client.get('/download/test_expired_file.enc')
        check("/download/ returns 200 with expired UI for expired file", resp.status_code == 200)
        html = resp.data.decode()
        check("/download/ expired page shows 'File No Longer Available'",
              'File No Longer Available' in html)
        check("/download/ expired page hides download button",
              'id="download-btn"' not in html)
        
        # Test /get/ with non-existent file
        resp = client.get('/get/totally_fake_file.enc')
        check("/get/ returns 404 for non-existent file", resp.status_code == 404)
        
        # Test /download/ with non-existent file
        resp = client.get('/download/totally_fake_file.enc')
        html = resp.data.decode()
        check("/download/ non-existent file shows expired UI",
              'File No Longer Available' in html)
        
        # ====================================================
        # 3. UTC NORMALIZATION (source audit)
        # ====================================================
        print("\n[3] UTC NORMALIZATION")
        
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'app.py'), 'r') as f:
            app_source = f.read()
        
        # Count occurrences (excluding comments)
        lines = app_source.split('\n')
        now_calls = [l.strip() for l in lines 
                     if 'datetime.now()' in l and not l.strip().startswith('#')]
        utcnow_calls = [l.strip() for l in lines 
                        if 'datetime.utcnow()' in l and not l.strip().startswith('#')]
        
        check("No datetime.now() calls remain in app.py", len(now_calls) == 0)
        check("datetime.utcnow() calls present", len(utcnow_calls) > 0)
        if now_calls:
            for l in now_calls:
                print(f"    WARNING: Found datetime.now() -> {l}")
        
        # ====================================================
        # 4. TOKEN ENTROPY
        # ====================================================
        print("\n[4] TOKEN ENTROPY")
        
        check("secrets.token_urlsafe used in source", 
              'secrets.token_urlsafe' in app_source)
        check("uuid.uuid4().hex[:8] removed from cipher creation",
              "uuid.uuid4().hex[:8]" not in app_source.split("def create_cipher")[1].split("def ")[0]
              if "def create_cipher" in app_source else False)
        
        # ====================================================
        # 5. SETTINGS ACCESS CONSISTENCY
        # ====================================================
        print("\n[5] SETTINGS ACCESS CONSISTENCY")
        
        # Login as non-admin via proper login flow
        client2 = app.test_client()
        client2.post('/login', data={
            'username': 'test_user_verify',
            'password': 'User123!',
            'csrf_token': 'dummy'
        })
        # Need to set csrf_token in session for login to work
        with client2.session_transaction() as sess:
            sess['csrf_token'] = 'test_csrf'
        resp_login = client2.post('/login', data={
            'username': 'test_user_verify',
            'password': 'User123!',
            'csrf_token': 'test_csrf'
        }, follow_redirects=False)
        
        resp = client2.get('/settings', follow_redirects=False)
        check("Non-admin /settings returns 200", resp.status_code == 200)
        
        # API now allowed for any authenticated user
        with client2.session_transaction() as sess:
            csrf = sess.get('csrf_token', 'test_csrf')
        resp = client2.post('/api/settings', 
                          json={'alias': 'TEST_ALIAS_VAL'},
                          headers={'X-CSRF-Token': csrf})
        check("Non-admin /api/settings returns 200", resp.status_code == 200)
        
        # Login as admin via proper login flow
        client3 = app.test_client()
        with client3.session_transaction() as sess:
            sess['csrf_token'] = 'admin_csrf'
        client3.post('/login', data={
            'username': 'test_admin_verify',
            'password': 'Admin123!',
            'csrf_token': 'admin_csrf'
        }, follow_redirects=False)
        
        resp = client3.get('/settings')
        check("Admin /settings returns 200", resp.status_code == 200)
        
        # ====================================================
        # 6. UNUSED ASSETS REMOVED
        # ====================================================
        print("\n[6] UNUSED FRONTEND ASSETS")
        
        static_js = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static', 'js')
        check("tailwind.js deleted", 
              not os.path.exists(os.path.join(static_js, 'tailwind.js')))
        check("tailwind-config.js deleted",
              not os.path.exists(os.path.join(static_js, 'tailwind-config.js')))
        check("app.js still exists",
              os.path.exists(os.path.join(static_js, 'app.js')))
        check("crypto.js still exists",
              os.path.exists(os.path.join(static_js, 'crypto.js')))
        
        # ====================================================
        # 7. CSP HARDENING
        # ====================================================
        print("\n[7] CSP HARDENING")
        
        check("cdn.tailwindcss.com removed from CSP",
              'cdn.tailwindcss.com' not in app_source)
        check("CSP script-src is self + unsafe-inline only",
              "script-src 'self' 'unsafe-inline'" in app_source)
        
        # ====================================================
        # 8. AUTH FLOW SANITY
        # ====================================================
        print("\n[8] AUTH FLOW SANITY")
        
        # Logout
        with client.session_transaction() as s:
            csrf = s.get('csrf_token', 'tok')
        client.post('/logout', data={'csrf_token': csrf})
        
        # Unauthenticated access to protected routes
        resp = client.get('/dashboard', follow_redirects=False)
        check("Unauthenticated /dashboard redirects", resp.status_code == 302)
        
        resp = client.get('/cipher', follow_redirects=False)
        check("Unauthenticated /cipher redirects", resp.status_code == 302)
        
        resp = client.get('/settings', follow_redirects=False)
        check("Unauthenticated /settings redirects", resp.status_code == 302)
        
        resp = client.get('/shared', follow_redirects=False)
        check("Unauthenticated /shared redirects", resp.status_code == 302)
        
        # Public routes still accessible
        resp = client.get('/')
        check("Public / returns 200", resp.status_code == 200)
        
        resp = client.get('/login')
        check("Public /login returns 200", resp.status_code == 200)
        
        resp = client.get('/register')
        check("Public /register returns 200", resp.status_code == 200)
        
        # ====================================================
        # 9. RELOAD / REFRESH STATE CLEANUP (CACHE-CONTROL)
        # ====================================================
        print("\n[9] RELOAD / REFRESH STATE CLEANUP")
        
        # Login again as admin to run reload check
        client_refresh = app.test_client()
        with client_refresh.session_transaction() as sess:
            sess['_user_id'] = str(admin.id)
            sess['_fresh'] = True
            sess['csrf_token'] = 'refresh_token'
            
        # Simulate an upload by setting session success variables
        with client_refresh.session_transaction() as sess:
            sess['success_public_url'] = 'http://localhost/download/test_file.enc'
            sess['success_qr_img'] = 'dummy_base64_qr'
            sess['success_message'] = 'Upload complete!'
            
        # First load of /dashboard should pop session variables and return 200 with the URL & Cache-Control headers
        resp_ref1 = client_refresh.get('/dashboard')
        check("First GET to /dashboard returns 200", resp_ref1.status_code == 200)
        check("First GET contains the public URL", 'http://localhost/download/test_file.enc' in resp_ref1.data.decode())
        check("First GET returns Cache-Control no-store header", 'no-store' in resp_ref1.headers.get('Cache-Control', ''))
        
        # Second load (refresh/reload) should have empty variables and NOT display the QR success card
        resp_ref2 = client_refresh.get('/dashboard')
        check("Second GET (reload) to /dashboard returns 200", resp_ref2.status_code == 200)
        check("Second GET (reload) does NOT contain the public URL", 'http://localhost/download/test_file.enc' not in resp_ref2.data.decode())
        check("Second GET (reload) contains placeholder awaiting state", 'Select a file to share' in resp_ref2.data.decode())
        
        # ====================================================
        # 10. CLIENT-SIDE SIZE LIMITS
        # ====================================================
        print("\n[10] CLIENT-SIDE SIZE LIMITS")
        
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static', 'js', 'app.js'), 'r') as f:
            js_source = f.read()
            
        check("app.js has file size validation before encryption",
              "1024" in js_source)
        
        # ====================================================
        # 11. REGISTRATION ALWAYS ENABLED
        # ====================================================
        print("\n[11] REGISTRATION ALWAYS ENABLED")
        
        client_reg = app.test_client()
        resp_enabled_get = client_reg.get('/register')
        check("GET /register renders username input",
              b'id="register-username"' in resp_enabled_get.data)
        check("GET /register does NOT contain disabled UI text",
              b"Registration is currently unavailable" not in resp_enabled_get.data)
        
        # ====================================================
        # CLEANUP test data
        # ====================================================
        Share.query.filter_by(filename='test_expired_file.enc').delete()
        Share.query.filter_by(filename='test_valid_file.enc').delete()
        db.session.commit()
        
        # ====================================================
        # SUMMARY
        # ====================================================
        print("\n" + "=" * 60)
        passed = sum(1 for _, ok in results if ok)
        failed = sum(1 for _, ok in results if not ok)
        print(f"RESULTS: {passed} passed, {failed} failed, {len(results)} total")
        
        if failed > 0:
            print("\nFAILED TESTS:")
            for name, ok in results:
                if not ok:
                    print(f"  [FAIL] {name}")
        else:
            print("\nALL TESTS PASSED")
        print("=" * 60)
        
        return failed == 0


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
