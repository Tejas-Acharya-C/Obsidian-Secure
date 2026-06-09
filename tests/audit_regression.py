"""
Obsidian Secure - COMPLETE PRODUCTION REGRESSION & STABILITY AUDIT
Covers: Auth, File Sharing, Secure Messages, Expiry, Revoke, Security, Edge Cases
"""
import os, sys, json, time, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User, Share, Transfer, Cipher, UserSetting, LoginAttempt, RegistrationAttempt
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta

results = []
SECTION = ""

def section(name):
    global SECTION
    SECTION = name
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")

def check(name, condition, detail=""):
    status = "[PASS]" if condition else "[FAIL]"
    results.append((SECTION, name, condition, detail))
    line = f"  {status}: {name}"
    if detail and not condition:
        line += f" -- {detail}"
    print(line)

def run_audit():
    app.testing = True
    
    with app.app_context():
        db.create_all()
        
        # Clean up any previous test artifacts
        User.query.filter(User.username.like('audit_%')).delete()
        LoginAttempt.query.delete()
        RegistrationAttempt.query.delete()
        db.session.commit()
        
        # Create test users
        admin = User(username='audit_admin', 
                    password_hash=generate_password_hash('AdminPass1!'))
        normal = User(username='audit_user',
                     password_hash=generate_password_hash('UserPass1!'))
        db.session.add_all([admin, normal])
        db.session.commit()

        # ================================================================
        # PHASE 1 - BOOT VERIFICATION
        # ================================================================
        section("PHASE 1: BOOT VERIFICATION")
        
        client = app.test_client()
        
        # Landing page loads
        resp = client.get('/')
        check("Landing page loads (200)", resp.status_code == 200)
        html = resp.data.decode()
        check("Landing page contains DOCTYPE", '<!DOCTYPE html>' in html or '<!doctype html>' in html.lower())
        check("Landing page loads styles.css", 'styles.css' in html)
        check("Landing page loads utilities.css", 'utilities.css' in html)
        check("Landing page loads app.js", 'app.js' in html)
        check("Landing page loads Inter font", 'fonts.googleapis.com' in html)
        check("Landing page loads Material Symbols", 'Material+Symbols' in html or 'Material_Symbols' in html)
        check("No tailwind.js reference", 'tailwind.js' not in html)
        check("No tailwind-config.js reference", 'tailwind-config.js' not in html)
        check("Landing page has proper title", '<title>' in html)
        check("Landing page has meta description", 'meta name="description"' in html)
        check("Landing page has skip link", 'skip-link' in html)
        
        # Static assets exist
        resp_css1 = client.get('/static/css/styles.css')
        check("styles.css accessible", resp_css1.status_code == 200)
        resp_css2 = client.get('/static/css/utilities.css')
        check("utilities.css accessible", resp_css2.status_code == 200)
        resp_js1 = client.get('/static/js/app.js')
        check("app.js accessible", resp_js1.status_code == 200)
        resp_js2 = client.get('/static/js/crypto.js')
        check("crypto.js accessible", resp_js2.status_code == 200)
        resp_logo = client.get('/static/img/logo.png')
        check("logo.png accessible", resp_logo.status_code == 200)
        
        # Deleted assets return 404
        resp_tw = client.get('/static/js/tailwind.js')
        check("tailwind.js returns 404 (deleted)", resp_tw.status_code == 404)
        resp_twc = client.get('/static/js/tailwind-config.js')
        check("tailwind-config.js returns 404 (deleted)", resp_twc.status_code == 404)
        
        # Security headers present
        resp = client.get('/')
        check("X-Content-Type-Options present", 
              resp.headers.get('X-Content-Type-Options') == 'nosniff')
        check("X-Frame-Options present", 
              resp.headers.get('X-Frame-Options') == 'DENY')
        csp = resp.headers.get('Content-Security-Policy', '')
        check("CSP header present", len(csp) > 0)
        check("CSP: no tailwind CDN reference", 'tailwindcss' not in csp)
        check("CSP: script-src present", 'script-src' in csp)
        check("CSP: font-src allows Google Fonts", 'fonts.gstatic.com' in csp)
        check("CSP: style-src allows Google Fonts", 'fonts.googleapis.com' in csp)
        
        # ================================================================
        # PHASE 2 - AUTH FLOW
        # ================================================================
        section("PHASE 2: AUTH FLOW")
        
        # --- Registration ---
        c = app.test_client()
        with c.session_transaction() as s:
            s['csrf_token'] = 'tok'
        
        # Empty fields
        resp = c.post('/register', data={'username': '', 'password': '', 'csrf_token': 'tok'})
        check("Register: empty fields returns error", b'Please fill out all fields' in resp.data)
        
        # Valid registration
        resp = c.post('/register', data={
            'username': 'audit_newuser', 'password': 'Test123!', 'confirm_password': 'Test123!', 'csrf_token': 'tok'
        }, follow_redirects=False)
        check("Register: valid creates user + redirects", resp.status_code in [302, 303])
        
        # Duplicate registration
        c2 = app.test_client()
        with c2.session_transaction() as s:
            s['csrf_token'] = 'tok'
        resp = c2.post('/register', data={
            'username': 'audit_newuser', 'password': 'Test123!', 'confirm_password': 'Test123!', 'csrf_token': 'tok'
        })
        check("Register: duplicate shows USER_EXISTS", b'username is already taken' in resp.data)
        
        # --- Login ---
        c3 = app.test_client()
        with c3.session_transaction() as s:
            s['csrf_token'] = 'tok'
        
        # Invalid credentials
        resp = c3.post('/login', data={
            'username': 'audit_admin', 'password': 'WrongPass', 'csrf_token': 'tok'
        })
        check("Login: invalid credentials shows ACCESS_DENIED", b'Incorrect username or password' in resp.data)
        
        # Valid login
        resp = c3.post('/login', data={
            'username': 'audit_admin', 'password': 'AdminPass1!', 'csrf_token': 'tok'
        }, follow_redirects=False)
        check("Login: valid credentials redirects to dashboard", 
              resp.status_code in [302, 303] and '/dashboard' in resp.headers.get('Location', ''))
        
        # After login, dashboard accessible
        resp = c3.get('/dashboard')
        check("Dashboard: accessible after login (200)", resp.status_code == 200)
        html = resp.data.decode()
        check("Dashboard: contains nav links", 'Files' in html and 'Messages' in html)
        check("Dashboard: contains settings link", '/settings' in html)
        
        # --- Non-admin user ---
        c4 = app.test_client()
        with c4.session_transaction() as s:
            s['csrf_token'] = 'tok'
        c4.post('/login', data={
            'username': 'audit_user', 'password': 'UserPass1!', 'csrf_token': 'tok'
        })
        
        resp = c4.get('/dashboard')
        html4 = resp.data.decode()
        check("Non-admin: contains settings link in nav", 
              '/settings' in html4)
        
        resp = c4.get('/settings', follow_redirects=False)
        check("Non-admin: /settings returns 200", resp.status_code == 200)
        
        with c4.session_transaction() as s:
            csrf = s.get('csrf_token', 'tok')
        resp = c4.post('/api/settings', json={'alias': 'HACKED'}, 
                      headers={'X-CSRF-Token': csrf})
        check("Non-admin: /api/settings returns 200", resp.status_code == 200)
        
        # --- Logout ---
        with c3.session_transaction() as s:
            csrf = s.get('csrf_token', 'tok')
        resp = c3.post('/logout', data={'csrf_token': csrf}, follow_redirects=False)
        check("Logout: redirects", resp.status_code in [302, 303])
        
        resp = c3.get('/dashboard', follow_redirects=False)
        check("After logout: dashboard redirects to login", resp.status_code == 302)
        
        # --- Unauthenticated protection ---
        c5 = app.test_client()
        for route in ['/dashboard', '/shared', '/cipher', '/settings', '/upload']:
            resp = c5.get(route, follow_redirects=False) if route != '/upload' else c5.post(route, follow_redirects=False)
            check(f"Unauth: {route} redirects", resp.status_code in [302, 303, 405],
                  f"got {resp.status_code}")
        
        # --- CSRF validation ---
        c6 = app.test_client()
        with c6.session_transaction() as s:
            s['csrf_token'] = 'correct_token'
        c6.post('/login', data={
            'username': 'audit_admin', 'password': 'AdminPass1!', 'csrf_token': 'correct_token'
        })
        
        # Upload without CSRF
        resp = c6.post('/upload/stream', 
                       data=b'test',
                       headers={
                           'Content-Type': 'application/octet-stream',
                           'X-CSRF-Token': 'wrong_token',
                           'X-Original-Name': 'test',
                           'X-Upload-ID': 'testupload',
                           'X-Chunk-Index': '0',
                           'X-Total-Chunks': '1'
                       })
        check("CSRF: upload with wrong token fails (403)", resp.status_code == 403)
        
        # --- Rate limiting ---
        c7 = app.test_client()
        # Clear any existing attempts
        LoginAttempt.query.delete()
        db.session.commit()
        
        with c7.session_transaction() as s:
            s['csrf_token'] = 'tok'
        
        for i in range(6):
            c7.post('/login', data={
                'username': 'audit_admin', 'password': 'WrongPass', 'csrf_token': 'tok'
            })
        
        resp = c7.post('/login', data={
            'username': 'audit_admin', 'password': 'AdminPass1!', 'csrf_token': 'tok'
        })
        check("Rate limit: 6+ failed attempts triggers rate limit",
              b'Too many attempts' in resp.data)
        
        # Clean up rate limit for remaining tests
        LoginAttempt.query.delete()
        db.session.commit()
        
        # ================================================================
        # PHASE 3 - FILE SHARING
        # ================================================================
        section("PHASE 3: FILE SHARING FLOW")
        
        c8 = app.test_client()
        with c8.session_transaction() as s:
            s['csrf_token'] = 'tok'
        c8.post('/login', data={
            'username': 'audit_admin', 'password': 'AdminPass1!', 'csrf_token': 'tok'
        })
        
        # Upload a test file via OBSv2 stream endpoint
        import io as iolib
        import base64 as b64lib
        test_content = b'This is encrypted test content for the audit.'
        original_name_b64 = b64lib.b64encode(b'test_document.txt').decode('utf-8')
        resp = c8.post('/upload/stream', 
                       data=test_content,
                       headers={
                           'Content-Type': 'application/octet-stream',
                           'X-CSRF-Token': 'tok',
                           'X-Original-Name': original_name_b64,
                           'X-Upload-ID': 'testuploadid12345',
                           'X-Chunk-Index': '0',
                           'X-Total-Chunks': '1'
                       })
        check("Upload: returns 200", resp.status_code == 200)
        
        # Get dashboard to verify the success panel display (redirection payload)
        resp = c8.get('/dashboard')
        html = resp.data.decode()
        check("Upload: shows share link panel", 'share-url' in html or 'public_url' in html.lower() or 'Secure link ready' in html)
        check("Upload: shows QR code", 'qr-container' in html or 'data:image/png;base64' in html)
        check("Upload: shows trust messaging", 'zero-knowledge' in html.lower() or 'never leaves your device' in html.lower() or 'decryption key' in html.lower())
        
        # Get the share record
        share = Share.query.filter_by(user_id=admin.id).order_by(Share.id.desc()).first()
        check("Upload: Share record created in DB", share is not None)
        if share:
            check("Upload: original_name preserved", share.original_name == 'test_document.txt')
            check("Upload: filename has unique prefix", len(share.filename) > len('test_document.txt'))
            check("Upload: expiry_time set", share.expiry_time is not None)
            check("Upload: public_url uses /download/", '/download/' in share.public_url)
            check("Upload: file exists on disk", 
                  os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], share.filename)))
            
            # Download landing page
            resp = c8.get(f'/download/{share.filename}')
            check("Download landing: returns 200", resp.status_code == 200)
            html = resp.data.decode()
            check("Download landing: shows download button", 'download-btn' in html)
            check("Download landing: has decrypt messaging", 'Decrypt' in html or 'decrypt' in html)
            check("Download landing: loads crypto.js", 'crypto.js' in html)
            check("Download landing: no expired state", 'File No Longer Available' not in html)
            
            # Direct file access
            resp = c8.get(f'/get/{share.filename}')
            check("Direct download: returns 200", resp.status_code == 200)
            check("Direct download: correct content", resp.data == test_content)
            check("Direct download: Content-Disposition present",
                  'attachment' in resp.headers.get('Content-Disposition', '').lower())
            
            # Activity page shows share (now consolidated into dashboard)
            resp = c8.get('/dashboard')
            html = resp.data.decode()
            check("Activity: shows uploaded file", 'test_document.txt' in html)
            check("Activity: shows copy link button", 'Copy link' in html)
            check("Activity: shows revoke button", 'Revoke' in html)
            
            # --- Expiry enforcement ---
            share.expiry_time = datetime.utcnow() - timedelta(hours=1)
            db.session.commit()
            
            resp = c8.get(f'/get/{share.filename}')
            check("Expired: /get/ returns 410", resp.status_code == 410)
            
            resp = c8.get(f'/download/{share.filename}')
            html = resp.data.decode()
            check("Expired: /download/ shows expired UI", 'File No Longer Available' in html)
            check("Expired: no download button", 'download-btn' not in html)
            
            # Restore for revoke test
            share.expiry_time = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            # --- Revoke ---
            with c8.session_transaction() as s:
                s['csrf_token'] = 'tok'
            resp = c8.post('/revoke', data={
                'csrf_token': 'tok',
                'public_url': share.public_url
            }, follow_redirects=False)
            check("Revoke: redirects", resp.status_code in [302, 303])
            
            revoked = Share.query.get(share.id)
            check("Revoke: share deleted from DB", revoked is None)
            check("Revoke: file deleted from disk",
                  not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], share.filename)))
        
        # Non-existent file
        resp = c8.get('/get/totally_nonexistent_file.enc')
        check("Non-existent: /get/ returns 404", resp.status_code == 404)
        
        resp = c8.get('/download/totally_nonexistent_file.enc')
        html = resp.data.decode()
        check("Non-existent: /download/ shows expired UI", 'File No Longer Available' in html)
        
        # ================================================================
        # PHASE 4 - SECURE MESSAGES
        # ================================================================
        section("PHASE 4: SECURE MESSAGE FLOW")
        
        # Create cipher
        with c8.session_transaction() as s:
            s['csrf_token'] = 'tok'
        resp = c8.post('/cipher/create', data={
            'content': 'dGVzdF9lbmNyeXB0ZWRfcGF5bG9hZA==',
            'burn_on_read': 'true',
            'csrf_token': 'tok'
        }, follow_redirects=True)
        check("Cipher create: returns 200", resp.status_code == 200)
        html = resp.data.decode()
        check("Cipher create: shows encrypted success", 
              'cipher-share-url' in html or 'Message encrypted' in html)
        
        cipher = Cipher.query.filter_by(is_read=False).order_by(Cipher.id.desc()).first()
        check("Cipher: record exists in DB", cipher is not None)
        
        if cipher:
            check("Cipher: public_id >= 16 chars (high entropy)", len(cipher.public_id) >= 16)
            check("Cipher: public_id is URL-safe", 
                  all(c.isalnum() or c in '-_' for c in cipher.public_id))
            check("Cipher: content stored (base64)", len(cipher.content) > 0)
            check("Cipher: burn_on_read set", cipher.burn_on_read == True)
            check("Cipher: is_read initially False", cipher.is_read == False)
            check("Cipher: created_at set", cipher.created_at is not None)
            
            # Decrypt page (public, no auth required)
            pub_client = app.test_client()
            resp = pub_client.get(f'/decrypt/{cipher.public_id}')
            check("Decrypt page: returns 200", resp.status_code == 200)
            html = resp.data.decode()
            check("Decrypt page: has cipher-content hidden input", 'id="cipher-content"' in html)
            check("Decrypt page: payload in value attribute", cipher.content in html)
            check("Decrypt page: has decrypt button", 'decrypt-btn' in html)
            check("Decrypt page: loads crypto.js", 'crypto.js' in html)
            check("Decrypt page: loads app.js", 'app.js' in html)
            check("Decrypt page: has error container", 'decrypt-error' in html)
            check("Decrypt page: has decrypted-content container", 'decrypted-content' in html)
            check("Decrypt page: has plaintext-message element", 'plaintext-message' in html)
            check("Decrypt page: trust messaging present", 'browser' in html.lower())
            check("Decrypt page: no plaintext rendered", 'test_encrypted_payload' not in html)
            
            # Burn-after-read check
            cipher_refreshed = Cipher.query.get(cipher.id)
            check("Burn: cipher NOT marked as read after first access", 
                  cipher_refreshed.is_read == False)
            
            # Simulate client calling confirm API
            resp_confirm = pub_client.post(f'/api/cipher/confirm_read/{cipher.public_id}')
            check("Burn: confirm API returns 200", resp_confirm.status_code == 200)

            cipher_refreshed_after_confirm = Cipher.query.get(cipher.id)
            check("Burn: cipher marked as read after confirm", 
                  cipher_refreshed_after_confirm.is_read == True)
            
            # Second access should show expired
            resp = pub_client.get(f'/decrypt/{cipher.public_id}')
            html = resp.data.decode()
            check("Burn: second access shows expired state", 'Message Unavailable' in html)
            check("Burn: no cipher-content on expired page", 'id="cipher-content"' not in html)
            check("Burn: no decrypt button on expired page", 'decrypt-btn' not in html)
            
            # Invalid public_id
            resp = pub_client.get('/decrypt/totally_invalid_id_12345')
            html = resp.data.decode()
            check("Invalid ID: shows expired state", 'Message Unavailable' in html)
            
            # Empty/malformed IDs
            resp = pub_client.get('/decrypt/')
            check("Empty decrypt path: returns 404", resp.status_code == 404)
        
        # Create non-burn cipher
        with c8.session_transaction() as s:
            s['csrf_token'] = 'tok'
        resp = c8.post('/cipher/create', data={
            'content': 'bm9uX2J1cm5fdGVzdA==',
            'csrf_token': 'tok'  # No burn_on_read checkbox
        }, follow_redirects=True)
        
        nb_cipher = Cipher.query.filter_by(is_read=False).order_by(Cipher.id.desc()).first()
        if nb_cipher:
            check("Non-burn cipher: burn_on_read is False", nb_cipher.burn_on_read == False)
            
            # Access should NOT mark as read
            pub_client.get(f'/decrypt/{nb_cipher.public_id}')
            nb_refreshed = Cipher.query.get(nb_cipher.id)
            check("Non-burn cipher: still accessible after first read", nb_refreshed.is_read == False)
            
            # Second access also works
            resp = pub_client.get(f'/decrypt/{nb_cipher.public_id}')
            check("Non-burn cipher: second access returns 200", resp.status_code == 200)
            html = resp.data.decode()
            check("Non-burn cipher: still shows decrypt UI", 'decrypt-btn' in html)
        
        # Empty content
        with c8.session_transaction() as s:
            s['csrf_token'] = 'tok'
        resp = c8.post('/cipher/create', data={
            'content': '',
            'csrf_token': 'tok'
        }, follow_redirects=False)
        check("Empty cipher: redirects (no creation)", resp.status_code in [302, 303])
        
        # Cipher page list
        resp = c8.get('/cipher')
        html = resp.data.decode()
        check("Cipher page: returns 200", resp.status_code == 200)
        check("Cipher page: lists active ciphers", 'Copy link' in html or 'No messages yet' in html)
        
        # Cipher Identity and Sender Consistency Tests (Phase 22.2)
        with c8.session_transaction() as s:
            csrf = s.get('csrf_token', 'tok')
        c8.post('/api/settings', json={'alias': 'Tejas'}, headers={'X-CSRF-Token': csrf})
        
        with c8.session_transaction() as s:
            s['csrf_token'] = 'tok'
        c8.post('/cipher/create', data={
            'content': 'dGVzdF9pZGVudGl0eV9wYXlsb2Fk',
            'burn_on_read': 'false',
            'csrf_token': 'tok'
        }, follow_redirects=True)
        
        cipher_identity = Cipher.query.filter_by(content='dGVzdF9pZGVudGl0eV9wYXlsb2Fk').first()
        check("Cipher Identity: message created", cipher_identity is not None)
        
        pub_client = app.test_client()
        resp = pub_client.get(f'/decrypt/{cipher_identity.public_id}')
        html = resp.data.decode()
        check("Cipher Identity: sender alias displayed is Tejas", 'Tejas' in html)
        
        with c8.session_transaction() as s:
            csrf = s.get('csrf_token', 'tok')
        c8.post('/api/settings', json={'alias': 'Acharya'}, headers={'X-CSRF-Token': csrf})
        
        resp = pub_client.get(f'/decrypt/{cipher_identity.public_id}')
        html = resp.data.decode()
        check("Cipher Identity: sender alias is still Tejas after user alias change", 'Tejas' in html and 'Acharya' not in html)
        
        with c8.session_transaction() as s:
            s['csrf_token'] = 'tok'
        c8.post('/cipher/create', data={
            'content': 'bmV3X2lkZW50aXR5X3BheWxvYWQ=',
            'burn_on_read': 'false',
            'csrf_token': 'tok'
        }, follow_redirects=True)
        
        new_cipher_identity = Cipher.query.filter_by(content='bmV3X2lkZW50aXR5X3BheWxvYWQ=').first()
        resp = pub_client.get(f'/decrypt/{new_cipher_identity.public_id}')
        html = resp.data.decode()
        check("Cipher Identity: new message displays updated alias Acharya", 'Acharya' in html)
        
        legacy_cipher = Cipher(
            content='bGVnYWN5X3BheWxvYWQ=',
            public_id='legacy12345publicid',
            burn_on_read=False,
            sender_alias=None
        )
        db.session.add(legacy_cipher)
        db.session.commit()
        
        resp = pub_client.get(f'/decrypt/legacy12345publicid')
        html = resp.data.decode()
        check("Cipher Identity: legacy message falls back to Obsidian Secure display", 'Obsidian Secure' in html)
        
        # ================================================================
        # PHASE 5 - SECURITY REGRESSION
        # ================================================================
        section("PHASE 5: SECURITY REGRESSION")
        
        # Source code audit
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'app.py'), 'r') as f:
            src = f.read()
        
        lines = src.split('\n')
        now_calls = [l.strip() for l in lines 
                     if 'datetime.now()' in l and not l.strip().startswith('#')]
        check("UTC: no datetime.now() in app.py", len(now_calls) == 0,
              f"Found: {now_calls}" if now_calls else "")
        
        check("Token: secrets.token_urlsafe in source", 'secrets.token_urlsafe' in src)
        check("Token: old uuid.hex[:8] removed from cipher", 
              'uuid.uuid4().hex[:8]' not in src.split('def create_cipher')[1].split('def ')[0])
        
        check("CSP: no tailwind CDN", 'cdn.tailwindcss.com' not in src)
        check("Security: CSRF function exists", 'validate_csrf' in src)
        check("Security: rate limiting exists", 'RATE_LIMIT' in src)
        check("Security: password hashing used", 'generate_password_hash' in src)
        check("Security: session cookie httponly", 'SESSION_COOKIE_HTTPONLY' in src)
        check("Security: X-Frame-Options DENY", "X-Frame-Options" in src)
        
        # Upload CSRF bypass attempt
        pub = app.test_client()
        resp = pub.post('/upload', data={
            'file': (iolib.BytesIO(b'malicious'), 'hack.txt')
        }, content_type='multipart/form-data', follow_redirects=False)
        print(f"DEBUG: pub.post upload returned {resp.status_code}")
        check("Security: unauthenticated upload blocked", resp.status_code in [302, 303])
        
        # Revoke CSRF bypass
        resp = pub.post('/revoke', data={'public_url': 'http://test'}, follow_redirects=False)
        print(f"DEBUG: pub.post revoke returned {resp.status_code}")
        check("Security: unauthenticated revoke blocked", resp.status_code in [302, 303])
        
        # Cross-user revoke attempt
        c_user = app.test_client()
        with c_user.session_transaction() as s:
            s['csrf_token'] = 'tok'
        c_user.post('/login', data={
            'username': 'audit_user', 'password': 'UserPass1!', 'csrf_token': 'tok'
        })
        
        # Create a share as admin
        c_admin = app.test_client()
        with c_admin.session_transaction() as s:
            s['csrf_token'] = 'tok'
        c_admin.post('/login', data={
            'username': 'audit_admin', 'password': 'AdminPass1!', 'csrf_token': 'tok'
        })
        c_admin.post('/upload', data={
            'csrf_token': 'tok',
            'file': (iolib.BytesIO(b'admin_file'), 'admin_secret.txt')
        }, content_type='multipart/form-data')
        
        admin_share = Share.query.filter_by(user_id=admin.id).order_by(Share.id.desc()).first()
        if admin_share:
            # Normal user tries to revoke admin's share
            with c_user.session_transaction() as s:
                s['csrf_token'] = 'tok'
            c_user.post('/revoke', data={
                'csrf_token': 'tok',
                'public_url': admin_share.public_url
            })
            still_exists = Share.query.get(admin_share.id)
            print(f"DEBUG: admin_share.id = {admin_share.id}, still_exists = {still_exists}")
            check("Security: cross-user revoke blocked", still_exists is not None)
            
            # Data isolation: non-admin shared page only shows own files
            resp = c_user.get('/shared')
            html = resp.data.decode()
            check("Data isolation: non-admin doesn't see admin files in /shared",
                  'admin_secret.txt' not in html)
        
        # ================================================================
        # PHASE 6 - TEMPLATE & ASSET CONSISTENCY
        # ================================================================
        section("PHASE 6: TEMPLATE & ASSET CONSISTENCY")
        
        # Check all pages render without errors
        pages_auth = ['/dashboard', '/shared', '/cipher', '/settings']
        for page in pages_auth:
            resp = c_admin.get(page)
            check(f"Page {page}: renders without 500", resp.status_code in [200, 302])
        
        # Check public pages
        pages_public = ['/', '/login', '/register']
        pub2 = app.test_client()
        for page in pages_public:
            resp = pub2.get(page)
            check(f"Page {page}: renders without 500", resp.status_code == 200)
        
        # Check all pages have proper HTML structure
        for page in ['/', '/login', '/register']:
            resp = pub2.get(page)
            html = resp.data.decode()
            check(f"Page {page}: has <html> tag", '<html' in html)
            check(f"Page {page}: has <head> tag", '<head>' in html or '<head ' in html)
            check(f"Page {page}: has <body> tag", '<body' in html)
            check(f"Page {page}: has </html> closing", '</html>' in html)
        
        # Check upload form structure
        resp = c_admin.get('/dashboard')
        html = resp.data.decode()
        check("Dashboard: has upload form", 'uploadForm' in html)
        check("Dashboard: has CSRF token input", 'csrf_token' in html)
        check("Dashboard: has file input", 'file-upload' in html)
        check("Dashboard: has dropzone", 'dropzone' in html)
        
        # Check cipher form structure
        resp = c_admin.get('/cipher')
        html = resp.data.decode()
        check("Cipher page: has cipher form", 'cipherForm' in html)
        check("Cipher page: has plaintext textarea", 'cipher-plaintext' in html)
        check("Cipher page: has hidden encrypted input", 'encrypted-message-input' in html)
        check("Cipher page: has encrypt button", 'cipher-btn' in html)
        check("Cipher page: has burn checkbox", 'burn-on-read' in html or 'burn_on_read' in html)
        
        # ================================================================
        # PHASE 7 - EDGE CASES
        # ================================================================
        section("PHASE 7: EDGE CASES")
        
        # Very long filename
        import base64 as b64lib
        long_name = 'a' * 200 + '.txt'
        long_name_b64 = b64lib.b64encode(long_name.encode('utf-8')).decode('utf-8')
        with c_admin.session_transaction() as s:
            s['csrf_token'] = 'tok'
        resp = c_admin.post('/upload/stream', 
                            data=b'test',
                            headers={
                                'Content-Type': 'application/octet-stream',
                                'X-CSRF-Token': 'tok',
                                'X-Original-Name': long_name_b64,
                                'X-Upload-ID': 'testuploadlong',
                                'X-Chunk-Index': '0',
                                'X-Total-Chunks': '1'
                            })
        check("Edge: very long filename handled", resp.status_code == 200)
        
        # Special characters in filename
        special_name = "test file (copy) [2].txt"
        special_name_b64 = b64lib.b64encode(special_name.encode('utf-8')).decode('utf-8')
        resp = c_admin.post('/upload/stream', 
                            data=b'test',
                            headers={
                                'Content-Type': 'application/octet-stream',
                                'X-CSRF-Token': 'tok',
                                'X-Original-Name': special_name_b64,
                                'X-Upload-ID': 'testuploadspecial',
                                'X-Chunk-Index': '0',
                                'X-Total-Chunks': '1'
                            })
        check("Edge: special chars in filename handled", resp.status_code == 200)
        
        # XSS in cipher content (should be escaped)
        with c_admin.session_transaction() as s:
            s['csrf_token'] = 'tok'
        xss_payload = '<script>alert("xss")</script>'
        resp = c_admin.post('/cipher/create', data={
            'content': xss_payload,
            'csrf_token': 'tok'
        }, follow_redirects=True)
        xss_cipher = Cipher.query.order_by(Cipher.id.desc()).first()
        if xss_cipher:
            check("Edge: XSS in cipher content escaped", 
                  '<script>' not in xss_cipher.content)
            check("Edge: HTML entities used", 
                  '&lt;' in xss_cipher.content or '&amp;' in xss_cipher.content)
        
        # Traversal attempt in filename
        resp = c_admin.get('/get/../app.py')
        check("Edge: path traversal in /get/ blocked", resp.status_code != 200)
        
        resp = c_admin.get('/download/../app.py')
        check("Edge: path traversal in /download/ blocked", resp.status_code != 200,
              f"got {resp.status_code}")
        
        # ================================================================
        # PHASE 8 - MODELS & DATA INTEGRITY
        # ================================================================
        section("PHASE 8: DATA INTEGRITY")
        
        # Check model schema
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models.py'), 'r') as f:
            models_src = f.read()
        
        check("Models: User model has password_hash", 'password_hash' in models_src)
        check("Models: User model does not have is_admin", 'is_admin' not in models_src)
        check("Models: UserSetting model exists", 'UserSetting' in models_src)
        check("Models: Share model has expiry_time", 'expiry_time' in models_src)
        check("Models: Share model has user_id FK", 'user_id' in models_src and 'ForeignKey' in models_src)
        check("Models: Cipher model has public_id", 'public_id' in models_src)
        check("Models: Cipher model has burn_on_read", 'burn_on_read' in models_src)
        check("Models: Cipher model has is_read", 'is_read' in models_src)
        check("Models: Transfer cascade delete", 'cascade' in models_src)
        check("Models: Cipher model has sender_alias", 'sender_alias' in models_src)
        check("Models: LoginAttempt model exists", 'LoginAttempt' in models_src)
        
        # Verify no orphaned DB records
        orphan_transfers = Transfer.query.filter(
            ~Transfer.share_id.in_(db.session.query(Share.id))
        ).count()
        check("Data: no orphaned transfers", orphan_transfers == 0)
        
        # ================================================================
        # PHASE 9 - UNUSED CODE AUDIT
        # ================================================================
        section("PHASE 9: UNUSED CODE & IMPORTS")
        
        check("Code: 'wraps' imported but used?", 'wraps' in src)
        check("Code: 'g' imported from flask", "'g'" in src or ', g,' in src or ', g ' in src)
        check("Code: 'jsonify' imported from flask", 'jsonify' in src)
        # Check removed unused imports
        
        # Check if these are actually used (not just imported)
        # Remove import lines and check remaining code
        code_without_imports = '\n'.join(l for l in lines if not l.startswith('from ') and not l.startswith('import '))
        
        check("Code: 'wraps' used beyond import?", 'wraps' in code_without_imports,
              "wraps imported but potentially unused")
        check("Code: 'g' used beyond import?", 
              '.g.' in code_without_imports or 'g.' in code_without_imports or ' g ' in code_without_imports,
              "g imported but potentially unused")
        check("Code: 'jsonify' used beyond import?", 'jsonify' in code_without_imports,
              "jsonify imported but potentially unused")
        # Image check removed
        check("Code: 'get_local_ip' function used?", 
              code_without_imports.count('get_local_ip') > 1,
              "get_local_ip defined but may not be called")
        
        # ================================================================
        # CLEANUP
        # ================================================================
        # Clean test data
        User.query.filter(User.username.like('audit_%')).delete()
        Cipher.query.filter(Cipher.content.in_([
            'dGVzdF9lbmNyeXB0ZWRfcGF5bG9hZA==',
            'bm9uX2J1cm5fdGVzdA==',
            '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;',
            'dGVzdF9pZGVudGl0eV9wYXlsb2Fk',
            'bmV3X2lkZW50aXR5X3BheWxvYWQ=',
            'bGVnYWN5X3BheWxvYWQ='
        ])).delete()
        Share.query.filter(Share.original_name.in_([
            'test_document.txt', 'admin_secret.txt', long_name, special_name
        ])).delete()
        db.session.commit()
        
        # ================================================================
        # SUMMARY
        # ================================================================
        print(f"\n{'='*60}")
        print("  FINAL RESULTS")
        print(f"{'='*60}")
        
        passed = sum(1 for _, _, ok, _ in results if ok)
        failed = sum(1 for _, _, ok, _ in results if not ok)
        total = len(results)
        
        print(f"\n  Total:  {total}")
        print(f"  Passed: {passed}")
        print(f"  Failed: {failed}")
        
        if failed > 0:
            print(f"\n  FAILURES:")
            for sect, name, ok, detail in results:
                if not ok:
                    d = f" -- {detail}" if detail else ""
                    print(f"    [{sect}] {name}{d}")
        else:
            print("\n  ALL TESTS PASSED")
        
        print(f"{'='*60}\n")
        return failed


if __name__ == '__main__':
    failures = run_audit()
    sys.exit(0 if failures == 0 else 1)
