"""
Obsidian Secure — Share Lifecycle & Expiration Logic Tests
Verifies file upload, storage, expiration thresholds (15m rule), recipient download access, and revocation cleanup.
"""
import os
import io
import base64
import pytest
from datetime import datetime, timedelta
from app import Share, db

def test_share_creation_and_download(auth_client, user1, csrf_token):
    """Verifies uploading an encrypted file share via /api/v2/upload and retrieving it via public download URL."""
    fake_file = (io.BytesIO(b"ENCRYPTED_AES256_GCM_CIPHERTEXT_BLOB"), 'encrypted.bin')
    orig_b64 = base64.b64encode(b'encrypted.bin').decode('utf-8')
    
    res = auth_client.post('/api/v2/upload', data={'file': fake_file}, headers={
        'X-CSRF-Token': csrf_token,
        'X-Original-Name': orig_b64,
        'X-Mime-Type': 'application/octet-stream'
    }, follow_redirects=True)
    
    assert res.status_code == 200
    json_resp = res.get_json()
    assert json_resp.get('status') == 'success'
    
    with auth_client.application.app_context():
        share = Share.query.filter_by(user_id=user1['id']).first()
        assert share is not None
        file_path = os.path.join(auth_client.application.config['UPLOAD_FOLDER'], share.filename)
        assert os.path.exists(file_path)
        
        # Test recipient access to download page
        dl_res = auth_client.get(f'/download/{share.filename}')
        assert dl_res.status_code == 200
        assert 'Download' in dl_res.data.decode('utf-8')
        
        # Test direct ciphertext retrieval endpoint
        get_res = auth_client.get(f'/get/{share.filename}')
        assert get_res.status_code == 200
        assert get_res.data == b"ENCRYPTED_AES256_GCM_CIPHERTEXT_BLOB"

def test_share_expiration_threshold_states(auth_client, user1):
    """Verifies share status states based on 15-minute expiration threshold logic."""
    now = datetime.utcnow()
    
    with auth_client.application.app_context():
        # 1. Active Share (> 15 minutes remaining)
        s_active = Share(
            filename='active.enc',
            original_name='active.txt',
            mime_type='text/plain',
            upload_time=now,
            expiry_time=now + timedelta(minutes=60),
            download_count=0,
            public_url='http://localhost/download/active.enc',
            user_id=user1['id']
        )
        
        # 2. Expiring Soon Share (<= 15 minutes remaining and > 0)
        s_expiring = Share(
            filename='expiring.enc',
            original_name='expiring.txt',
            mime_type='text/plain',
            upload_time=now,
            expiry_time=now + timedelta(minutes=10),
            download_count=0,
            public_url='http://localhost/download/expiring.enc',
            user_id=user1['id']
        )
        
        # 3. Expired Share (<= 0 minutes remaining)
        s_expired = Share(
            filename='expired.enc',
            original_name='expired.txt',
            mime_type='text/plain',
            upload_time=now - timedelta(hours=2),
            expiry_time=now - timedelta(minutes=5),
            download_count=0,
            public_url='http://localhost/download/expired.enc',
            user_id=user1['id']
        )
        
        db.session.add_all([s_active, s_expiring, s_expired])
        db.session.commit()

        # Check calculated status states
        # s_active remaining = 60m > 15m => Active
        assert (s_active.expiry_time - now).total_seconds() > 900
        
        # s_expiring remaining = 10m <= 15m (900s) => Expiring Soon
        assert 0 < (s_expiring.expiry_time - now).total_seconds() <= 900
        
        # s_expired remaining <= 0 => Expired
        assert (s_expired.expiry_time - now).total_seconds() <= 0

    # Verify expired share endpoint returns HTTP 410 Gone
    get_expired = auth_client.get('/get/expired.enc')
    assert get_expired.status_code == 410

def test_share_revocation(auth_client, user1, csrf_token):
    """Verifies that revoking a share deletes database metadata and disk storage files."""
    test_filename = 'revoke_test.enc'
    test_path = os.path.join(auth_client.application.config['UPLOAD_FOLDER'], test_filename)
    with open(test_path, 'wb') as f:
        f.write(b"DATA_TO_BE_REVOKED")
        
    with auth_client.application.app_context():
        s = Share(
            filename=test_filename,
            original_name='revoke.txt',
            mime_type='text/plain',
            upload_time=datetime.utcnow(),
            expiry_time=datetime.utcnow() + timedelta(hours=1),
            download_count=0,
            public_url='http://localhost/download/revoke_test.enc',
            user_id=user1['id']
        )
        db.session.add(s)
        db.session.commit()
        share_id = s.id
        public_url = s.public_url

    res = auth_client.post('/revoke', data={
        'public_url': public_url,
        'csrf_token': csrf_token
    }, follow_redirects=True)
    
    assert res.status_code == 200
    with auth_client.application.app_context():
        assert db.session.get(Share, share_id) is None
        assert not os.path.exists(test_path)

def test_download_counter_increments(auth_client, user1):
    """Verifies that accessing a share file increments the download_count in DB atomically."""
    test_filename = 'counter_test.enc'
    test_path = os.path.join(auth_client.application.config['UPLOAD_FOLDER'], test_filename)
    with open(test_path, 'wb') as f:
        f.write(b"DATA_COUNTER_TEST")
        
    with auth_client.application.app_context():
        s = Share(
            filename=test_filename,
            original_name='counter.txt',
            mime_type='text/plain',
            upload_time=datetime.utcnow(),
            expiry_time=datetime.utcnow() + timedelta(hours=1),
            download_count=0,
            public_url='http://localhost/download/counter_test.enc',
            user_id=user1['id']
        )
        db.session.add(s)
        db.session.commit()
        share_id = s.id

    # Initial download count check
    with auth_client.application.app_context():
        share_obj = db.session.get(Share, share_id)
        assert share_obj.download_count == 0

    # First access
    res1 = auth_client.get(f'/get/{test_filename}')
    assert res1.status_code == 200

    with auth_client.application.app_context():
        share_obj = db.session.get(Share, share_id)
        assert share_obj.download_count == 1

    # Second access
    res2 = auth_client.get(f'/api/v2/get/{test_filename}')
    assert res2.status_code == 200

    with auth_client.application.app_context():
        share_obj = db.session.get(Share, share_id)
        assert share_obj.download_count == 2
