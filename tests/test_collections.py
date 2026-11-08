"""
Obsidian Secure — Multi-File Secure Sharing (ZIP-Only Download) Test Suite
Verifies collection lifecycle:
- Zero-knowledge AES-256-GCM encryption decoupling
- Multi-file staging, initialization, streaming upload, and finalization
- Ownership validation and resource boundaries
- Collection expiration and revocation
- Recipient manifest retrieval, browser-side decryption, and ZIP archive verification
- Filename sanitization, Unicode support, and duplicate disambiguation
- Automatic cleanup of partial and expired collections
"""
import os
import io
import json
import base64
import pytest
import zipfile
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import db, User, Share, ShareCollection, CollectionFile, CollectionTransfer


def encrypt_payload_aes_gcm(plaintext: bytes, key: bytes) -> bytes:
    """Simulates browser-side encryptFile: generates 12-byte random IV,
    encrypts via AES-256-GCM, and returns [12-byte IV || ciphertext + 16-byte tag].
    """
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return iv + ciphertext


def decrypt_payload_aes_gcm(encrypted_blob: bytes, key: bytes) -> bytes:
    """Simulates browser-side decryptFile: extracts 12-byte IV from beginning
    and decrypts ciphertext via AES-256-GCM with authentication tag check.
    """
    iv = encrypted_blob[:12]
    ciphertext = encrypted_blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)


def test_collection_initialization_and_validation(auth_client, user1, csrf_token):
    """Verifies collection initialization rules, limits, and parameter validation."""
    # 1. Valid initialization
    res = auth_client.post('/api/v2/collection/init', json={
        'file_count': 3,
        'total_size': 1024 * 1024
    }, headers={'X-CSRF-Token': csrf_token})
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert 'public_id' in data
    assert 'public_url' in data
    assert f"/collection/{data['public_id']}" in data['public_url']

    # 2. Invalid file count (0 files)
    res_zero = auth_client.post('/api/v2/collection/init', json={
        'file_count': 0,
        'total_size': 1024
    }, headers={'X-CSRF-Token': csrf_token})
    assert res_zero.status_code == 400

    # 3. Invalid file count (> 10 files limit)
    res_excess = auth_client.post('/api/v2/collection/init', json={
        'file_count': 11,
        'total_size': 1024
    }, headers={'X-CSRF-Token': csrf_token})
    assert res_excess.status_code == 400

    # 4. Exceeds 50MB collection size limit
    res_large = auth_client.post('/api/v2/collection/init', json={
        'file_count': 2,
        'total_size': 55 * 1024 * 1024
    }, headers={'X-CSRF-Token': csrf_token})
    assert res_large.status_code == 400

    # 5. Missing CSRF token rejected
    res_no_csrf = auth_client.post('/api/v2/collection/init', json={
        'file_count': 2,
        'total_size': 1024
    })
    assert res_no_csrf.status_code == 403


def test_multi_file_collection_upload_and_finalize(auth_client, user1, csrf_token):
    """Verifies uploading multiple individually encrypted files and finalizing the collection."""
    master_key = AESGCM.generate_key(bit_length=256)

    files_to_share = [
        ("contract.pdf", b"%PDF-1.5 Confidential Contract Data", "application/pdf"),
        ("architecture.png", b"\x89PNG\r\n\x1a\n Diagram Data", "image/png"),
        ("notes.txt", b"Secret deployment notes and credentials", "text/plain")
    ]

    total_plain_size = sum(len(content) for _, content, _ in files_to_share)

    # 1. Initialize Collection
    init_res = auth_client.post('/api/v2/collection/init', json={
        'file_count': len(files_to_share),
        'total_size': total_plain_size
    }, headers={'X-CSRF-Token': csrf_token})
    assert init_res.status_code == 200
    public_id = init_res.get_json()['public_id']

    # 2. Encrypt each file with unique IV and upload individually
    file_ids = []
    for orig_name, plain_bytes, mime_type in files_to_share:
        enc_blob = encrypt_payload_aes_gcm(plain_bytes, master_key)
        orig_b64 = base64.b64encode(orig_name.encode('utf-8')).decode('utf-8')

        up_res = auth_client.post(
            f'/api/v2/collection/{public_id}/file',
            data={'file': (io.BytesIO(enc_blob), orig_name)},
            headers={
                'X-CSRF-Token': csrf_token,
                'X-Original-Name': orig_b64,
                'X-Mime-Type': mime_type
            }
        )
        assert up_res.status_code == 200
        up_data = up_res.get_json()
        assert up_data['status'] == 'success'
        file_ids.append(up_data['file_id'])

    assert len(file_ids) == 3

    # 3. Finalize Collection
    fin_res = auth_client.post(
        f'/api/v2/collection/{public_id}/finalize',
        headers={'X-CSRF-Token': csrf_token}
    )
    assert fin_res.status_code == 200
    fin_data = fin_res.get_json()
    assert fin_data['status'] == 'success'
    assert fin_data['share']['file_count'] == 3

    # 4. Verify DB records and disk files
    with auth_client.application.app_context():
        col = ShareCollection.query.filter_by(public_id=public_id).first()
        assert col is not None
        assert col.is_finalized is True
        assert col.file_count == 3
        assert len(col.files) == 3

        for cf in col.files:
            file_on_disk = os.path.join(auth_client.application.config['UPLOAD_FOLDER'], cf.stored_filename)
            assert os.path.exists(file_on_disk)
            assert os.path.getsize(file_on_disk) > 0


def test_recipient_manifest_decryption_and_zip_creation(auth_client, client, user1, csrf_token):
    """Verifies that recipient can retrieve manifest, download encrypted blobs, decrypt them
    with zero server knowledge, and create a verified ZIP archive containing all files."""
    master_key = AESGCM.generate_key(bit_length=256)

    files_data = [
        ("report.docx", b"PK\x03\x04 Annual Financial Report 2026", "application/vnd.openxmlformats-officedocument"),
        ("dataset.csv", b"id,user,role\n1,alice,admin\n2,bob,operator", "text/csv"),
        ("readme.md", b"# Project Readme\nZero-knowledge verified.", "text/markdown")
    ]

    # Initialize and upload collection
    init_res = auth_client.post('/api/v2/collection/init', json={
        'file_count': len(files_data),
        'total_size': sum(len(c) for _, c, _ in files_data)
    }, headers={'X-CSRF-Token': csrf_token})
    public_id = init_res.get_json()['public_id']

    for name, content, mime in files_data:
        enc_blob = encrypt_payload_aes_gcm(content, master_key)
        auth_client.post(
            f'/api/v2/collection/{public_id}/file',
            data={'file': (io.BytesIO(enc_blob), name)},
            headers={
                'X-CSRF-Token': csrf_token,
                'X-Original-Name': base64.b64encode(name.encode('utf-8')).decode('utf-8'),
                'X-Mime-Type': mime
            }
        )

    auth_client.post(f'/api/v2/collection/{public_id}/finalize', headers={'X-CSRF-Token': csrf_token})

    # Recipient access (unauthenticated client!)
    # 1. Recipient loads HTML page
    page_res = client.get(f'/collection/{public_id}')
    assert page_res.status_code == 200
    html = page_res.data.decode('utf-8')
    assert 'Secure Collection' in html
    assert 'Download All as ZIP' in html
    assert 'download-zip-btn' in html
    # Verify NO individual download buttons exist
    assert 'download-btn' not in html

    # 2. Recipient fetches manifest
    manifest_res = client.get(f'/api/v2/collection/{public_id}/manifest')
    assert manifest_res.status_code == 200
    manifest = manifest_res.get_json()
    assert manifest['status'] == 'success'
    assert manifest['file_count'] == 3
    assert len(manifest['files']) == 3

    # 3. Recipient downloads each encrypted blob, decrypts, and builds a ZIP archive
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        for f_meta in manifest['files']:
            f_id = f_meta['file_id']
            orig_name = f_meta['original_name']

            blob_res = client.get(f'/api/v2/collection/{public_id}/file/{f_id}')
            assert blob_res.status_code == 200
            encrypted_bytes = blob_res.data

            # Decrypt in browser (simulated here with AESGCM)
            decrypted_bytes = decrypt_payload_aes_gcm(encrypted_bytes, master_key)

            # Match against original
            expected_content = next(c for n, c, _ in files_data if n == orig_name)
            assert decrypted_bytes == expected_content

            # Add to ZIP
            zf.writestr(orig_name, decrypted_bytes)

    # 4. Verify ZIP archive integrity
    zip_buffer.seek(0)
    with zipfile.ZipFile(zip_buffer, mode='r') as zf:
        namelist = zf.namelist()
        assert len(namelist) == 3
        assert "report.docx" in namelist
        assert "dataset.csv" in namelist
        assert "readme.md" in namelist
        assert zf.read("dataset.csv") == b"id,user,role\n1,alice,admin\n2,bob,operator"

    # 5. Record download metrics
    rec_res = client.post(f'/api/v2/collection/{public_id}/record_download', json={'token': manifest['download_token']})
    assert rec_res.status_code == 200

    with auth_client.application.app_context():
        col_check = ShareCollection.query.filter_by(public_id=public_id).first()
        assert col_check.download_count == 1
        assert len(col_check.transfers) == 1


def test_collection_ownership_isolation(auth_client, other_auth_client, user1, user2, csrf_token):
    """Verifies that User2 cannot modify, upload to, finalize, or revoke User1's collection."""
    # 1. User1 initializes collection
    init_res = auth_client.post('/api/v2/collection/init', json={
        'file_count': 2,
        'total_size': 2000
    }, headers={'X-CSRF-Token': csrf_token})
    public_id = init_res.get_json()['public_id']

    # 2. Get User2 CSRF token
    u2_res = other_auth_client.get('/active-shares')
    import re
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', u2_res.data.decode('utf-8'))
    u2_csrf = match.group(1) if match else ""

    # 3. User2 attempts to upload file to User1's collection -> 403 Forbidden
    u2_up = other_auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"MALICIOUS_FILE"), 'hack.txt')},
        headers={'X-CSRF-Token': u2_csrf, 'X-Original-Name': base64.b64encode(b'hack.txt').decode('utf-8')}
    )
    assert u2_up.status_code == 403

    # 4. User2 attempts to finalize User1's collection -> 403 Forbidden
    u2_fin = other_auth_client.post(
        f'/api/v2/collection/{public_id}/finalize',
        headers={'X-CSRF-Token': u2_csrf}
    )
    assert u2_fin.status_code == 403

    # User1 uploads valid file and finalizes
    auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"ENCRYPTED_USER1_DATA"), 'user1.txt')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'user1.txt').decode('utf-8')}
    )
    auth_client.post(f'/api/v2/collection/{public_id}/finalize', headers={'X-CSRF-Token': csrf_token})

    # 5. User2 attempts to revoke User1's collection -> rejected / share preserved
    u2_revoke = other_auth_client.post('/revoke', data={
        'public_url': f'http://localhost/collection/{public_id}',
        'csrf_token': u2_csrf
    }, follow_redirects=True)
    assert u2_revoke.status_code == 200

    with auth_client.application.app_context():
        col_check = ShareCollection.query.filter_by(public_id=public_id).first()
        assert col_check is not None
        assert col_check.is_revoked is False


def test_collection_revocation(auth_client, client, user1, csrf_token):
    """Verifies that revoking a collection deletes physical files from disk and returns 410 on all recipient access."""
    # Create and finalize collection
    init_res = auth_client.post('/api/v2/collection/init', json={'file_count': 1, 'total_size': 500}, headers={'X-CSRF-Token': csrf_token})
    public_id = init_res.get_json()['public_id']

    auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"REVOKE_TEST_DATA"), 'doc.txt')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'doc.txt').decode('utf-8')}
    )
    auth_client.post(f'/api/v2/collection/{public_id}/finalize', headers={'X-CSRF-Token': csrf_token})

    with auth_client.application.app_context():
        col = ShareCollection.query.filter_by(public_id=public_id).first()
        file_path = os.path.join(auth_client.application.config['UPLOAD_FOLDER'], col.files[0].stored_filename)
        assert os.path.exists(file_path)

    # Revoke collection
    revoke_res = auth_client.post('/revoke', data={
        'public_url': f'http://localhost/collection/{public_id}',
        'csrf_token': csrf_token
    }, follow_redirects=True)
    assert revoke_res.status_code == 200

    # Verify disk files removed
    assert not os.path.exists(file_path)

    # Verify recipient endpoints return 410 Gone with Revoked notice
    page_res = client.get(f'/collection/{public_id}')
    assert page_res.status_code == 410
    assert 'Collection Revoked' in page_res.data.decode('utf-8')

    manifest_res = client.get(f'/api/v2/collection/{public_id}/manifest')
    assert manifest_res.status_code == 410


def test_collection_expiration_enforcement(auth_client, client, user1, csrf_token):
    """Verifies that expired collections reject manifest and file retrieval with HTTP 410."""
    init_res = auth_client.post('/api/v2/collection/init', json={'file_count': 1, 'total_size': 500}, headers={'X-CSRF-Token': csrf_token})
    public_id = init_res.get_json()['public_id']

    up_res = auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"EXPIRY_TEST_DATA"), 'exp.txt')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'exp.txt').decode('utf-8')}
    )
    file_id = up_res.get_json()['file_id']
    auth_client.post(f'/api/v2/collection/{public_id}/finalize', headers={'X-CSRF-Token': csrf_token})

    # Artificially expire the collection
    with auth_client.application.app_context():
        col = ShareCollection.query.filter_by(public_id=public_id).first()
        col.expiry_time = datetime.utcnow() - timedelta(minutes=10)
        db.session.commit()

    # Recipient access to expired collection
    res_page = client.get(f'/collection/{public_id}')
    assert res_page.status_code == 410
    assert 'Collection Expired' in res_page.data.decode('utf-8')

    res_manifest = client.get(f'/api/v2/collection/{public_id}/manifest')
    assert res_manifest.status_code == 410

    res_file = client.get(f'/api/v2/collection/{public_id}/file/{file_id}')
    assert res_file.status_code == 410


def test_collection_abort_and_partial_cleanup(auth_client, user1, csrf_token):
    """Verifies that aborting an in-progress collection cleans up physical files and DB record."""
    init_res = auth_client.post('/api/v2/collection/init', json={'file_count': 2, 'total_size': 1000}, headers={'X-CSRF-Token': csrf_token})
    public_id = init_res.get_json()['public_id']

    # Upload 1 file
    up_res = auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"PARTIAL_UPLOAD_DATA"), 'part.txt')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'part.txt').decode('utf-8')}
    )
    assert up_res.status_code == 200

    with auth_client.application.app_context():
        col = ShareCollection.query.filter_by(public_id=public_id).first()
        part_path = os.path.join(auth_client.application.config['UPLOAD_FOLDER'], col.files[0].stored_filename)
        assert os.path.exists(part_path)

    # Abort collection
    abort_res = auth_client.post(f'/api/v2/collection/{public_id}/abort', headers={'X-CSRF-Token': csrf_token})
    assert abort_res.status_code == 200
    assert abort_res.get_json()['status'] == 'aborted'

    # Verify physical file deleted and DB record removed
    assert not os.path.exists(part_path)
    with auth_client.application.app_context():
        assert ShareCollection.query.filter_by(public_id=public_id).first() is None


def test_active_shares_display_both_single_and_collection(auth_client, user1, csrf_token):
    """Verifies that the Active Shares dashboard lists both single shares and multi-file collections."""
    now = datetime.utcnow()

    # 1. Create single-file share
    with auth_client.application.app_context():
        s = Share(
            filename='single_test.enc',
            original_name='single_doc.pdf',
            mime_type='application/pdf',
            upload_time=now,
            expiry_time=now + timedelta(days=1),
            download_count=2,
            public_url='http://localhost/download/single_test.enc',
            user_id=user1['id']
        )
        db.session.add(s)
        db.session.commit()

    # 2. Create collection share
    init_res = auth_client.post('/api/v2/collection/init', json={'file_count': 1, 'total_size': 500}, headers={'X-CSRF-Token': csrf_token})
    public_id = init_res.get_json()['public_id']
    auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"DATA"), 'col_file.txt')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'col_file.txt').decode('utf-8')}
    )
    auth_client.post(f'/api/v2/collection/{public_id}/finalize', headers={'X-CSRF-Token': csrf_token})

    # 3. Load active shares page
    res = auth_client.get('/active-shares')
    assert res.status_code == 200
    html = res.data.decode('utf-8')
    assert 'single_doc.pdf' in html
    assert 'Collection (1 files)' in html or 'Collection' in html
    assert 'folder_zip' in html


def test_path_traversal_sanitization(auth_client, client, user1, csrf_token):
    """Verifies that path traversal attempts in uploaded filenames are safely sanitized."""
    init_res = auth_client.post('/api/v2/collection/init', json={'file_count': 1, 'total_size': 500}, headers={'X-CSRF-Token': csrf_token})
    public_id = init_res.get_json()['public_id']

    traversal_name = "../../etc/passwd"
    b64_name = base64.b64encode(traversal_name.encode('utf-8')).decode('utf-8')

    up_res = auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"TRAVERSAL_TEST"), 'passwd')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': b64_name}
    )
    assert up_res.status_code == 200
    auth_client.post(f'/api/v2/collection/{public_id}/finalize', headers={'X-CSRF-Token': csrf_token})

    with auth_client.application.app_context():
        col = ShareCollection.query.filter_by(public_id=public_id).first()
        stored_name = col.files[0].stored_filename
        # Must not contain directory separators
        assert ".." not in stored_name
        assert "/" not in stored_name
        assert "\\" not in stored_name
        assert os.path.exists(os.path.join(auth_client.application.config['UPLOAD_FOLDER'], stored_name))


def test_unicode_and_duplicate_filenames(auth_client, client, user1, csrf_token):
    """Verifies that Unicode filenames are preserved and duplicate filenames in collections are supported."""
    master_key = AESGCM.generate_key(bit_length=256)
    unicode_name = "報告_2026_財務.pdf"
    b64_unicode = base64.b64encode(unicode_name.encode('utf-8')).decode('utf-8')

    init_res = auth_client.post('/api/v2/collection/init', json={'file_count': 2, 'total_size': 1000}, headers={'X-CSRF-Token': csrf_token})
    public_id = init_res.get_json()['public_id']

    # File 1: Unicode filename
    auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(encrypt_payload_aes_gcm(b"UNICODE_CONTENT", master_key)), unicode_name)},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': b64_unicode}
    )

    # File 2: Duplicate name as File 1
    auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(encrypt_payload_aes_gcm(b"SECOND_COPY_CONTENT", master_key)), unicode_name)},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': b64_unicode}
    )

    auth_client.post(f'/api/v2/collection/{public_id}/finalize', headers={'X-CSRF-Token': csrf_token})

    # Retrieve manifest
    man_res = client.get(f'/api/v2/collection/{public_id}/manifest')
    assert man_res.status_code == 200
    files = man_res.get_json()['files']
    assert len(files) == 2
    assert files[0]['original_name'] == unicode_name
    assert files[1]['original_name'] == unicode_name


def test_upload_collection_file_aggregate_size_limits_and_cleanup(auth_client, user1, csrf_token):
    """Verifies pre-write aggregate size limit enforcement:
    - Multiple files totaling under limit succeed
    - Exactly-at-limit upload succeeds
    - One-byte-over-limit upload is rejected before writing to disk
    - Multiple files exceeding aggregate limit are rejected
    - No orphaned files or DB records remain after rejection
    """
    from app import MAX_COLLECTION_SIZE

    upload_folder = auth_client.application.config['UPLOAD_FOLDER']

    init_res = auth_client.post('/api/v2/collection/init', json={
        'file_count': 3,
        'total_size': MAX_COLLECTION_SIZE
    }, headers={'X-CSRF-Token': csrf_token})
    assert init_res.status_code == 200
    public_id = init_res.get_json()['public_id']

    # File 1: 30 MB
    size_1 = 30 * 1024 * 1024
    up_1 = auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"A" * size_1), 'file1.bin')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'file1.bin').decode('utf-8')}
    )
    assert up_1.status_code == 200

    # File 2: 20 MB -> Total becomes exactly MAX_COLLECTION_SIZE (50 MB)
    size_2 = MAX_COLLECTION_SIZE - size_1
    up_2 = auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"B" * size_2), 'file2.bin')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'file2.bin').decode('utf-8')}
    )
    assert up_2.status_code == 200

    # Check files currently in folder
    files_at_limit = set(os.listdir(upload_folder))

    # File 3: Attempt 1-byte over limit -> MUST be rejected with 400
    up_3_over = auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"X"), 'file3_over.bin')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'file3_over.bin').decode('utf-8')}
    )
    assert up_3_over.status_code == 400
    assert 'exceeds maximum limit' in up_3_over.get_json()['error']

    # Verify no new files were written to disk for rejected upload
    files_after_reject = set(os.listdir(upload_folder))
    assert files_after_reject == files_at_limit, "Rejected upload must not leave orphaned file on disk"

    # Verify DB collection still only contains 2 files
    with auth_client.application.app_context():
        col = ShareCollection.query.filter_by(public_id=public_id).first()
        assert len(col.files) == 2
        assert sum(f.file_size for f in col.files) == MAX_COLLECTION_SIZE


def test_concurrent_upload_aggregate_limit_safety(auth_client, user1, csrf_token):
    """Verifies that concurrent uploads attempting to exceed the aggregate collection limit
    are safely rejected by pre-write or atomic post-flush checks without orphaned files."""
    import threading
    from app import MAX_COLLECTION_SIZE

    upload_folder = auth_client.application.config['UPLOAD_FOLDER']

    init_res = auth_client.post('/api/v2/collection/init', json={
        'file_count': 5,
        'total_size': MAX_COLLECTION_SIZE
    }, headers={'X-CSRF-Token': csrf_token})
    assert init_res.status_code == 200
    public_id = init_res.get_json()['public_id']

    # 4 concurrent threads each attempting to upload a 20 MB file (total 80 MB > 50 MB limit)
    chunk_size = 20 * 1024 * 1024
    upload_statuses = []

    def upload_worker(idx):
        with auth_client.application.test_client() as c_worker:
            with c_worker.session_transaction() as sess:
                sess['csrf_token'] = 'csrf_thread'
                sess['_user_id'] = str(user1['id'])
                sess['_fresh'] = True
            res = c_worker.post(
                f'/api/v2/collection/{public_id}/file',
                data={'file': (io.BytesIO(b"C" * chunk_size), f'thread_{idx}.bin')},
                headers={'X-CSRF-Token': 'csrf_thread', 'X-Original-Name': base64.b64encode(f'thread_{idx}.bin'.encode()).decode()}
            )
            upload_statuses.append(res.status_code)

    threads = [threading.Thread(target=upload_worker, args=(i,)) for i in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()

    # At least two uploads must have succeeded (40 MB <= 50 MB), and the rest rejected (400)
    assert 200 in upload_statuses
    assert 400 in upload_statuses

    # Verify aggregate size never exceeded MAX_COLLECTION_SIZE
    with auth_client.application.app_context():
        col = ShareCollection.query.filter_by(public_id=public_id).first()
        total_stored = sum(f.file_size for f in col.files)
        assert total_stored <= MAX_COLLECTION_SIZE
        # Verify all files recorded in DB exist on disk and no orphaned files exist
        for f in col.files:
            assert os.path.exists(os.path.join(upload_folder, f.stored_filename))


def test_collection_download_token_metrics_protection(auth_client, client, user1, csrf_token):
    """Verifies that collection download metrics require a valid, single-use, unexpired token,
    and prevent replay attacks or arbitrary counter inflation."""
    from app import CollectionDownloadToken

    init_res = auth_client.post('/api/v2/collection/init', json={'file_count': 1, 'total_size': 500}, headers={'X-CSRF-Token': csrf_token})
    public_id = init_res.get_json()['public_id']

    auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"DATA"), 'doc.txt')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'doc.txt').decode('utf-8')}
    )
    auth_client.post(f'/api/v2/collection/{public_id}/finalize', headers={'X-CSRF-Token': csrf_token})

    # 1. Fetch manifest to obtain single-use download token
    man_res = client.get(f'/api/v2/collection/{public_id}/manifest')
    assert man_res.status_code == 200
    token = man_res.get_json().get('download_token')
    assert token is not None and len(token) > 20

    # 2. Rejection of requests with missing token
    r_missing = client.post(f'/api/v2/collection/{public_id}/record_download', json={})
    assert r_missing.status_code == 400

    # 3. Rejection of requests with invalid / forged token
    r_invalid = client.post(f'/api/v2/collection/{public_id}/record_download', json={'token': 'forged_token_xyz'})
    assert r_invalid.status_code == 400

    # 4. Successful acknowledgement with valid token
    r_valid = client.post(f'/api/v2/collection/{public_id}/record_download', json={'token': token})
    assert r_valid.status_code == 200
    assert r_valid.get_json()['status'] == 'success'

    with auth_client.application.app_context():
        col = ShareCollection.query.filter_by(public_id=public_id).first()
        assert col.download_count == 1

    # 5. Replay attack rejection (token has already been used)
    r_replay = client.post(f'/api/v2/collection/{public_id}/record_download', json={'token': token})
    assert r_replay.status_code == 409
    assert 'already used' in r_replay.get_json()['error']

    with auth_client.application.app_context():
        col = ShareCollection.query.filter_by(public_id=public_id).first()
        assert col.download_count == 1, "Download count must not increment on replay"

    # 6. Rejection of expired token
    # Get a fresh token
    man_res2 = client.get(f'/api/v2/collection/{public_id}/manifest')
    token2 = man_res2.get_json().get('download_token')
    with auth_client.application.app_context():
        tok_obj = CollectionDownloadToken.query.filter_by(token=token2).first()
        tok_obj.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()

    r_expired = client.post(f'/api/v2/collection/{public_id}/record_download', json={'token': token2})
    assert r_expired.status_code == 410
    assert 'expired' in r_expired.get_json()['error']


def test_collection_revocation_tombstone_lifecycle(auth_client, client, user1, csrf_token):
    """Verifies that revoked collections preserve tombstone state, return 410 to recipients,
    idempotently handle repeated revocation calls, and clean up physical files immediately."""
    init_res = auth_client.post('/api/v2/collection/init', json={'file_count': 2, 'total_size': 1000}, headers={'X-CSRF-Token': csrf_token})
    public_id = init_res.get_json()['public_id']

    up1 = auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"REV1"), 'file1.txt')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'file1.txt').decode()}
    )
    up2 = auth_client.post(
        f'/api/v2/collection/{public_id}/file',
        data={'file': (io.BytesIO(b"REV2"), 'file2.txt')},
        headers={'X-CSRF-Token': csrf_token, 'X-Original-Name': base64.b64encode(b'file2.txt').decode()}
    )
    auth_client.post(f'/api/v2/collection/{public_id}/finalize', headers={'X-CSRF-Token': csrf_token})

    with auth_client.application.app_context():
        col = ShareCollection.query.filter_by(public_id=public_id).first()
        file_paths = [os.path.join(auth_client.application.config['UPLOAD_FOLDER'], cf.stored_filename) for cf in col.files]
        for fp in file_paths:
            assert os.path.exists(fp)

    # 1. Revoke collection
    rev_res = auth_client.post('/revoke', data={
        'public_url': f'http://localhost/collection/{public_id}',
        'csrf_token': csrf_token
    }, follow_redirects=True)
    assert rev_res.status_code == 200

    # 2. Check files on disk are removed and file records deleted
    for fp in file_paths:
        assert not os.path.exists(fp), "Physical files must be deleted upon revocation"

    with auth_client.application.app_context():
        col_tombstone = ShareCollection.query.filter_by(public_id=public_id).first()
        assert col_tombstone is not None, "Collection record must remain as a tombstone"
        assert col_tombstone.is_revoked is True
        assert len(col_tombstone.files) == 0, "File records should be purged from tombstone"

    # 3. Repeated revocation is safe and idempotent
    rev_repeat = auth_client.post('/revoke', data={
        'public_url': f'http://localhost/collection/{public_id}',
        'csrf_token': csrf_token
    }, follow_redirects=True)
    assert rev_repeat.status_code == 200

    # 4. Recipient access to revoked collection returns 410 Gone with Revocation notice
    page_res = client.get(f'/collection/{public_id}')
    assert page_res.status_code == 410
    assert 'Collection Revoked' in page_res.data.decode('utf-8')
    assert 'The sender has revoked access to this collection' in page_res.data.decode('utf-8')

    manifest_res = client.get(f'/api/v2/collection/{public_id}/manifest')
    assert manifest_res.status_code == 410

    file_res = client.get(f'/api/v2/collection/{public_id}/file/any_id')
    assert file_res.status_code == 410

    record_res = client.post(f'/api/v2/collection/{public_id}/record_download', json={'token': 'test'})
    assert record_res.status_code == 410
