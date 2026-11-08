"""
Obsidian Secure — Cryptography & Zero-Knowledge Contract Tests
Verifies zero-knowledge key decoupling, atomic single-use Burn-On-Read consumption,
concurrency safety, and immediate ciphertext erasure.
"""
import io
import json
import secrets
import threading
import re
from datetime import datetime, timedelta
import pytest
from app import Cipher, db

def extract_csrf_from_page(client, url):
    res = client.get(url)
    html = res.data.decode('utf-8', errors='ignore')
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if m:
        return m.group(1)
    m2 = re.search(r'id="cipher-csrf-token"\s+value="([^"]+)"', html)
    if m2:
        return m2.group(1)
    m_meta = re.search(r'name="csrf-token"\s+content="([^"]+)"', html)
    return m_meta.group(1) if m_meta else ""

def test_cipher_creation_and_zero_knowledge_delivery(auth_client, user1, csrf_token):
    """Verifies that ciphers store encrypted ciphertext and GET /decrypt never leaks ciphertext."""
    encrypted_payload = "V0VDRU5DUllQVEVEX0FFUzI1Nl9HRE1fUEFZTE9BRA=="

    res = auth_client.post('/cipher/create', data={
        'content': encrypted_payload,
        'burn_on_read': 'on',
        'csrf_token': csrf_token
    }, follow_redirects=True)

    assert res.status_code == 200

    with auth_client.application.app_context():
        c = Cipher.query.first()
        assert c is not None
        assert c.content == encrypted_payload
        assert c.burn_on_read is True
        assert c.is_read is False
        assert len(c.public_id) >= 16

        # Test recipient decrypt landing page NEVER exposes ciphertext in HTML
        dec_res = auth_client.get(f'/decrypt/{c.public_id}')
        assert dec_res.status_code == 200
        html = dec_res.data.decode('utf-8')
        assert encrypted_payload not in html, "SECURITY VIOLATION: GET /decrypt exposed ciphertext in HTML"
        assert 'crypto.js' in html


def test_burn_on_read_atomic_single_consumption(client):
    """Verifies atomic consumption: recipient gets ciphertext only via POST, which immediately wipes DB content."""
    with client.application.app_context():
        c = Cipher(
            public_id='burn_test_single_use_01',
            content='ENCRYPTED_SECRET_DATA_01',
            burn_on_read=True,
            is_read=False,
            sender_alias='Tejas'
        )
        db.session.add(c)
        db.session.commit()
        public_id = c.public_id

    # 1. GET does NOT expose ciphertext or consume message
    recip_client = client.application.test_client()
    get_res = recip_client.get(f'/decrypt/{public_id}')
    assert get_res.status_code == 200
    assert 'ENCRYPTED_SECRET_DATA_01' not in get_res.data.decode('utf-8')

    with client.application.app_context():
        c_check = Cipher.query.filter_by(public_id=public_id).first()
        assert c_check.is_read is False, "GET request prematurely consumed message"
        assert c_check.content == 'ENCRYPTED_SECRET_DATA_01'

    # Extract recipient CSRF token
    csrf = extract_csrf_from_page(recip_client, f'/decrypt/{public_id}')

    # 2. First explicit consumption claims message and returns ciphertext
    consume_res = recip_client.post(
        f'/api/cipher/consume/{public_id}',
        headers={'X-CSRF-Token': csrf}
    )
    assert consume_res.status_code == 200
    data = consume_res.get_json()
    assert data.get('ciphertext') == 'ENCRYPTED_SECRET_DATA_01'

    # 3. Database is immediately wiped
    with client.application.app_context():
        c_after = Cipher.query.filter_by(public_id=public_id).first()
        assert c_after.is_read is True
        assert c_after.content == '', "SECURITY VIOLATION: Ciphertext remained in DB after consumption"

    # 4. Repeated consumption by same client is rejected with 410 without ciphertext
    repeat_res = recip_client.post(
        f'/api/cipher/consume/{public_id}',
        headers={'X-CSRF-Token': csrf}
    )
    assert repeat_res.status_code == 410
    repeat_json = repeat_res.get_json() or {}
    assert 'ciphertext' not in repeat_json
    assert 'ENCRYPTED_SECRET_DATA_01' not in repeat_res.data.decode('utf-8')

    # 5. Subsequent GET renders expired status
    get_expired = recip_client.get(f'/decrypt/{public_id}')
    assert get_expired.status_code == 200
    assert 'unavailable' in get_expired.data.decode('utf-8').lower() or 'expired' in get_expired.data.decode('utf-8').lower()


def test_burn_on_read_concurrency_two_simultaneous_requests(client):
    """Invariant: Across 2 concurrent requests, AT MOST ONE can obtain ciphertext."""
    pub_id = f"concur_2_{secrets.token_hex(6)}"
    with client.application.app_context():
        c = Cipher(
            public_id=pub_id,
            content='CONCURRENT_PAYLOAD_TWO',
            burn_on_read=True,
            is_read=False
        )
        db.session.add(c)
        db.session.commit()

    c1 = client.application.test_client()
    c2 = client.application.test_client()
    csrf1 = extract_csrf_from_page(c1, f'/decrypt/{pub_id}')
    csrf2 = extract_csrf_from_page(c2, f'/decrypt/{pub_id}')

    deliveries = []
    errors = []

    def make_claim(cl, csrf):
        res = cl.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})
        body = res.data.decode('utf-8', errors='ignore')
        if res.status_code == 200 and 'CONCURRENT_PAYLOAD_TWO' in body:
            deliveries.append(res.get_json().get('ciphertext'))
        else:
            errors.append(res.status_code)

    t1 = threading.Thread(target=make_claim, args=(c1, csrf1))
    t2 = threading.Thread(target=make_claim, args=(c2, csrf2))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(deliveries) == 1, f"Expected exactly 1 delivery, got {len(deliveries)}"
    assert len(errors) == 1, f"Expected 1 rejected request, got {len(errors)}"
    assert errors[0] in [409, 410]


def test_burn_on_read_concurrency_five_simultaneous_requests(client):
    """Invariant: Across 5 concurrent requests, AT MOST ONE can obtain ciphertext."""
    pub_id = f"concur_5_{secrets.token_hex(6)}"
    with client.application.app_context():
        c = Cipher(
            public_id=pub_id,
            content='CONCURRENT_PAYLOAD_FIVE',
            burn_on_read=True,
            is_read=False
        )
        db.session.add(c)
        db.session.commit()

    clients = [client.application.test_client() for _ in range(5)]
    csrfs = [extract_csrf_from_page(cl, f'/decrypt/{pub_id}') for cl in clients]

    deliveries = []
    rejected = []

    def make_claim(cl, csrf):
        res = cl.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})
        body = res.data.decode('utf-8', errors='ignore')
        if res.status_code == 200 and 'CONCURRENT_PAYLOAD_FIVE' in body:
            deliveries.append(res.get_json().get('ciphertext'))
        else:
            rejected.append(res.status_code)

    threads = [threading.Thread(target=make_claim, args=(clients[i], csrfs[i])) for i in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()

    # Strict invariant assertion: exactly one delivery
    assert len(deliveries) == 1, f"Concurrency violation: {len(deliveries)} deliveries!"
    assert deliveries[0] == 'CONCURRENT_PAYLOAD_FIVE'
    assert len(rejected) == 4
    for code in rejected:
        assert code in [409, 410]


def test_burn_on_read_post_without_valid_csrf(client):
    """Verifies that consumption POST without valid CSRF is rejected with HTTP 403."""
    pub_id = f"csrf_test_{secrets.token_hex(6)}"
    with client.application.app_context():
        c = Cipher(public_id=pub_id, content='CSRF_PROTECTED_DATA', burn_on_read=True, is_read=False)
        db.session.add(c)
        db.session.commit()

    recip = client.application.test_client()
    # No CSRF header
    res = recip.post(f'/api/cipher/consume/{pub_id}')
    assert res.status_code == 403
    assert 'CSRF_PROTECTED_DATA' not in res.data.decode('utf-8')

    # Confirm message was NOT burned by rejected request
    with client.application.app_context():
        c_check = Cipher.query.filter_by(public_id=pub_id).first()
        assert c_check.is_read is False
        assert c_check.content == 'CSRF_PROTECTED_DATA'


def test_burn_on_read_consumption_after_expiry(client):
    """Verifies that expired messages cannot be consumed."""
    pub_id = f"exp_test_{secrets.token_hex(6)}"
    with client.application.app_context():
        c = Cipher(
            public_id=pub_id,
            content='EXPIRED_SECRET_DATA',
            burn_on_read=True,
            is_read=False,
            created_at=datetime.utcnow() - timedelta(hours=25)  # 25 hours old (>24h limit)
        )
        db.session.add(c)
        db.session.commit()

    recip = client.application.test_client()
    csrf = extract_csrf_from_page(recip, '/login')

    res = recip.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})
    assert res.status_code == 410
    assert 'EXPIRED_SECRET_DATA' not in res.data.decode('utf-8')


def test_burn_on_read_ciphertext_inaccessible_after_consumption(client):
    """Verifies that DB and raw endpoints never leak ciphertext after consumption."""
    pub_id = f"leak_check_{secrets.token_hex(6)}"
    with client.application.app_context():
        c = Cipher(public_id=pub_id, content='DEFINITIVE_SECRET', burn_on_read=True, is_read=False)
        db.session.add(c)
        db.session.commit()

    recip = client.application.test_client()
    csrf = extract_csrf_from_page(recip, f'/decrypt/{pub_id}')

    # Claim
    res = recip.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})
    assert res.status_code == 200

    # Direct DB inspection: content must be empty string
    with client.application.app_context():
        db_c = Cipher.query.filter_by(public_id=pub_id).first()
        assert db_c.is_read is True
        assert db_c.content == ''

    # GET /decrypt must not contain ciphertext
    get_res = recip.get(f'/decrypt/{pub_id}')
    assert 'DEFINITIVE_SECRET' not in get_res.data.decode('utf-8')


def test_burn_on_read_database_rollback_on_failure(client, monkeypatch):
    """Verifies that if an unexpected error occurs during commit, transaction rolls back safely."""
    pub_id = f"rollback_test_{secrets.token_hex(6)}"
    with client.application.app_context():
        c = Cipher(public_id=pub_id, content='ROLLBACK_PROTECTED_DATA', burn_on_read=True, is_read=False)
        db.session.add(c)
        db.session.commit()

    recip = client.application.test_client()
    csrf = extract_csrf_from_page(recip, '/login')

    # Simulate database commit failure
    original_commit = db.session.commit
    call_count = 0
    def failing_commit():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("Simulated Database I/O Failure on Commit")
        original_commit()

    monkeypatch.setattr(db.session, "commit", failing_commit)

    res = recip.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})
    assert res.status_code == 500
    assert 'ROLLBACK_PROTECTED_DATA' not in res.data.decode('utf-8')

    monkeypatch.undo()

    # Verify atomic rollback: neither claim nor erasure was committed
    with client.application.app_context():
        c_check = Cipher.query.filter_by(public_id=pub_id).first()
        assert c_check is not None
        assert c_check.is_read is False, "Rollback failed: is_read was committed despite failure"
        assert c_check.content == 'ROLLBACK_PROTECTED_DATA', "Rollback failed: content was modified"


def test_burn_on_read_expiry_just_before_boundary(client):
    """Verifies that a message within the 24h window (23h 59m 50s old) is successfully claimable."""
    pub_id = f"exp_before_{secrets.token_hex(6)}"
    now = datetime.utcnow()
    with client.application.app_context():
        c = Cipher(
            public_id=pub_id,
            content='BEFORE_EXPIRY_SECRET',
            burn_on_read=True,
            is_read=False,
            created_at=now - timedelta(hours=23, minutes=59, seconds=50)
        )
        db.session.add(c)
        db.session.commit()

    recip = client.application.test_client()
    csrf = extract_csrf_from_page(recip, f'/decrypt/{pub_id}')

    res = recip.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})
    assert res.status_code == 200
    assert res.get_json().get('ciphertext') == 'BEFORE_EXPIRY_SECRET'

    with client.application.app_context():
        c_db = Cipher.query.filter_by(public_id=pub_id).first()
        assert c_db.is_read is True
        assert c_db.content == ''


def test_burn_on_read_expiry_just_after_boundary(client):
    """Verifies that a message just past the 24h window (24h 0m 10s old) is atomically rejected."""
    pub_id = f"exp_after_{secrets.token_hex(6)}"
    now = datetime.utcnow()
    with client.application.app_context():
        c = Cipher(
            public_id=pub_id,
            content='AFTER_EXPIRY_SECRET',
            burn_on_read=True,
            is_read=False,
            created_at=now - timedelta(hours=24, minutes=0, seconds=10)
        )
        db.session.add(c)
        db.session.commit()

    recip = client.application.test_client()
    csrf = extract_csrf_from_page(recip, '/login')

    res = recip.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})
    assert res.status_code == 410
    assert 'AFTER_EXPIRY_SECRET' not in res.data.decode('utf-8')

    # Confirm message was NOT claimed or mutated
    with client.application.app_context():
        c_db = Cipher.query.filter_by(public_id=pub_id).first()
        assert c_db.is_read is False
        assert c_db.content == 'AFTER_EXPIRY_SECRET'


def test_burn_on_read_expired_message_repeated_consumption(client):
    """Verifies that an expired message consistently rejects repeated consumption attempts."""
    pub_id = f"exp_repeat_{secrets.token_hex(6)}"
    now = datetime.utcnow()
    with client.application.app_context():
        c = Cipher(
            public_id=pub_id,
            content='EXPIRED_REPEAT_SECRET',
            burn_on_read=True,
            is_read=False,
            created_at=now - timedelta(hours=26)
        )
        db.session.add(c)
        db.session.commit()

    recip = client.application.test_client()
    csrf = extract_csrf_from_page(recip, '/login')

    res1 = recip.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})
    assert res1.status_code == 410

    res2 = recip.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})
    assert res2.status_code == 410

    res3 = recip.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})
    assert res3.status_code == 410
    assert 'EXPIRED_REPEAT_SECRET' not in res3.data.decode('utf-8')


def test_burn_on_read_single_transaction_atomicity(client):
    """Verifies that claim and erasure occur within the exact same database commit."""
    pub_id = f"atomicity_{secrets.token_hex(6)}"
    with client.application.app_context():
        c = Cipher(public_id=pub_id, content='ATOMIC_PAYLOAD', burn_on_read=True, is_read=False)
        db.session.add(c)
        db.session.commit()

    recip = client.application.test_client()
    csrf = extract_csrf_from_page(recip, f'/decrypt/{pub_id}')

    commit_count = 0
    original_commit = db.session.commit
    def track_commit():
        nonlocal commit_count
        commit_count += 1
        original_commit()

    import unittest.mock as mock
    with mock.patch.object(db.session, 'commit', side_effect=track_commit):
        res = recip.post(f'/api/cipher/consume/{pub_id}', headers={'X-CSRF-Token': csrf})

    assert res.status_code == 200
    assert res.get_json().get('ciphertext') == 'ATOMIC_PAYLOAD'
    # Exactly ONE database commit occurred during the claim and erasure!
    assert commit_count == 1, f"Expected exactly 1 commit, but observed {commit_count}"
