"""
Obsidian Secure — Cryptography & Zero-Knowledge Contract Tests
Verifies zero-knowledge key decoupling, payload delivery, and Burn-On-Read cipher self-destruct semantics.
"""
import pytest
from app import Cipher, db

def test_cipher_creation_and_zero_knowledge_delivery(auth_client, user1, csrf_token):
    """Verifies that ciphers store encrypted ciphertext without server key custody."""
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
        
        # Test recipient decrypt page loads hidden payload without key
        dec_res = auth_client.get(f'/decrypt/{c.public_id}')
        assert dec_res.status_code == 200
        html = dec_res.data.decode('utf-8')
        assert encrypted_payload in html
        assert 'crypto.js' in html

def test_burn_on_read_cipher_self_destruct(auth_client, user1):
    """Verifies that Burn-On-Read ciphers are invalidated after single-use confirmation."""
    with auth_client.application.app_context():
        c = Cipher(
            public_id='burn_test_public_id_12345',
            content='ENCRYPTED_SECRET_DATA',
            burn_on_read=True,
            is_read=False,
            sender_alias='Tejas'
        )
        db.session.add(c)
        db.session.commit()
        public_id = c.public_id

    # First access loads decrypt page
    res1 = auth_client.get(f'/decrypt/{public_id}')
    assert res1.status_code == 200
    assert 'ENCRYPTED_SECRET_DATA' in res1.data.decode('utf-8')

    # Confirm burn read endpoint
    confirm_res = auth_client.post(f'/api/cipher/confirm_read/{public_id}')
    assert confirm_res.status_code == 200

    # Second access returns expired state
    res2 = auth_client.get(f'/decrypt/{public_id}')
    assert res2.status_code == 200
    assert 'expired' in res2.data.decode('utf-8').lower() or 'unavailable' in res2.data.decode('utf-8').lower()
