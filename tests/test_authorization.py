"""
Obsidian Secure — Resource Authorization & Boundary Security Tests
Verifies multi-user resource isolation and prevents cross-tenant data access or share revocation.
"""
import pytest
from app import Share, db
from datetime import datetime, timedelta

def test_user_cannot_revoke_other_user_share(auth_client, other_auth_client, user1, user2):
    """Verifies that User2 cannot revoke a share created by User1."""
    # 1. Create a share owned by user1
    with auth_client.application.app_context():
        s = Share(
            filename='user1_encrypted_file.enc',
            original_name='confidential.pdf',
            mime_type='application/pdf',
            upload_time=datetime.utcnow(),
            expiry_time=datetime.utcnow() + timedelta(hours=24),
            download_count=0,
            public_url='http://localhost/download/user1_encrypted_file.enc',
            user_id=user1['id']
        )
        db.session.add(s)
        db.session.commit()
        share_id = s.id
        public_url = s.public_url

    # 2. Get CSRF token for user2 client
    res2 = other_auth_client.get('/active-shares')
    html2 = res2.data.decode('utf-8')
    import re
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html2)
    user2_token = match.group(1) if match else ""

    # 3. User2 attempts to revoke User1's share
    revoke_res = other_auth_client.post('/revoke', data={
        'public_url': public_url,
        'csrf_token': user2_token
    }, follow_redirects=True)
    
    # Verify Share was NOT deleted
    with auth_client.application.app_context():
        s_check = db.session.get(Share, share_id)
        assert s_check is not None, "User2 was able to revoke User1's share!"

def test_unauthenticated_revoke_redirects(client):
    """Verifies that unauthenticated POST requests to /revoke redirect to login."""
    res = client.post('/revoke', data={'public_url': 'http://localhost/download/test.enc'}, follow_redirects=False)
    assert res.status_code == 302
    assert '/login' in res.location
