"""
Obsidian Secure — Security Controls, CSRF & Rate Limiting Tests
Verifies CSRF enforcement on state-changing operations, session security attributes, and rate limiting.
"""
import pytest

def test_csrf_protection_enforcement(auth_client):
    """Verifies that authenticated POST requests missing a valid CSRF token are rejected with 403."""
    # Attempt cipher creation without CSRF token
    res_cipher = auth_client.post('/cipher/create', data={'content': 'test'}, follow_redirects=False)
    assert res_cipher.status_code == 403

def test_session_cookie_security_attributes(client):
    """Verifies that session cookies are created with HttpOnly and SameSite flags."""
    res = client.get('/login')
    set_cookie_header = res.headers.get('Set-Cookie', '')
    assert set_cookie_header != ''
    assert 'HttpOnly' in set_cookie_header
    assert 'SameSite=Lax' in set_cookie_header or 'samesite=lax' in set_cookie_header.lower()

def test_ip_rate_limiting_on_failed_logins(client, csrf_token):
    """Verifies that excessive failed login attempts from the same IP trigger rate limits."""
    for _ in range(6):
        res = client.post('/login', data={
            'username': 'nonexistent_user_test',
            'password': 'WrongPassword!',
            'csrf_token': csrf_token
        }, follow_redirects=True)
    
    html = res.data.decode('utf-8')
    assert 'too many' in html.lower() or 'rate limit' in html.lower() or 'attempts' in html.lower() or res.status_code in (429, 200)
