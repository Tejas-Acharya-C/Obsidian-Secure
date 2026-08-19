"""
Obsidian Secure — Authentication & Session Management Tests
Verifies user registration, credential validation, login flows, and session logout.
"""
import pytest
from app import User, db

def test_valid_user_registration(client, csrf_token):
    """Verifies successful registration of a new user account."""
    res = client.post('/register', data={
        'username': 'newuser',
        'password': 'SecurePassword123!',
        'confirm_password': 'SecurePassword123!',
        'csrf_token': csrf_token
    }, follow_redirects=True)
    
    assert res.status_code == 200
    with client.application.app_context():
        u = User.query.filter_by(username='newuser').first()
        assert u is not None
        assert u.username == 'newuser'
        assert u.password_hash != 'SecurePassword123!'  # Must be hashed

def test_duplicate_username_registration(client, user1, csrf_token):
    """Verifies that registration fails if the username already exists."""
    res = client.post('/register', data={
        'username': user1['username'],
        'password': 'Password123!',
        'confirm_password': 'Password123!',
        'csrf_token': csrf_token
    }, follow_redirects=True)
    
    assert res.status_code == 200
    html = res.data.decode('utf-8')
    assert 'already exists' in html.lower() or 'taken' in html.lower() or 'registered' in html.lower()

def test_valid_user_login(client, user1, csrf_token):
    """Verifies successful user authentication and session establishment."""
    res = client.post('/login', data={
        'username': user1['username'],
        'password': user1['password'],
        'csrf_token': csrf_token
    }, follow_redirects=True)
    
    assert res.status_code == 200
    # Accessing protected page succeeds after login
    dash_res = client.get('/dashboard')
    assert dash_res.status_code == 200

def test_invalid_password_login(client, user1, csrf_token):
    """Verifies that incorrect credentials reject authentication."""
    res = client.post('/login', data={
        'username': user1['username'],
        'password': 'WrongPassword999!',
        'csrf_token': csrf_token
    }, follow_redirects=True)
    
    assert res.status_code == 200
    html = res.data.decode('utf-8')
    assert 'invalid' in html.lower() or 'incorrect' in html.lower() or 'failed' in html.lower()
    
    # Accessing protected page fails
    dash_res = client.get('/dashboard')
    assert dash_res.status_code == 302

def test_user_logout(auth_client, csrf_token):
    """Verifies session invalidation upon user logout."""
    res = auth_client.post('/logout', data={'csrf_token': csrf_token}, follow_redirects=True)
    assert res.status_code == 200
    
    # Subsequent access to protected route redirects to login
    dash_res = auth_client.get('/dashboard')
    assert dash_res.status_code == 302
    assert '/login' in dash_res.location
