"""
Obsidian Secure — Pytest Fixtures & Clean Environment Setup
Configures isolated in-memory test database, temporary file storage, and authenticated client fixtures.
"""
import os
import sys
import shutil
import pytest

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app as flask_app, db as _db, User, Share, Cipher
from werkzeug.security import generate_password_hash

@pytest.fixture(scope='session')
def app(tmp_path_factory):
    """Creates an isolated application instance with temporary storage and testing flags."""
    test_upload_dir = tmp_path_factory.mktemp("test_uploads")
    
    flask_app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'UPLOAD_FOLDER': str(test_upload_dir),
        'WTF_CSRF_ENABLED': True,
        'SECRET_KEY': 'test-secret-key-for-pytest-suite',
        'SERVER_NAME': 'localhost'
    })

    with flask_app.app_context():
        _db.create_all()
        yield flask_app
        _db.drop_all()

    # Clean up temp upload directory
    if os.path.exists(test_upload_dir):
        shutil.rmtree(test_upload_dir, ignore_errors=True)

@pytest.fixture(autouse=True)
def clean_db(app):
    """Ensures database tables are clean and reset before each test."""
    with app.app_context():
        _db.session.rollback()
        for table in reversed(_db.metadata.sorted_tables):
            _db.session.execute(table.delete())
        _db.session.commit()
        yield
        _db.session.rollback()

@pytest.fixture
def client(app):
    """Provides a fresh Flask test client."""
    return app.test_client()

@pytest.fixture
def csrf_token(client):
    """Retrieves a valid CSRF token from the login page."""
    res = client.get('/login')
    html = res.data.decode('utf-8')
    import re
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if match:
        return match.group(1)
    # Fallback to meta tag if present
    match_meta = re.search(r'name="csrf-token"\s+content="([^"]+)"', html)
    return match_meta.group(1) if match_meta else ""

@pytest.fixture
def user1(app):
    """Creates primary test user."""
    with app.app_context():
        u = User(username='testuser1', password_hash=generate_password_hash('Password123!'))
        _db.session.add(u)
        _db.session.commit()
        return {'id': u.id, 'username': u.username, 'password': 'Password123!'}

@pytest.fixture
def user2(app):
    """Creates secondary test user for authorization checks."""
    with app.app_context():
        u = User(username='testuser2', password_hash=generate_password_hash('Password123!'))
        _db.session.add(u)
        _db.session.commit()
        return {'id': u.id, 'username': u.username, 'password': 'Password123!'}

@pytest.fixture
def auth_client(client, user1, csrf_token):
    """Provides a client logged in as primary user1."""
    client.post('/login', data={
        'username': user1['username'],
        'password': user1['password'],
        'csrf_token': csrf_token
    }, follow_redirects=True)
    return client

@pytest.fixture
def other_auth_client(app, user2):
    """Provides a separate test client logged in as user2."""
    c = app.test_client()
    res = c.get('/login')
    html = res.data.decode('utf-8')
    import re
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    token = match.group(1) if match else ""
    c.post('/login', data={
        'username': user2['username'],
        'password': user2['password'],
        'csrf_token': token
    }, follow_redirects=True)
    return c
