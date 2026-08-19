"""
Obsidian Secure — Public & Authenticated Routing Tests
Verifies HTTP status codes, public access, authentication boundaries, and custom 404 behavior.
"""
import pytest

def test_public_routes(client):
    """Verifies that public pages return HTTP 200 OK without requiring authentication."""
    for path in ['/', '/login', '/register', '/privacy']:
        res = client.get(path)
        assert res.status_code == 200, f"Route {path} failed with {res.status_code}"

def test_protected_routes_redirect_unauthenticated(client):
    """Verifies that protected application endpoints redirect unauthenticated users to /login."""
    protected_paths = ['/dashboard', '/active-shares', '/shared', '/cipher', '/settings', '/security']
    for path in protected_paths:
        res = client.get(path)
        assert res.status_code == 302, f"Protected route {path} did not redirect"
        assert '/login' in res.location

def test_protected_routes_accessible_when_authenticated(auth_client):
    """Verifies that authenticated users can access protected workspace routes."""
    for path in ['/dashboard', '/active-shares', '/cipher', '/settings', '/security']:
        res = auth_client.get(path)
        assert res.status_code == 200, f"Authenticated user could not access {path}"

def test_custom_404_error_page(client):
    """Verifies that non-existent routes return HTTP 404 and render the custom standalone 404 page."""
    res = client.get('/nonexistent-test-route-404')
    assert res.status_code == 404
    html = res.data.decode('utf-8')
    assert 'Page Not Found' in html
    assert 'Return to Homepage' in html
    # Verify nav system is suppressed
    assert 'Main navigation' not in html
    assert 'Active Shares' not in html
