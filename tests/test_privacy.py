"""
Obsidian Secure — Privacy Policy Specification Tests
Verifies privacy page accessibility, search indexability, and key architecture disclosures.
"""
import pytest

def test_privacy_policy_page_accessibility_and_disclosures(client):
    """Verifies that /privacy is publicly accessible and contains core security disclosures."""
    res = client.get('/privacy')
    assert res.status_code == 200
    
    html = res.data.decode('utf-8')
    assert '<title>Privacy Policy | Obsidian Secure</title>' in html
    assert '<link rel="canonical"' in html
    assert 'href="http://localhost/privacy"' in html or '/privacy' in html
    assert '<meta name="robots" content="index, follow">' in html
    
    # Core disclosure assertions
    assert 'Zero-Knowledge Architecture' in html
    assert 'AES-256-GCM' in html
    assert 'PBKDF2' in html
    assert 'Rate Limiting' in html
    assert 'Third-Party' in html
