"""
Obsidian Secure — SEO, Sitemap & Search Engine Discoverability Tests
Verifies meta tags, canonical links, Open Graph tags, robots.txt rules, sitemap XML, and private noindex protection.
"""
import pytest
import xml.etree.ElementTree as ET

def test_homepage_seo_metadata(client):
    """Verifies page title, meta description, canonical link, and Open Graph tags on public homepage."""
    res = client.get('/')
    assert res.status_code == 200
    html = res.data.decode('utf-8')
    
    assert '<title>Obsidian Secure' in html
    assert 'name="description"' in html
    assert '<link rel="canonical"' in html
    assert 'property="og:title"' in html
    assert 'property="og:description"' in html
    assert 'property="og:image"' in html
    assert 'name="twitter:card"' in html

def test_robots_txt_rules(client):
    """Verifies robots.txt disallow rules for private routes and sitemap advertisement."""
    res = client.get('/robots.txt')
    assert res.status_code == 200
    assert 'text/plain' in res.headers.get('Content-Type', '')
    
    text = res.data.decode('utf-8')
    assert 'User-agent: *' in text
    assert 'Allow: /' in text
    assert 'Disallow: /dashboard' in text
    assert 'Disallow: /active-shares' in text
    assert 'Disallow: /cipher' in text
    assert 'Sitemap:' in text

def test_sitemap_xml_format(client):
    """Verifies sitemap.xml structure, inclusion of indexable public URLs (/ and /privacy), and exclusion of private routes."""
    res = client.get('/sitemap.xml')
    assert res.status_code == 200
    assert 'xml' in res.headers.get('Content-Type', '')
    
    xml_str = res.data.decode('utf-8')
    root = ET.fromstring(xml_str)
    assert root.tag.endswith('urlset')
    assert '<loc>http://localhost/</loc>' in xml_str or '<loc>https://' in xml_str
    assert '/privacy</loc>' in xml_str
    assert '/dashboard' not in xml_str
    assert '/login' not in xml_str
    assert '/register' not in xml_str

def test_private_routes_noindex_protection(client):
    """Verifies that recipient share pages and unauthenticated error states enforce noindex, nofollow."""
    res_dl = client.get('/download/nonexistent_file')
    assert res_dl.status_code == 200
    assert '<meta name="robots" content="noindex, nofollow">' in res_dl.data.decode('utf-8')

def test_google_search_console_verification(client):
    """Verifies public accessibility and exact content of Google Search Console HTML verification endpoint."""
    res = client.get('/googlee5ae4db6815276ae.html')
    assert res.status_code == 200
    assert res.headers.get('Content-Type', '').startswith('text/html')
    assert res.data.decode('utf-8') == "google-site-verification: googlee5ae4db6815276ae.html"
