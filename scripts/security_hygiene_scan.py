"""
Obsidian Secure — Repository Security & Secret Hygiene Scanner
Scans all modified tracked files and all untracked files proposed for commit.
"""
import os
import sys
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 18 Modified Tracked Files + 16 Untracked Files Proposed for Commit
FILES_TO_SCAN = [
    # Tracked Modified (18)
    ".gitignore",
    "Procfile",
    "app.py",
    "models.py",
    "render.yaml",
    "static/css/styles.css",
    "static/css/utilities.css",
    "static/js/app.js",
    "templates/active_shares.html",
    "templates/base.html",
    "templates/cipher_read.html",
    "templates/dashboard.html",
    "templates/landing.html",
    "templates/landing_page.html",
    "templates/login.html",
    "templates/register.html",
    "tests/conftest.py",
    "tests/test_crypto.py",
    # Untracked Proposed (16)
    "static/js/jszip.min.js",
    "templates/collection_landing.html",
    "tests/test_collections.py",
    "scripts/analyze_audit.py",
    "scripts/e2e_acceptance_audit.py",
    "scripts/e2e_browser_crypto_audit.py",
    "scripts/prepare_test_fixtures.py",
    "scripts/run_cdp_audit.py",
    "scripts/run_responsive_audit.py",
    "scripts/test_advisory_suite.py",
    "scripts/test_burn_on_read_suite.py",
    "scripts/test_http_concurrency.py",
    "scripts/test_mobile_drawer.py",
    "scripts/test_postgres_integration.py",
    "scripts/test_storage_failures.py",
    "scripts/security_hygiene_scan.py"
]

# Sensitive patterns (excluding dynamic variable interpolations like {pg_pass})
PATTERNS = [
    ("Hardcoded Literal Database URI with Credentials", re.compile(r'postgres(?:ql)?://[a-zA-Z0-9_\-]+:(?!\{)[^@\s\'\"<>{}]+@[a-zA-Z0-9_\.\-]+:\d+/', re.I)),
    ("Hardcoded Private Key", re.compile(r'-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA)?\s*PRIVATE\s+KEY-----')),
    ("AWS Access Key ID", re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
    ("GitHub Personal Access Token", re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b')),
    ("Google API Key", re.compile(r'\b(AIza[0-9A-Za-z\\-_]{35})\b')),
    ("Stripe API Secret Key", re.compile(r'\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\b')),
    ("Slack Token", re.compile(r'\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b')),
    ("Hardcoded Production SECRET_KEY assignment", re.compile(r'^\s*SECRET_KEY\s*=\s*[\'\"][a-zA-Z0-9_\-]{16,}[\'\"]', re.M)),
]

# Known non-secret mock/sample patterns to exclude
MOCK_ALLOWLIST = [
    "ENCRYPTED_SECRET_DATA_01",
    "DEFINITIVE_SECRET",
    "BEFORE_EXPIRY_SECRET",
    "AFTER_EXPIRY_SECRET",
    "EXPIRED_REPEAT_SECRET",
    "SECRET_PAYLOAD_XYZ",
    "CONFIDENTIAL_PAYLOAD_E2E"
]

def scan():
    print("===================================================================")
    print("  OBSIDIAN SECURE — COMPREHENSIVE SECURITY & SECRET SCANNER")
    print("===================================================================")

    total_files = 0
    total_lines = 0
    findings = []

    # Check that no forbidden files are tracked in git
    import subprocess
    proc = subprocess.run(['git', 'ls-files'], capture_output=True, text=True)
    tracked_files = proc.stdout.splitlines()
    forbidden_extensions = ['.env', '.sqlite', '.db', '.p12', '.pem', '.key']
    for f in tracked_files:
        for ext in forbidden_extensions:
            if f.endswith(ext) and not f.startswith('.env.example'):
                findings.append((f, 0, f"Forbidden tracked file extension: {ext}", f))

    for rel_path in FILES_TO_SCAN:
        full_path = os.path.join(BASE_DIR, rel_path)
        if not os.path.exists(full_path):
            print(f"  [MISSING] {rel_path}")
            findings.append((rel_path, 0, "Proposed file does not exist", ""))
            continue

        total_files += 1
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as fp:
                lines = fp.readlines()
            total_lines += len(lines)

            for line_no, line in enumerate(lines, 1):
                # Skip license comments
                if 'Stuart Knightley' in line or 'pako' in line:
                    continue
                for name, pat in PATTERNS:
                    match = pat.search(line)
                    if match:
                        matched_text = match.group(0)
                        if not any(allow in matched_text for allow in MOCK_ALLOWLIST):
                            findings.append((rel_path, line_no, name, line.strip()))
        except Exception as e:
            print(f"  [ERROR] Could not read {rel_path}: {e}")
            findings.append((rel_path, 0, f"Read error: {e}", ""))

    print(f"Files Scanned:       {total_files} / {len(FILES_TO_SCAN)}")
    print(f"Total Lines Scanned: {total_lines}")
    print("-------------------------------------------------------------------")

    if findings:
        print(f"STATUS: FAILED — {len(findings)} security findings detected:\n")
        for fpath, lno, reason, text in findings:
            print(f"  [ALERT] {fpath}:{lno} -> {reason}")
            if text:
                print(f"          Snippet: {text[:80]}")
        sys.exit(2)
    else:
        print("STATUS: CLEAN — 0 secrets, 0 credentials, 0 forbidden files found.")
        print("===================================================================")
        sys.exit(0)

if __name__ == '__main__':
    scan()
