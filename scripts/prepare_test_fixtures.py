import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
shared_files = os.path.join(BASE_DIR, 'shared_files')
os.makedirs(shared_files, exist_ok=True)

# Write dummy encrypted blobs for test shares
dummy_payload = b"OBSIDIAN_TEST_ENCRYPTED_BLOB_FIXTURE_DATA_AES256"

for fn in ['financial_audit_2026.pdf', 'security_key_backup.kdbx', 'cf1.bin', 'cf2.bin']:
    fp = os.path.join(shared_files, fn)
    with open(fp, 'wb') as f:
        f.write(dummy_payload)
    print(f"Created fixture file: {fn} ({len(dummy_payload)} bytes)")
