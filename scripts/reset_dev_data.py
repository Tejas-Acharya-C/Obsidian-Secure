"""
Obsidian Secure — Local Development Data Reset Script
Safely clears test database records and uploaded files in shared_files/
preserving schema definitions, configuration, and project source code.
"""
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User, Share, Transfer, UserSetting, Cipher, LoginAttempt, RegistrationAttempt

def reset_local_data():
    print("Starting Obsidian Secure Local Development Data Reset...")
    
    with app.app_context():
        # 1. Clear DB Tables
        num_transfers = Transfer.query.delete()
        num_shares = Share.query.delete()
        num_ciphers = Cipher.query.delete()
        num_settings = UserSetting.query.delete()
        num_login_attempts = LoginAttempt.query.delete()
        num_reg_attempts = RegistrationAttempt.query.delete()
        num_users = User.query.delete()
        
        db.session.commit()
        db.session.execute(db.text("VACUUM;"))
        
        print(f"Cleaned DB Records:")
        print(f"  - Users removed: {num_users}")
        print(f"  - Shares removed: {num_shares}")
        print(f"  - Transfers removed: {num_transfers}")
        print(f"  - Ciphers removed: {num_ciphers}")
        print(f"  - Settings removed: {num_settings}")
        print(f"  - Login Attempts removed: {num_login_attempts}")
        print(f"  - Registration Attempts removed: {num_reg_attempts}")

    # 2. Clean shared_files directory (keep .gitkeep)
    upload_dir = app.config['UPLOAD_FOLDER']
    files_removed = 0
    if os.path.exists(upload_dir):
        for filename in os.listdir(upload_dir):
            if filename == '.gitkeep':
                continue
            file_path = os.path.join(upload_dir, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
                files_removed += 1

    print(f"Cleaned Physical Shared Files: {files_removed} files removed")

    # 3. Clean __pycache__ folders
    cache_dirs_cleaned = 0
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for dirpath, dirnames, filenames in os.walk(root_dir):
        if '__pycache__' in dirnames:
            cache_path = os.path.join(dirpath, '__pycache__')
            for f in os.listdir(cache_path):
                os.remove(os.path.join(cache_path, f))
            os.rmdir(cache_path)
            cache_dirs_cleaned += 1

    print(f"Cleaned Runtime PyCache Directories: {cache_dirs_cleaned} directories cleaned")
    print("Local Development Data Reset Complete!")

if __name__ == '__main__':
    reset_local_data()
