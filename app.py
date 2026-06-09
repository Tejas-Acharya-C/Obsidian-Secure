import os
import re
import uuid
import html as html_lib
import socket
import io
import base64
import secrets
import threading
import time
import mimetypes
from functools import wraps
from flask import Flask, render_template, request, send_from_directory, redirect, url_for, g, session, jsonify
from datetime import datetime, timedelta
import zipfile
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

# Enterprise Models
from models import db, User, Share, Transfer, UserSetting, Cipher, LoginAttempt, RegistrationAttempt

app = None

try:
    app = Flask(__name__)
    
    # --- ENTERPRISE CONFIGURATION ---
    # Storage Path for Render Persistent Disk
    if os.environ.get('RENDER'):
        # Default Render Persistent Disk mount point
        DATA_DIR = os.environ.get('PERSISTENT_DISK_PATH', '/var/lib/obsidian/data')
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            # Test write access to confirm persistent disk is attached and writable
            test_path = os.path.join(DATA_DIR, '.write_test')
            with open(test_path, 'w') as f:
                f.write('test')
            os.remove(test_path)
            UPLOAD_FOLDER = os.path.join(DATA_DIR, 'shared_files')
        except Exception:
            # Fallback to project root directory (e.g. on free tier without disk attached)
            DATA_DIR = os.path.dirname(os.path.abspath(__file__))
            UPLOAD_FOLDER = os.path.join(DATA_DIR, 'shared_files')
            
        DATABASE_URI = os.environ.get('DATABASE_URL')
        if DATABASE_URI:
            if DATABASE_URI.startswith("postgres://"):
                DATABASE_URI = DATABASE_URI.replace("postgres://", "postgresql://", 1)
        else:
            DATABASE_URI = 'sqlite:///' + os.path.join(DATA_DIR, 'qr_app.db')
    else:
        DATA_DIR = os.path.dirname(os.path.abspath(__file__))
        UPLOAD_FOLDER = os.path.join(DATA_DIR, 'shared_files')
        DATABASE_URI = 'sqlite:///' + os.path.join(DATA_DIR, 'qr_app.db')
    
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = int(5.5 * 1024 * 1024 * 1024)  # 5.5GB
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    
    # Ensure storage path exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # --- REVERSE PROXY SAFETY ---
    # Trust 1 level of proxy headers (standard for Render / Cloudflare / Nginx).
    # This ensures request.remote_addr resolves to the real client IP,
    # not the proxy's IP, which would cause global login rate-limit lockouts.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    # Initialize DB & Login
    db.init_app(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login_page'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # --- SECURITY CONFIG ---
    app.permanent_session_lifetime = timedelta(hours=24)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=True if os.environ.get('RENDER') else False
    )
    
    # Public base URL — set this in the Render environment to match the actual
    # service URL (e.g. https://obsidian-secure-ootw.onrender.com).
    # Falls back to deriving the base URL from the incoming request at link
    # generation time, which is correct for local development.
    PUBLIC_BASE_URL = os.environ.get('PUBLIC_BASE_URL', '').rstrip('/')

    heavy_task_semaphore = threading.Semaphore(3)
    
    # Initial Setup Logic
    def init_enterprise_db():
        with app.app_context():
            # Step 1: Create any tables that are entirely missing.
            # db.create_all() is safe to call on an existing DB — it only creates
            # tables that do not yet exist and never modifies existing ones.
            db.create_all()

            # Step 2: Run column-level migrations for tables that already exist
            # in production but are missing columns added in later model revisions.
            # This handles schema drift between db.create_all() deployments.
            run_schema_migrations()

    def run_schema_migrations():
        """Production-safe column migration layer.

        db.create_all() creates missing tables but never alters existing ones.
        This function detects and adds individual missing columns using raw SQL
        so that existing production databases are brought in sync with models.py
        without any data loss or table drops.

        Supports both SQLite (development) and PostgreSQL (production on Render).
        Each ALTER is isolated in its own transaction so a single failure does not
        block the remaining migrations.
        """
        from sqlalchemy import text, inspect

        # Columns to ensure exist: (table_name, column_name, column_definition)
        # Add new entries here whenever a nullable or defaulted column is added
        # to an existing model after the initial production deployment.
        REQUIRED_COLUMNS = [
            # Cipher.sender_alias — added after initial production deploy
            ('cipher', 'sender_alias', 'VARCHAR(255)'),
            # Share.mime_type — added for MIME type preservation
            ('share', 'mime_type', 'VARCHAR(255)'),
            # Share.version — added for V2 File Sharing architecture
            ('share', 'version', 'INTEGER DEFAULT 2'),
        ]

        is_postgres = 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'].lower()
        is_sqlite = 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI'].lower()

        with db.engine.connect() as conn:
            for table_name, column_name, column_type in REQUIRED_COLUMNS:
                try:
                    column_exists = False

                    if is_postgres:
                        # PostgreSQL: query information_schema for the column
                        result = conn.execute(text(
                            "SELECT COUNT(*) FROM information_schema.columns "
                            "WHERE table_name = :t AND column_name = :c"
                        ), {'t': table_name, 'c': column_name})
                        column_exists = result.scalar() > 0

                    elif is_sqlite:
                        # SQLite: use PRAGMA table_info to list columns
                        result = conn.execute(text(f"PRAGMA table_info({table_name})"))
                        columns = [row[1] for row in result.fetchall()]
                        column_exists = column_name in columns

                    if not column_exists:
                        # Add the missing column. NULL is safe because all added
                        # columns are nullable — no default is required.
                        conn.execute(text(
                            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
                        ))
                        conn.commit()
                        print(
                            f"[schema_migration] Added missing column: "
                            f"{table_name}.{column_name} ({column_type})",
                            flush=True
                        )
                    else:
                        # Column already present — nothing to do
                        pass

                except Exception as migration_err:
                    # Log but do not crash startup. If the column already exists
                    # under a different type or the table does not exist yet,
                    # db.create_all() above will have handled the table case,
                    # and a type mismatch is not actionable here.
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    print(
                        f"[schema_migration] Warning — could not migrate "
                        f"{table_name}.{column_name}: {migration_err}",
                        flush=True
                    )

    init_enterprise_db()
except Exception as e:
    import sys
    import traceback
    print("FATAL ERROR DURING APP INITIALIZATION:", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    sys.stderr.flush()
    sys.exit(1)

# --- SECURITY HEADERS ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer'
    
    # HSTS Hardening for production environments
    if os.environ.get('RENDER'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "
        "font-src 'self' fonts.gstatic.com; "
        "img-src 'self' data:; "
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Prevent caching of dynamic resources (pages containing sensitive E2EE details/QR codes)
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=3600'
    else:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        
    return response

# --- CONTEXT LEAK MITIGATION ---
@app.before_request
def clear_stale_login_cache():
    """Ensure cached Flask-Login current_user is re-evaluated if session user changes or is cleared.
    This resolves stale global context reuse in test suites running within a persistent app_context.
    """
    from flask import g
    session_user_id = session.get('_user_id')
    if hasattr(g, '_login_user'):
        cached_user = getattr(g, '_login_user')
        is_stale = False
        if not session_user_id:
            # If session is anonymous, but cached user is authenticated -> stale
            if cached_user and getattr(cached_user, 'is_authenticated', False):
                is_stale = True
        else:
            # If session is logged in, but cached user is anonymous or has a different ID -> stale
            if not cached_user or not getattr(cached_user, 'is_authenticated', False):
                is_stale = True
            elif hasattr(cached_user, 'id') and str(cached_user.id) != str(session_user_id):
                is_stale = True
            elif not hasattr(cached_user, 'id'):
                is_stale = True
                
        if is_stale:
            delattr(g, '_login_user')

# --- AUTH ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    ip = request.remote_addr
    error = request.args.get('error')
    if error and error not in ['RATE_LIMIT_EXCEEDED', 'ACCESS_DENIED', 'CSRF_VALIDATION_FAILED']:
        app.logger.error(f"Unknown login error code: {error}")
        error = None
    
    # Rate Limit Check
    attempt = LoginAttempt.query.get(ip)
    if attempt:
        if attempt.attempts >= 5 and datetime.utcnow() < attempt.last_attempt + timedelta(minutes=15):
            return render_template('login.html', error='RATE_LIMIT_EXCEEDED')
        elif datetime.utcnow() > attempt.last_attempt + timedelta(minutes=15):
            attempt.attempts = 0
            db.session.commit()

    if request.method == 'POST':
        if not validate_csrf():
             time.sleep(1)
             return render_template('login.html', error='CSRF_VALIDATION_FAILED')

        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            remember = request.form.get('remember') == 'true'
            login_user(user, remember=remember)
            # Reset attempts
            if attempt:
                db.session.delete(attempt)
                db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            if not attempt:
                attempt = LoginAttempt(ip=ip, attempts=1, last_attempt=datetime.utcnow())
                db.session.add(attempt)
            else:
                attempt.attempts += 1
                attempt.last_attempt = datetime.utcnow()
            db.session.commit()
            time.sleep(1)
            error = 'ACCESS_DENIED'
            
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register_page():

    ip = request.remote_addr
    error = request.args.get('error')
    if error and error not in ['FIELDS_REQUIRED', 'USER_EXISTS', 'INVALID_USERNAME', 'INVALID_PASSWORD', 'RATE_LIMIT_EXCEEDED', 'CSRF_VALIDATION_FAILED', 'PASSWORDS_DONT_MATCH']:
        app.logger.error(f"Unknown registration error code: {error}")
        error = None

    if request.method == 'POST':
        # Dedicated Registration Rate Limiting (5 per hour)
        now = datetime.utcnow()
        reg_attempt = RegistrationAttempt.query.get(ip)
        if reg_attempt:
            if now > reg_attempt.last_attempt + timedelta(hours=1):
                reg_attempt.attempts = 1
                reg_attempt.last_attempt = now
            else:
                reg_attempt.attempts += 1
        else:
            reg_attempt = RegistrationAttempt(ip=ip, attempts=1, last_attempt=now)
            db.session.add(reg_attempt)
            
        db.session.commit()

        if reg_attempt.attempts > 5:
            return render_template('register.html', error='RATE_LIMIT_EXCEEDED')

        if not validate_csrf():
             time.sleep(1)
             return render_template('register.html', error='CSRF_VALIDATION_FAILED')

        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password or not confirm_password:
            return render_template('register.html', error='FIELDS_REQUIRED')
            
        if password != confirm_password:
            return render_template('register.html', error='PASSWORDS_DONT_MATCH')
            
        if not re.match(r'^[A-Za-z0-9_]+$', username) or len(username) > 50:
            return render_template('register.html', error='INVALID_USERNAME')
            
        if not is_password_valid(password):
            return render_template('register.html', error='INVALID_PASSWORD')
            
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='USER_EXISTS')
            
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('dashboard'))
        
    return render_template('register.html', error=error)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    if not validate_csrf():
        return 'CSRF validation failed', 403
    logout_user()
    return redirect(url_for('login_page'))

# --- CSRF ---
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf():
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return False
    return True

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# --- CLEANUP ---

def background_cleanup():
    """Periodic cleanup of expired files and read ciphers. Runs in background.
    Uses SQLAlchemy ORM within a Flask app context so it works transparently
    against both SQLite (development) and PostgreSQL (production).
    """
    while True:
        try:
            with app.app_context():
                now = datetime.utcnow()
                
                # Find and remove expired shares
                expired_shares = Share.query.filter(Share.expiry_time < now).all()
                for share in expired_shares:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], share.filename)
                    if os.path.exists(file_path):
                        try: os.remove(file_path)
                        except: pass
                    db.session.delete(share)  # cascade deletes associated transfers
                
                # Also clean read ciphers older than 24h
                Cipher.query.filter(
                    Cipher.is_read == True,
                    Cipher.created_at < now - timedelta(hours=24)
                ).delete()
                
                # CLEANUP: Remove old login attempts (older than 7 days) to prevent DB bloat
                LoginAttempt.query.filter(
                    LoginAttempt.last_attempt < now - timedelta(days=7)
                ).delete()
                
                # DISK RECONCILIATION: Remove orphan files from UPLOAD_FOLDER
                if os.path.exists(app.config['UPLOAD_FOLDER']):
                    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        if os.path.isfile(file_path):
                            # Check if older than 24h
                            try:
                                mtime = os.path.getmtime(file_path)
                                mtime_dt = datetime.utcfromtimestamp(mtime)
                                if now - mtime_dt > timedelta(hours=24):
                                    # Verify it does NOT exist in the Share table
                                    if not Share.query.filter_by(filename=filename).first():
                                        os.remove(file_path)
                            except Exception:
                                pass
                
                db.session.commit()
            
            # Run every 5 minutes
            time.sleep(300)
        except Exception as e:
            try:
                with app.app_context():
                    db.session.rollback()
            except:
                pass
            # If DB is locked or unavailable, wait a bit and retry
            time.sleep(30)


# --- METRICS BATCHER (Optimization for 1000 Users) ---

class MetricsBatcher:
    """Thread-safe buffer to batch download updates and reduce DB writes.
    Uses SQLAlchemy ORM within a Flask app context so it works transparently
    against both SQLite (development) and PostgreSQL (production).
    """
    def __init__(self, flush_interval=10):
        self.flush_interval = flush_interval
        self.queue = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._flusher, daemon=True)
        self.thread.start()

    def log_download(self, share_id, filename):
        with self.lock:
            self.queue.append({'id': share_id, 'file': filename, 'time': datetime.utcnow()})
            # Flush immediately if queue is getting too large
            if len(self.queue) >= 50:
                self._flush_now()

    def _flusher(self):
        while True:
            time.sleep(self.flush_interval)
            self._flush_now()

    def _flush_now(self):
        with self.lock:
            if not self.queue:
                return
            current_batch = self.queue[:]
            self.queue = []

        try:
            with app.app_context():
                # Batch update download counts
                counts = {}
                for item in current_batch:
                    counts[item['file']] = counts.get(item['file'], 0) + 1
                
                for filename, count in counts.items():
                    Share.query.filter_by(filename=filename).update(
                        {Share.download_count: Share.download_count + count}
                    )
                
                # Batch insert transfers
                for item in current_batch:
                    db.session.add(Transfer(share_id=item['id'], timestamp=item['time']))
                
                db.session.commit()
        except Exception as e:
            print(f"Metrics Batcher Error: {e}")
            try:
                with app.app_context():
                    db.session.rollback()
            except:
                pass

# Initialize global batcher
metrics_batcher = MetricsBatcher()



def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# Regression test references (do not delete):
# wraps, jsonify, Image, socket, get_local_ip

# Removed generate_qr_base64

USER_SETTING_DEFAULTS = {
    'alias': 'OBSIDIAN_NODE',
    'auto_revoke': 'true',
    'ghost_mode': 'false'
}

def get_user_setting(user_id, key, default=None):
    if not user_id:
        return USER_SETTING_DEFAULTS.get(key, default)
    s = UserSetting.query.filter_by(user_id=user_id, key=key).first()
    if s:
        return s.value
    return USER_SETTING_DEFAULTS.get(key, default)


def is_password_valid(password):
    return bool(password) and len(password) >= 8


def serialize_share(row, is_ghost=False):
    canonical_url = row.public_url.replace('/get/', '/download/')
    latest_transfer = None
    if row.transfers:
        latest_transfer = max((t.timestamp for t in row.transfers if t.timestamp), default=None)

    return {
        'id': row.id,
        'filename': row.filename,
        'original_name': f"Hidden file {row.id}" if is_ghost else row.original_name,
        'upload_time': row.upload_time,
        'expiry_time': row.expiry_time,
        'download_count': row.download_count,
        'public_url': canonical_url,
        'last_accessed_at': latest_transfer
    }

def get_storage_size(folder):
    total_size = 0
    if not os.path.exists(folder): return 0
    for dirpath, dirnames, filenames in os.walk(folder):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size

# Allowed settings keys (BUG-004 fix)
ALLOWED_SETTINGS = {'alias', 'auto_revoke', 'ghost_mode'}

# --- CONTEXT ---
@app.context_processor
def inject_global_vars():
    try:
        # DATA ISOLATION: Only show notifications if logged in
        if not current_user.is_authenticated:
            return dict(notifications=[], now=datetime.utcnow)

        is_ghost = get_user_setting(current_user.id, 'ghost_mode') == 'true'
        
        raw_notifications = Share.query.filter(Share.download_count > 0).order_by(Share.id.desc()).limit(5).all()
        notifications = []
        for n in raw_notifications:
            name = "HIDDEN_PAYLOAD.enc" if is_ghost else n.original_name
            notifications.append({'original_name': name, 'download_count': n.download_count})
            
        return dict(
            notifications=notifications,
            now=datetime.utcnow
        )
    except:
        return dict(notifications=[], now=datetime.utcnow)

# --- ROUTES ---

@app.route('/')
def home_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing_page.html')

@app.route('/dashboard')
@login_required
def dashboard():
    public_url = session.pop('success_public_url', None)
    message = session.pop('success_message', None)
    is_ghost = get_user_setting(current_user.id, 'ghost_mode') == 'true'
    shares = Share.query.filter_by(user_id=current_user.id).order_by(Share.upload_time.desc()).all()
    shares_list = [serialize_share(row, is_ghost=is_ghost) for row in shares]
    return render_template('dashboard.html', current_page='files', 
                           public_url=public_url, message=message, shares=shares_list)

@app.route('/shared')
@login_required
def shared_page():
    return redirect(url_for('dashboard'))

@app.route('/cipher')
@login_required
def cipher_page():
    ciphers = Cipher.query.filter_by(is_read=False).order_by(Cipher.created_at.desc()).all()
    ciphers_list = []
    for row in ciphers:
        ciphers_list.append({
            'id': row.id,
            'content': row.content,
            'public_id': row.public_id,
            'burn_on_read': row.burn_on_read,
            'is_read': row.is_read,
            'created_at': row.created_at
        })
    public_url = session.pop('success_cipher_url', None)
    message = session.pop('success_cipher_message', None)
    return render_template('dashboard.html', current_page='cipher', ciphers=ciphers_list,
                           public_url=public_url, message=message)

@app.route('/cipher/create', methods=['POST'])
@login_required
def create_cipher():
    if not validate_csrf():
        return 'CSRF validation failed', 403
    
    content = request.form.get('content', '').strip()
    burn = 'true' if request.form.get('burn_on_read') else 'false'
    if not content:
        return redirect(url_for('cipher_page'))
    
    content = html_lib.escape(content)
    public_id = secrets.token_urlsafe(16)
    
    base_url = PUBLIC_BASE_URL if PUBLIC_BASE_URL else f"{request.scheme}://{request.host}"
    decrypt_url = f"{base_url}/decrypt/{public_id}"
    
    # Capture current user's alias snapshot
    sender_alias = get_user_setting(current_user.id, 'alias', 'OBSIDIAN_NODE')

    new_cipher = Cipher(
        content=content,
        public_id=public_id,
        burn_on_read= (burn == 'true'),
        created_at=datetime.utcnow(),
        sender_alias=sender_alias
    )
    db.session.add(new_cipher)
    db.session.commit()
    
    session['success_cipher_url'] = decrypt_url
    session['success_cipher_message'] = "Message encrypted successfully"
    return redirect(url_for('cipher_page'))

@app.route('/decrypt/<public_id>')
def decrypt_cipher(public_id):
    row = Cipher.query.filter_by(public_id=public_id, is_read=False).first()
    if not row:
        return render_template('cipher_read.html', content=None, expired=True, alias=None)
    
    content = row.content
    alias = row.sender_alias if row.sender_alias else 'OBSIDIAN_NODE'
    
    return render_template('cipher_read.html', content=content, expired=False, alias=alias)

@app.route('/api/cipher/confirm_read/<public_id>', methods=['POST'])
def confirm_cipher_read(public_id):
    row = Cipher.query.filter_by(public_id=public_id, is_read=False).first()
    if row and row.burn_on_read:
        row.is_read = True
        db.session.commit()
    return jsonify({"status": "success"})

@app.route('/settings')
@login_required
def settings_page():
    # Lazy initialize settings for this user if they don't exist yet
    for key in ALLOWED_SETTINGS:
        s = UserSetting.query.filter_by(user_id=current_user.id, key=key).first()
        if not s:
            default_val = USER_SETTING_DEFAULTS.get(key)
            db.session.add(UserSetting(user_id=current_user.id, key=key, value=default_val))
    db.session.commit()

    rows = UserSetting.query.filter_by(user_id=current_user.id).all()
    settings = {row.key: row.value for row in rows}
    size_bytes = get_storage_size(app.config['UPLOAD_FOLDER'])
    size_mb = round(size_bytes / (1024 * 1024), 2)
    my_share_count = Share.query.filter_by(user_id=current_user.id).count()

    return render_template('dashboard.html', current_page='settings', 
                           storage_size=size_mb,
                           settings=settings,
                           my_share_count=my_share_count,
                           password_error=session.pop('password_error', None),
                           password_success=session.pop('password_success', None))


@app.route('/security')
@login_required
def security_page():
    return render_template('dashboard.html', current_page='security')


@app.route('/settings/password', methods=['POST'])
@login_required
def change_password():
    if not validate_csrf():
        session['password_error'] = 'Security check failed. Reload the page and try again.'
        return redirect(url_for('settings_page'))

    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not check_password_hash(current_user.password_hash, current_password):
        session['password_error'] = 'Current password is incorrect.'
        return redirect(url_for('settings_page'))

    if not is_password_valid(new_password):
        session['password_error'] = 'New password must be at least 8 characters long.'
        return redirect(url_for('settings_page'))

    if new_password != confirm_password:
        session['password_error'] = 'New password and confirmation do not match.'
        return redirect(url_for('settings_page'))

    if check_password_hash(current_user.password_hash, new_password):
        session['password_error'] = 'Choose a new password that is different from your current one.'
        return redirect(url_for('settings_page'))

    current_user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    session['password_success'] = 'Password updated successfully.'
    return redirect(url_for('settings_page'))

@app.route('/api/settings', methods=['POST'])
@login_required
def update_settings():
    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return {'error': 'CSRF validation failed'}, 403
    
    data = request.json
    for key, value in data.items():
        if key not in ALLOWED_SETTINGS:
            continue
        val_str = str(value)
        if key in ('auto_revoke', 'ghost_mode'):
            val_str = val_str.lower()
        s = UserSetting.query.filter_by(user_id=current_user.id, key=key).first()
        if not s:
            s = UserSetting(user_id=current_user.id, key=key, value=val_str)
            db.session.add(s)
        else:
            s.value = val_str
    db.session.commit()
    return {"status": "success"}

@app.route('/get/<filename>')
def get_file(filename):
    share = Share.query.filter_by(filename=filename).first()
    if not share:
        return "File not found", 404
    
    # Enforce expiry at access time — never serve expired files
    if share.expiry_time and datetime.utcnow() > share.expiry_time:
        return "File expired", 410

    # Guard against missing physical file (ephemeral storage reset on Render free tier
    # or any other condition where the DB record outlives the file on disk).
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        app.logger.warning(f"[get_file] Physical file missing for share id={share.id} filename={filename}")
        return "File is no longer available", 410
    
    # LOG ASYNC METRICS
    metrics_batcher.log_download(share.id, filename)
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 
        filename, 
        as_attachment=True, 
        download_name=share.original_name
    )

@app.route('/revoke', methods=['POST'])
@login_required
def revoke_link():
    if not validate_csrf():
        return 'CSRF validation failed', 403
    
    share_url = request.form.get('public_url')
    if share_url:
        # Security: Only revoke if I am the owner
        share = Share.query.filter_by(public_url=share_url).first()
        if share and (share.user_id == current_user.id):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], share.filename)
            if os.path.exists(file_path):
                try: os.remove(file_path)
                except: pass
            db.session.delete(share)
            db.session.commit()
    return redirect(request.referrer or url_for('shared_page'))

@app.route('/download/<filename>')
def landing_page(filename):
    # Verify share exists and enforce expiry at access time
    share = Share.query.filter_by(filename=filename).first()
    if not share or (share.expiry_time and datetime.utcnow() > share.expiry_time):
        return render_template('landing.html', filename=filename, display_name=filename, alias=None, expired=True, file_unavailable=False)
    
    is_ghost = False
    alias = 'OBSIDIAN_NODE'
    try:
        if share.user_id:
            is_ghost = get_user_setting(share.user_id, 'ghost_mode') == 'true'
            alias = get_user_setting(share.user_id, 'alias', 'OBSIDIAN_NODE')
        else:
            is_ghost = USER_SETTING_DEFAULTS.get('ghost_mode') == 'true'
            alias = USER_SETTING_DEFAULTS.get('alias', 'OBSIDIAN_NODE')
    except:
        pass
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file_exists = os.path.exists(file_path)
    file_size = os.path.getsize(file_path) if file_exists else 0

    # File record is valid and not expired, but the physical file is missing.
    # This happens on Render free tier when storage is reset after a redeploy
    # or after the service wakes from sleep. Show a clear, professional message.
    file_unavailable = not file_exists

    display_name = f"ENCRYPTED_PAYLOAD.bin" if is_ghost else share.original_name
    
    # MIME Type Preservation (Fallback to guess for legacy shares)
    mime_type = share.mime_type
    if not mime_type:
        mime_type = mimetypes.guess_type(share.original_name)[0] or 'application/octet-stream'

    return render_template('landing.html', filename=filename, display_name=display_name,
                           alias=alias, expired=False, file_size=file_size,
                           expiry_time=share.expiry_time, file_unavailable=file_unavailable,
                           mime_type=mime_type)

@app.route('/upload/stream', methods=['POST'])
@login_required
def upload_file_stream():
    """Accept raw encrypted stream upload (OBSv2 format) via sequential chunks.
    Headers: X-CSRF-Token, X-Original-Name, X-Upload-ID, X-Chunk-Index, X-Total-Chunks
    """
    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'error': 'CSRF validation failed'}), 403
    
    upload_id = request.headers.get('X-Upload-ID')
    if not upload_id or not upload_id.isalnum():
        return jsonify({'error': 'Invalid Upload ID'}), 400
        
    try:
        chunk_index = int(request.headers.get('X-Chunk-Index', 0))
        total_chunks = int(request.headers.get('X-Total-Chunks', 1))
    except ValueError:
        return jsonify({'error': 'Invalid chunk headers'}), 400
    
    original_name_b64 = request.headers.get('X-Original-Name', '')
    try:
        original_name = base64.b64decode(original_name_b64).decode('utf-8', errors='replace')
    except Exception:
        original_name = 'unnamed_file'
    safe_name = secure_filename(original_name) or 'unnamed_file'
    
    mime_type = request.headers.get('X-Mime-Type', 'application/octet-stream')
    
    filename = f"{upload_id}_{safe_name}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Append mode for all chunks after the first
    mode = 'ab' if chunk_index > 0 else 'wb'
    
    with heavy_task_semaphore:
        with open(file_path, mode) as f:
            while True:
                chunk = request.stream.read(65536)
                if not chunk:
                    break
                f.write(chunk)
    
    # Validate write
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return jsonify({'error': 'Upload failed: no data received'}), 400
    
    # If this is the final chunk, finalize the share record
    if chunk_index == total_chunks - 1:
        is_auto_revoke = get_user_setting(current_user.id, 'auto_revoke') == 'true'
        upload_time = datetime.utcnow()
        expiry_delta = timedelta(hours=1) if is_auto_revoke else timedelta(days=7)
        expiry_time = upload_time + expiry_delta
        
        base_url = PUBLIC_BASE_URL if PUBLIC_BASE_URL else f"{request.scheme}://{request.host}"
        share_url = f"{base_url}/download/{filename}"
        
        new_share = Share(
            filename=filename,
            original_name=original_name,
            mime_type=mime_type,
            upload_time=upload_time,
            expiry_time=expiry_time,
            public_url=share_url,
            user_id=current_user.id
        )
        db.session.add(new_share)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'redirect': url_for('dashboard'),
            'public_url': share_url,
            'share': {
                'original_name': serialize_share(new_share, is_ghost=get_user_setting(current_user.id, 'ghost_mode') == 'true')['original_name'],
                'public_url': share_url,
                'download_count': 0,
                'upload_time': upload_time.isoformat() + 'Z',
                'expiry_time': expiry_time.isoformat() + 'Z',
                'last_accessed_at': None
            }
        })
        
    return jsonify({'status': 'continue'})

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    return jsonify({"error": "Endpoint deprecated. Use OBSv2 /upload/stream or /api/v2/upload"}), 410

@app.route('/api/v2/upload', methods=['POST'])
@login_required
def upload_file_v2():
    """Accept single encrypted Blob upload (V2 architecture) up to 100MB.
    Headers: X-CSRF-Token, X-Original-Name, X-Mime-Type
    """
    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'error': 'CSRF validation failed'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400
        
    file_obj = request.files['file']
    if file_obj.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Read original name
    original_name_b64 = request.headers.get('X-Original-Name', '')
    try:
        original_name = base64.b64decode(original_name_b64).decode('utf-8', errors='replace')
    except Exception:
        original_name = 'unnamed_file'
    safe_name = secure_filename(original_name) or 'unnamed_file'
    
    mime_type = request.headers.get('X-Mime-Type', 'application/octet-stream')
    
    upload_id = secrets.token_hex(8)
    filename = f"{upload_id}_{safe_name}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Write entire file at once
    with heavy_task_semaphore:
        file_obj.save(file_path)
    
    # Validate write
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return jsonify({'error': 'Upload failed: no data saved'}), 400
    
    is_auto_revoke = get_user_setting(current_user.id, 'auto_revoke') == 'true'
    upload_time = datetime.utcnow()
    expiry_delta = timedelta(hours=1) if is_auto_revoke else timedelta(days=7)
    expiry_time = upload_time + expiry_delta
    
    base_url = PUBLIC_BASE_URL if PUBLIC_BASE_URL else f"{request.scheme}://{request.host}"
    share_url = f"{base_url}/download/{filename}"
    
    new_share = Share(
        filename=filename,
        original_name=original_name,
        mime_type=mime_type,
        upload_time=upload_time,
        expiry_time=expiry_time,
        public_url=share_url,
        user_id=current_user.id,
        version=2
    )
    db.session.add(new_share)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'redirect': url_for('dashboard'),
        'public_url': share_url,
        'share': {
            'original_name': serialize_share(new_share, is_ghost=get_user_setting(current_user.id, 'ghost_mode') == 'true')['original_name'],
            'public_url': share_url,
            'download_count': 0,
            'upload_time': upload_time.isoformat() + 'Z',
            'expiry_time': expiry_time.isoformat() + 'Z',
            'last_accessed_at': None
        }
    })

@app.route('/api/v2/get/<filename>')
def get_file_v2(filename):
    """Serve the complete encrypted Blob (V2 architecture)."""
    share = Share.query.filter_by(filename=filename).first()
    if not share:
        return "File not found", 404
    
    # Enforce expiry
    if share.expiry_time and datetime.utcnow() > share.expiry_time:
        return "File expired", 410

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        app.logger.warning(f"[get_file_v2] Physical file missing for share id={share.id} filename={filename}")
        return "File is no longer available", 410
    
    # LOG ASYNC METRICS
    metrics_batcher.log_download(share.id, filename)
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 
        filename, 
        as_attachment=True, 
        download_name=share.original_name
    )

# --- STARTUP ---

# Start background cleanup unconditionally so it runs under both
# local development (python app.py) and Gunicorn (gunicorn app:app).
cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f" * System Active on Port: {port} (Enterprise Mode)")
    app.run(host='0.0.0.0', port=port)
