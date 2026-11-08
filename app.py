import os
import sys
import re
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
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy import text

# Enterprise Models
from models import (
    db, User, Share, Transfer, UserSetting, Cipher, LoginAttempt, RegistrationAttempt,
    ShareCollection, CollectionFile, CollectionTransfer, CollectionDownloadToken
)

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
        except Exception as e:
            # FAIL-CLOSED REQUIREMENT: In production, never silently fall back to ephemeral
            # container storage if persistent disk is unattached or unwritable.
            raise RuntimeError(
                f"FATAL: Production persistent storage at '{DATA_DIR}' is unavailable or unwritable: {e}. "
                "Failing closed to prevent data loss in ephemeral container storage."
            )

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

    # Engine options for database concurrency & lock prevention (SQLite & PostgreSQL)
    if 'sqlite' in DATABASE_URI.lower():
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'connect_args': {'timeout': 30, 'check_same_thread': False},
            'pool_pre_ping': True
        }
    else:
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_size': 10,
            'max_overflow': 20
        }

    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

    # Ensure storage path exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        try:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        except Exception as e:
            if os.environ.get('RENDER'):
                raise RuntimeError(f"FATAL: Failed to create upload folder at '{app.config['UPLOAD_FOLDER']}': {e}")

    # --- REVERSE PROXY SAFETY ---
    # Trust 1 level of proxy headers (standard for Render / Cloudflare / Nginx).
    # This ensures request.remote_addr resolves to the real client IP,
    # not the proxy's IP, which would cause global login rate-limit lockouts.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Initialize DB & Login
    db.init_app(app)

    # SQLite WAL & synchronous NORMAL configuration
    from sqlalchemy.engine import Engine
    from sqlalchemy import event

    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        if 'sqlite' in app.config.get('SQLALCHEMY_DATABASE_URI', '').lower():
            import sqlite3
            if isinstance(dbapi_connection, sqlite3.Connection):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("PRAGMA synchronous=NORMAL;")
                cursor.execute("PRAGMA busy_timeout=30000;")
                cursor.close()

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login_page'

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

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
        "img-src 'self' data: blob:; "
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

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
        try:
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
        except Exception:
            try:
                delattr(g, '_login_user')
            except Exception:
                pass

@app.teardown_request
def shutdown_session(exception=None):
    if not app.testing:
        db.session.remove()

# --- AUTH ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    ip = request.remote_addr
    error = request.args.get('error')
    if error and error not in ['RATE_LIMIT_EXCEEDED', 'ACCESS_DENIED', 'CSRF_VALIDATION_FAILED']:
        app.logger.error(f"Unknown login error code: {error}")
        error = None

    # Rate Limit Check
    attempt = db.session.get(LoginAttempt, ip)
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
        # 1. Perform light validations first (no database hits)
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

        if not validate_csrf():
             time.sleep(1)
             return render_template('register.html', error='CSRF_VALIDATION_FAILED')

        # 2. Check rate limit
        now = datetime.utcnow()
        reg_attempt = db.session.get(RegistrationAttempt, ip)
        if reg_attempt and reg_attempt.attempts > 5 and now <= reg_attempt.last_attempt + timedelta(hours=1):
            return render_template('register.html', error='RATE_LIMIT_EXCEEDED')

        # 3. Check if user already exists
        if User.query.filter_by(username=username).first():
            # Increment and commit rate limiting attempts even on user exists
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
            return render_template('register.html', error='USER_EXISTS')

        # 4. Generate password hash (CPU-intensive operation done before database transaction write lock)
        pwd_hash = generate_password_hash(password)

        # 5. Write to DB and commit both attempts and user creation in a single transaction
        if reg_attempt:
            if now > reg_attempt.last_attempt + timedelta(hours=1):
                reg_attempt.attempts = 1
                reg_attempt.last_attempt = now
            else:
                reg_attempt.attempts += 1
        else:
            reg_attempt = RegistrationAttempt(ip=ip, attempts=1, last_attempt=now)
            db.session.add(reg_attempt)

        new_user = User(
            username=username,
            password_hash=pwd_hash
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

class CrossProcessLock:
    """Backend-specific cross-process mutual exclusion.
    - PostgreSQL: Checks out a dedicated connection and holds session advisory lock 98234120.
      If unlock fails, invalidates connection to prevent leaking a held lock back to the pool.
    - SQLite: Uses a non-blocking OS file lock (.cleanup.lock) via msvcrt (Windows) or fcntl (POSIX).
    """
    LOCK_ID = 98234120

    def __init__(self, is_pg):
        self.is_pg = is_pg
        self.conn = None
        self.has_lock = False
        self.file_fd = None
        self.lock_file_path = None

    def acquire(self):
        if self.is_pg:
            try:
                self.conn = db.engine.connect()
                res = self.conn.execute(
                    text("SELECT pg_try_advisory_lock(:id)"),
                    {"id": self.LOCK_ID}
                ).scalar()
                self.has_lock = bool(res)
                if not self.has_lock:
                    self.conn.close()
                    self.conn = None
            except Exception as e:
                app.logger.warning(f"[cleanup] PostgreSQL advisory lock acquisition failed: {e}")
                self.has_lock = False
                if self.conn:
                    try:
                        self.conn.close()
                    except Exception:
                        pass
                    self.conn = None
            return self.has_lock
        else:
            upload_dir = app.config.get('UPLOAD_FOLDER', 'data')
            os.makedirs(upload_dir, exist_ok=True)
            self.lock_file_path = os.path.join(upload_dir, '.cleanup.lock')
            try:
                self.file_fd = os.open(self.lock_file_path, os.O_CREAT | os.O_RDWR)
                if sys.platform == 'win32':
                    import msvcrt
                    msvcrt.locking(self.file_fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.file_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.has_lock = True
                return True
            except (IOError, OSError):
                if self.file_fd is not None:
                    try:
                        os.close(self.file_fd)
                    except Exception:
                        pass
                    self.file_fd = None
                self.has_lock = False
                return False

    def release(self):
        if self.is_pg:
            if self.conn and self.has_lock:
                try:
                    self.conn.execute(
                        text("SELECT pg_advisory_unlock(:id)"),
                        {"id": self.LOCK_ID}
                    )
                except Exception as e:
                    app.logger.warning(f"[cleanup] PostgreSQL advisory unlock failed: {e}")
                    # Invalidate connection so it is terminated at DB level and not leaked back to pool
                    try:
                        self.conn.invalidate()
                    except Exception:
                        pass
                finally:
                    try:
                        if not self.conn.invalidated:
                            self.conn.close()
                    except Exception:
                        pass
                    self.conn = None
                    self.has_lock = False
        else:
            if self.file_fd is not None and self.has_lock:
                try:
                    if sys.platform == 'win32':
                        import msvcrt
                        os.lseek(self.file_fd, 0, os.SEEK_SET)
                        msvcrt.locking(self.file_fd, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(self.file_fd, fcntl.LOCK_UN)
                    os.close(self.file_fd)
                except Exception:
                    pass
                finally:
                    self.file_fd = None
                    self.has_lock = False


def background_cleanup():
    """Periodic cleanup of expired files and read ciphers. Runs in background.
    Uses SQLAlchemy ORM within a Flask app context so it works transparently
    against both SQLite (development) and PostgreSQL (production).
    Guarantees single-owner execution via CrossProcessLock across workers and engines.
    """
    while True:
        try:
            now = datetime.utcnow()
            expired_filenames = []

            with app.app_context():
                is_pg = 'postgresql' in app.config.get('SQLALCHEMY_DATABASE_URI', '').lower()
                lock = CrossProcessLock(is_pg=is_pg)

                if not lock.acquire():
                    # Another worker owns the cleanup cycle; yield and sleep
                    time.sleep(300)
                    continue

                try:
                    # Step 1: Query and delete expired records in a short write transaction
                    expired_shares = Share.query.filter(Share.expiry_time < now).all()
                    for share in expired_shares:
                        expired_filenames.append(share.filename)
                        db.session.delete(share)  # cascade deletes associated transfers

                    # Clean expired collections or revoked tombstones older than 7-day retention window
                    tombstone_cutoff = now - timedelta(days=7)
                    expired_collections = ShareCollection.query.filter(
                        (ShareCollection.expiry_time < now) |
                        ((ShareCollection.is_revoked == True) & (ShareCollection.created_at < tombstone_cutoff))
                    ).all()
                    for col in expired_collections:
                        for cf in col.files:
                            expired_filenames.append(cf.stored_filename)
                        db.session.delete(col)

                    # Clean unfinalized abandoned collections older than 2 hours
                    abandoned_collections = ShareCollection.query.filter(
                        ShareCollection.is_finalized == False,
                        ShareCollection.created_at < now - timedelta(hours=2)
                    ).all()
                    for col in abandoned_collections:
                        for cf in col.files:
                            expired_filenames.append(cf.stored_filename)
                        db.session.delete(col)

                    # Clean expired collection download tokens
                    CollectionDownloadToken.query.filter(
                        CollectionDownloadToken.expires_at < now
                    ).delete()

                    # Also clean read ciphers older than 24h
                    Cipher.query.filter(
                        Cipher.is_read == True,
                        Cipher.created_at < now - timedelta(hours=24)
                    ).delete()

                    # CLEANUP: Remove old login attempts (older than 7 days) to prevent DB bloat
                    LoginAttempt.query.filter(
                        LoginAttempt.last_attempt < now - timedelta(days=7)
                    ).delete()

                    db.session.commit()
                except Exception as db_err:
                    app.logger.error(f"[cleanup] Error during database record cleanup: {db_err}")
                    db.session.rollback()
                finally:
                    db.session.remove()
                    lock.release()

            # Step 2: Delete expired physical files on disk (done outside active transaction)
            for filename in expired_filenames:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as rm_err:
                        app.logger.warning(f"[cleanup] Failed to delete expired file {filename}: {rm_err}")

            # Step 3: Scan filesystem for candidate orphan files (done outside active transaction)
            candidate_files = []
            if os.path.exists(app.config['UPLOAD_FOLDER']):
                for filename in os.listdir(app.config['UPLOAD_FOLDER']):
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    if os.path.isfile(file_path):
                        # Check if older than 24h
                        try:
                            mtime = os.path.getmtime(file_path)
                            mtime_dt = datetime.utcfromtimestamp(mtime)
                            if now - mtime_dt > timedelta(hours=24):
                                candidate_files.append(filename)
                        except Exception:
                            pass

            # Step 4: Verify existing filenames in DB using batch SELECT query (done outside write transaction)
            if candidate_files:
                existing_filenames = set()
                with app.app_context():
                    # Process in chunks of 500 to avoid SQL IN limits
                    chunk_size = 500
                    for i in range(0, len(candidate_files), chunk_size):
                        chunk = candidate_files[i:i+chunk_size]
                        shares = Share.query.filter(Share.filename.in_(chunk)).all()
                        for s in shares:
                            existing_filenames.add(s.filename)
                        col_files = CollectionFile.query.filter(CollectionFile.stored_filename.in_(chunk)).all()
                        for cf in col_files:
                            existing_filenames.add(cf.stored_filename)

                # Step 5: Remove orphan files from the filesystem
                for filename in candidate_files:
                    if filename not in existing_filenames:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        try:
                            os.remove(file_path)
                        except Exception as rm_err:
                            app.logger.warning(f"[cleanup] Failed to delete orphan file {filename}: {rm_err}")

            # Clean up session to return connection to pool while sleeping
            try:
                with app.app_context():
                    db.session.remove()
            except Exception:
                pass

            # Run every 5 minutes
            time.sleep(300)
        except Exception as e:
            try:
                with app.app_context():
                    db.session.rollback()
                    db.session.remove()
            except Exception:
                pass
            # If DB is locked or unavailable, wait a bit and retry
            time.sleep(30)


# --- ATOMIC ACCESS COUNTER LOGGING ---

def increment_download_count(share_id, filename):
    """Atomically increments the download counter and logs transfer record.
    Executes synchronously to ensure multi-worker Gunicorn safety and instant DB persistence.
    """
    try:
        with app.app_context():
            Share.query.filter_by(id=share_id).update(
                {Share.download_count: Share.download_count + 1},
                synchronize_session=False
            )
            db.session.add(Transfer(share_id=share_id, timestamp=datetime.utcnow()))
            db.session.commit()
    except Exception as e:
        try:
            with app.app_context():
                db.session.rollback()
        except:
            pass
        app.logger.warning(f"Failed to increment download count for share id={share_id}: {e}")

def increment_collection_download_count(collection_id):
    """Atomically increments the download counter for a collection and logs transfer record.
    Executes synchronously to ensure multi-worker Gunicorn safety and instant DB persistence.
    """
    try:
        with app.app_context():
            ShareCollection.query.filter_by(id=collection_id).update(
                {ShareCollection.download_count: ShareCollection.download_count + 1},
                synchronize_session=False
            )
            db.session.add(CollectionTransfer(collection_id=collection_id, timestamp=datetime.utcnow()))
            db.session.commit()
    except Exception as e:
        try:
            with app.app_context():
                db.session.rollback()
        except:
            pass
        app.logger.warning(f"Failed to increment download count for collection id={collection_id}: {e}")



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


def serialize_share(row, is_ghost=False, is_auto_revoke=False):
    canonical_url = row.public_url.replace('/get/', '/download/')
    latest_transfer = None
    if row.transfers:
        latest_transfer = max((t.timestamp for t in row.transfers if t.timestamp), default=None)

    return {
        'id': row.id,
        'filename': row.filename,
        'original_name': f"Hidden file {row.id}" if is_ghost else row.original_name,
        'mime_type': row.mime_type or 'encrypted file',
        'upload_time': row.upload_time,
        'expiry_time': row.expiry_time,
        'download_count': row.download_count,
        'public_url': canonical_url,
        'last_accessed_at': latest_transfer,
        'is_auto_revoke': is_auto_revoke,
        'is_collection': False
    }

def serialize_collection(row, is_ghost=False, is_auto_revoke=False):
    latest_transfer = None
    if row.transfers:
        latest_transfer = max((t.timestamp for t in row.transfers if t.timestamp), default=None)

    display_name = f"Collection ({row.file_count} files)"
    if is_ghost:
        display_name = f"Hidden Collection {row.id} ({row.file_count} files)"

    return {
        'id': row.id,
        'filename': f"collection_{row.public_id}.zip",
        'original_name': display_name,
        'mime_type': f'application/zip ({row.file_count} files)',
        'upload_time': row.created_at,
        'expiry_time': row.expiry_time,
        'download_count': row.download_count,
        'public_url': row.public_url,
        'last_accessed_at': latest_transfer,
        'is_auto_revoke': is_auto_revoke,
        'is_collection': True,
        'file_count': row.file_count,
        'total_size': row.total_size
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
    base_url = PUBLIC_BASE_URL if PUBLIC_BASE_URL else f"{request.scheme}://{request.host}"
    try:
        # DATA ISOLATION: Only show notifications if logged in
        if not current_user.is_authenticated:
            return dict(notifications=[], now=datetime.utcnow, public_base_url=base_url)

        is_ghost = get_user_setting(current_user.id, 'ghost_mode') == 'true'

        raw_notifications = Share.query.filter(Share.download_count > 0).order_by(Share.id.desc()).limit(5).all()
        notifications = []
        for n in raw_notifications:
            name = "HIDDEN_PAYLOAD.enc" if is_ghost else n.original_name
            notifications.append({'original_name': name, 'download_count': n.download_count})

        return dict(
            notifications=notifications,
            now=datetime.utcnow,
            public_base_url=base_url
        )
    except:
        return dict(notifications=[], now=datetime.utcnow, public_base_url=base_url)

# --- ROUTES ---

@app.route('/robots.txt')
def robots_txt():
    base_url = PUBLIC_BASE_URL if PUBLIC_BASE_URL else f"{request.scheme}://{request.host}"
    content = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /dashboard\n"
        "Disallow: /active-shares\n"
        "Disallow: /shared\n"
        "Disallow: /cipher\n"
        "Disallow: /settings\n"
        "Disallow: /security\n"
        "Disallow: /api/\n"
        "Disallow: /upload\n"
        "Disallow: /revoke\n"
        "Disallow: /get/\n"
        "Disallow: /collection/\n"
        "\n"
        f"Sitemap: {base_url}/sitemap.xml\n"
    )
    return app.response_class(content, mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap_xml():
    base_url = PUBLIC_BASE_URL if PUBLIC_BASE_URL else f"{request.scheme}://{request.host}"
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        '  <url>\n'
        f'    <loc>{base_url}/</loc>\n'
        '    <changefreq>weekly</changefreq>\n'
        '    <priority>1.0</priority>\n'
        '  </url>\n'
        '  <url>\n'
        f'    <loc>{base_url}/privacy</loc>\n'
        '    <changefreq>monthly</changefreq>\n'
        '    <priority>0.5</priority>\n'
        '  </url>\n'
        '</urlset>'
    )
    return app.response_class(content, mimetype='application/xml')

@app.route('/googlee5ae4db6815276ae.html')
def google_verification():
    return app.response_class('google-site-verification: googlee5ae4db6815276ae.html', mimetype='text/html')

@app.route('/health', methods=['GET'])
@app.route('/health/live', methods=['GET'])
def health_liveness():
    """Production liveness probe for reverse proxy and load balancer monitoring.
    Returns HTTP 200 immediately if the WSGI worker process is responsive, without hitting the database.
    """
    return jsonify({
        'status': 'healthy',
        'type': 'liveness',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 200

@app.route('/health/ready', methods=['GET'])
def health_readiness():
    """Production readiness probe verifying database connectivity.
    Executes a minimal SELECT 1 check. If the database is unreachable, returns HTTP 503
    without exposing database credentials, hostnames, or internal stack traces.
    """
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify({
            'status': 'ready',
            'type': 'readiness',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 200
    except Exception as e:
        app.logger.error(f"[health] Database readiness check failed: {e}")
        return jsonify({
            'status': 'unready',
            'type': 'readiness',
            'database': 'unavailable',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 503
    finally:
        db.session.remove()

@app.route('/')
def home_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing_page.html')

@app.route('/privacy')
def privacy_page():
    return render_template('privacy.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/dashboard')
@login_required
def dashboard():
    public_url = session.pop('success_public_url', None)
    message = session.pop('success_message', None)
    return render_template('dashboard.html', current_page='files',
                           public_url=public_url, message=message)

@app.route('/active-shares')
@app.route('/shared')
@login_required
def active_shares_page():
    is_ghost = get_user_setting(current_user.id, 'ghost_mode') == 'true'
    is_auto = get_user_setting(current_user.id, 'auto_revoke') == 'true'
    shares = Share.query.filter_by(user_id=current_user.id).order_by(Share.upload_time.desc()).all()
    collections = ShareCollection.query.filter_by(
        user_id=current_user.id, is_finalized=True, is_revoked=False
    ).order_by(ShareCollection.created_at.desc()).all()

    shares_list = [serialize_share(row, is_ghost=is_ghost, is_auto_revoke=is_auto) for row in shares]
    collections_list = [serialize_collection(row, is_ghost=is_ghost, is_auto_revoke=is_auto) for row in collections]
    all_shares = sorted(shares_list + collections_list, key=lambda s: s['upload_time'] or datetime.min, reverse=True)
    return render_template('active_shares.html', current_page='active_shares', shares=all_shares)

shared_page = active_shares_page

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

@app.route('/decrypt/<public_id>', methods=['GET'])
def decrypt_cipher(public_id):
    """Renders the Burn-On-Read message landing page.
    SECURITY INVARIANT:
    Does NOT deliver ciphertext or plaintext in response to ordinary GET requests.
    Prevents link preview scrapers, social media crawlers, and browser prefetchers
    from inadvertently reading or destroying the message.
    """
    cipher = Cipher.query.filter_by(public_id=public_id).first()
    now = datetime.utcnow()
    is_unavailable = (
        not cipher or
        cipher.is_read or
        (cipher.burn_on_read and not cipher.content) or
        (cipher.created_at and now > cipher.created_at + timedelta(hours=24))
    )
    if is_unavailable:
        return render_template('cipher_read.html', expired=True, public_id=public_id, alias=None)

    alias = cipher.sender_alias if cipher.sender_alias else 'Obsidian Secure'
    return render_template('cipher_read.html', expired=False, public_id=public_id, alias=alias)


@app.route('/api/cipher/consume/<public_id>', methods=['POST'])
def consume_cipher(public_id):
    """Recipient-initiated atomic consumption endpoint.
    ATOMICITY GUARANTEE:
    Executes a single atomic database statement that claims the cipher (`is_read = True`),
    erases the stored ciphertext (`content = ''`), and validates 24-hour expiry eligibility
    within a single committed database transaction.
    Exactly one concurrent request obtains rowcount == 1 and receives the ciphertext.
    Losing, expired, or repeated requests receive HTTP 410 Gone with zero ciphertext.
    """
    if not validate_csrf():
        return jsonify({'error': 'CSRF validation failed'}), 403

    try:
        # 1. Read existing record within the active transaction to retrieve payload before mutation
        cipher = Cipher.query.filter_by(public_id=public_id).first()
        if not cipher:
            return jsonify({'error': 'Message not found'}), 404

        now = datetime.utcnow()
        min_created = now - timedelta(hours=24)

        # Fast rejection if already read, empty, or expired
        if cipher.is_read or (cipher.burn_on_read and not cipher.content) or (cipher.created_at and cipher.created_at < min_created):
            return jsonify({'error': 'Message already read or unavailable'}), 410

        ciphertext = cipher.content
        sender_alias = cipher.sender_alias if cipher.sender_alias else 'Obsidian Secure'

        if cipher.burn_on_read:
            # Atomic conditional claim, erasure, and expiry enforcement in a single statement
            stmt = (
                db.update(Cipher)
                .where(
                    Cipher.public_id == public_id,
                    Cipher.is_read == False,
                    (Cipher.created_at == None) | (Cipher.created_at >= min_created)
                )
                .values(is_read=True, content='')
            )
            result = db.session.execute(stmt)

            if result.rowcount != 1:
                # Race lost or message expired between initial check and claim
                db.session.rollback()
                return jsonify({'error': 'Message already read or unavailable'}), 410

            # Exactly one database commit for the combined claim and erasure
            db.session.commit()
        else:
            stmt = (
                db.update(Cipher)
                .where(
                    Cipher.public_id == public_id,
                    (Cipher.created_at == None) | (Cipher.created_at >= min_created)
                )
                .values(is_read=True)
            )
            result = db.session.execute(stmt)
            if result.rowcount == 0:
                db.session.rollback()
                return jsonify({'error': 'Message expired or unavailable'}), 410
            db.session.commit()

        return jsonify({
            'status': 'success',
            'ciphertext': ciphertext,
            'sender_alias': sender_alias
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error consuming cipher {public_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/cipher/confirm_read/<public_id>', methods=['POST'])
def confirm_cipher_read(public_id):
    """Legacy confirmation endpoint kept for backward compatibility."""
    row = Cipher.query.filter_by(public_id=public_id, is_read=False).first()
    if row and row.burn_on_read:
        row.is_read = True
        row.content = ''
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

    # LOG ATOMIC METRICS
    increment_download_count(share.id, filename)

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
        share = Share.query.filter(
            (Share.public_url == share_url) |
            (Share.public_url == share_url.replace('/download/', '/get/')) |
            (Share.public_url == share_url.replace('/get/', '/download/'))
        ).first()
        if share and (share.user_id == current_user.id):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], share.filename)
            if os.path.exists(file_path):
                try: os.remove(file_path)
                except: pass
            db.session.delete(share)
            db.session.commit()
            return redirect(request.referrer or url_for('active_shares_page'))

        # Security: Check ShareCollection ownership and revoke
        collection = ShareCollection.query.filter_by(public_url=share_url).first()
        if not collection and '/collection/' in share_url:
            public_id = share_url.split('/collection/')[-1].split('?')[0].split('#')[0]
            collection = ShareCollection.query.filter_by(public_id=public_id).first()

        if collection and (collection.user_id == current_user.id):
            if not collection.is_revoked:
                # Remove all physical encrypted files and file records immediately
                for cf in list(collection.files):
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], cf.stored_filename)
                    if os.path.exists(file_path):
                        try: os.remove(file_path)
                        except Exception: pass
                    db.session.delete(cf)

                # Maintain collection record as a minimal tombstone (preserves 410 Revoked state)
                collection.is_revoked = True
                collection.file_count = 0
                collection.total_size = 0
                db.session.commit()

            return redirect(request.referrer or url_for('active_shares_page'))

    return redirect(request.referrer or url_for('active_shares_page'))

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

    try:
        # Write entire file at once
        with heavy_task_semaphore:
            file_obj.save(file_path)

        # Validate write
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            if os.path.exists(file_path):
                try: os.remove(file_path)
                except Exception: pass
            return jsonify({'error': 'Upload failed: no data saved'}), 400
    except Exception as save_err:
        if os.path.exists(file_path):
            try: os.remove(file_path)
            except Exception: pass
        app.logger.error(f"[upload_file_v2] Disk write failed: {save_err}")
        return jsonify({'error': 'Failed to save file to persistent storage'}), 500

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

    # LOG ATOMIC METRICS
    increment_download_count(share.id, filename)

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=True,
        download_name=share.original_name
    )

# --- MULTI-FILE SECURE SHARING (ZIP-ONLY DOWNLOAD) ---

MAX_COLLECTION_FILES = 10
MAX_COLLECTION_SIZE = 50 * 1024 * 1024  # 50 MB total collection limit (memory-safe for JSZip in mobile browsers)
MAX_SINGLE_FILE_SIZE = 50 * 1024 * 1024 # 50 MB single file limit

@app.route('/api/v2/collection/init', methods=['POST'])
@login_required
def init_collection():
    """Initializes a new multi-file share collection record."""
    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'error': 'CSRF validation failed'}), 403

    data = request.get_json(silent=True) or {}
    try:
        file_count = int(data.get('file_count', 0))
        total_size = int(data.get('total_size', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid collection parameters'}), 400

    if file_count < 1 or file_count > MAX_COLLECTION_FILES:
        return jsonify({'error': f'Collection file count must be between 1 and {MAX_COLLECTION_FILES}'}), 400

    if total_size <= 0 or total_size > MAX_COLLECTION_SIZE:
        return jsonify({'error': f'Total collection size exceeds maximum limit of {MAX_COLLECTION_SIZE // (1024*1024)}MB'}), 400

    public_id = secrets.token_urlsafe(16)
    base_url = PUBLIC_BASE_URL if PUBLIC_BASE_URL else f"{request.scheme}://{request.host}"
    share_url = f"{base_url}/collection/{public_id}"

    is_auto_revoke = get_user_setting(current_user.id, 'auto_revoke') == 'true'
    upload_time = datetime.utcnow()
    expiry_delta = timedelta(hours=1) if is_auto_revoke else timedelta(days=7)
    expiry_time = upload_time + expiry_delta

    new_collection = ShareCollection(
        public_id=public_id,
        user_id=current_user.id,
        created_at=upload_time,
        expiry_time=expiry_time,
        public_url=share_url,
        file_count=file_count,
        total_size=total_size,
        is_finalized=False,
        is_revoked=False
    )
    db.session.add(new_collection)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'public_id': public_id,
        'public_url': share_url
    })


@app.route('/api/v2/collection/<public_id>/file', methods=['POST'])
@login_required
def upload_collection_file(public_id):
    """Uploads a single encrypted file belonging to an initialized collection.
    Enforces aggregate upload limits before writing to disk and guards against concurrency races.
    """
    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'error': 'CSRF validation failed'}), 403

    collection = ShareCollection.query.filter_by(public_id=public_id).first()
    if not collection:
        return jsonify({'error': 'Collection not found'}), 404

    if collection.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    if collection.is_finalized:
        return jsonify({'error': 'Collection is already finalized'}), 400

    if collection.expiry_time and datetime.utcnow() > collection.expiry_time:
        return jsonify({'error': 'Collection expired'}), 410

    if len(collection.files) >= collection.file_count or len(collection.files) >= MAX_COLLECTION_FILES:
        return jsonify({'error': 'Maximum files for collection reached'}), 400

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file_obj = request.files['file']
    if file_obj.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Determine incoming file size prior to disk write
    file_obj.seek(0, os.SEEK_END)
    incoming_size = file_obj.tell()
    file_obj.seek(0)

    if incoming_size <= 0:
        return jsonify({'error': 'Upload failed: no data received'}), 400

    if incoming_size > MAX_SINGLE_FILE_SIZE:
        return jsonify({'error': f'Individual file exceeds size limit of {MAX_SINGLE_FILE_SIZE // (1024*1024)}MB'}), 400

    # Pre-write aggregate limit validation
    current_aggregate_size = db.session.query(
        db.func.coalesce(db.func.sum(CollectionFile.file_size), 0)
    ).filter(CollectionFile.collection_id == collection.id).scalar()

    if current_aggregate_size + incoming_size > MAX_COLLECTION_SIZE:
        return jsonify({'error': f'Total collection size exceeds maximum limit of {MAX_COLLECTION_SIZE // (1024*1024)}MB'}), 400

    original_name_b64 = request.headers.get('X-Original-Name', '')
    try:
        original_name = base64.b64decode(original_name_b64).decode('utf-8', errors='replace')
    except Exception:
        original_name = 'unnamed_file'
    safe_name = secure_filename(original_name) or 'unnamed_file'

    mime_type = request.headers.get('X-Mime-Type', 'application/octet-stream')

    file_id = secrets.token_hex(8)
    stored_filename = f"col_{public_id}_{file_id}_{safe_name}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)

    with heavy_task_semaphore:
        file_obj.save(file_path)

    stored_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
    if stored_size == 0:
        if os.path.exists(file_path):
            try: os.remove(file_path)
            except Exception: pass
        return jsonify({'error': 'Upload failed: no data saved'}), 400

    if stored_size > MAX_SINGLE_FILE_SIZE:
        if os.path.exists(file_path):
            try: os.remove(file_path)
            except Exception: pass
        return jsonify({'error': f'Individual file exceeds size limit of {MAX_SINGLE_FILE_SIZE // (1024*1024)}MB'}), 400

    col_file = CollectionFile(
        collection_id=collection.id,
        file_id=file_id,
        stored_filename=stored_filename,
        original_name=original_name,
        file_size=stored_size,
        mime_type=mime_type,
        created_at=datetime.utcnow()
    )
    db.session.add(col_file)
    db.session.flush()

    # Post-flush aggregate limit verification (atomic concurrency protection)
    verified_total = db.session.query(
        db.func.coalesce(db.func.sum(CollectionFile.file_size), 0)
    ).filter(CollectionFile.collection_id == collection.id).scalar()

    if verified_total > MAX_COLLECTION_SIZE:
        db.session.rollback()
        if os.path.exists(file_path):
            try: os.remove(file_path)
            except Exception: pass
        return jsonify({'error': f'Total collection size exceeds maximum limit of {MAX_COLLECTION_SIZE // (1024*1024)}MB'}), 400

    db.session.commit()

    return jsonify({
        'status': 'success',
        'file_id': file_id,
        'uploaded_files': len(collection.files)
    })


@app.route('/api/v2/collection/<public_id>/finalize', methods=['POST'])
@login_required
def finalize_collection(public_id):
    """Finalizes an initialized collection once all files are uploaded."""
    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'error': 'CSRF validation failed'}), 403

    collection = ShareCollection.query.filter_by(public_id=public_id).first()
    if not collection:
        return jsonify({'error': 'Collection not found'}), 404

    if collection.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    if collection.is_finalized:
        return jsonify({'error': 'Collection already finalized'}), 400

    if not collection.files:
        return jsonify({'error': 'Cannot finalize empty collection'}), 400

    actual_size = sum(f.file_size for f in collection.files)
    if actual_size > MAX_COLLECTION_SIZE:
        return jsonify({'error': 'Total collection size exceeds maximum limit'}), 400

    collection.total_size = actual_size
    collection.file_count = len(collection.files)
    collection.is_finalized = True
    db.session.commit()

    is_ghost = get_user_setting(current_user.id, 'ghost_mode') == 'true'
    serialized = serialize_collection(
        collection,
        is_ghost=is_ghost,
        is_auto_revoke=get_user_setting(current_user.id, 'auto_revoke') == 'true'
    )

    return jsonify({
        'status': 'success',
        'public_url': collection.public_url,
        'share': serialized
    })


@app.route('/api/v2/collection/<public_id>/abort', methods=['POST'])
@login_required
def abort_collection(public_id):
    """Aborts an unfinalized collection and removes partial uploads."""
    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'error': 'CSRF validation failed'}), 403

    collection = ShareCollection.query.filter_by(public_id=public_id).first()
    if collection and collection.user_id == current_user.id and not collection.is_finalized:
        for cf in collection.files:
            fp = os.path.join(app.config['UPLOAD_FOLDER'], cf.stored_filename)
            if os.path.exists(fp):
                try: os.remove(fp)
                except: pass
        db.session.delete(collection)
        db.session.commit()

    return jsonify({'status': 'aborted'})


@app.route('/collection/<public_id>')
def collection_landing_page(public_id):
    """Collection recipient landing page (ZIP download only)."""
    collection = ShareCollection.query.filter_by(public_id=public_id).first()
    if not collection or not collection.is_finalized:
        return render_template('collection_landing.html', not_found=True, expired=False, revoked=False, file_unavailable=False), 404

    if collection.is_revoked:
        return render_template('collection_landing.html', not_found=False, expired=False, revoked=True, file_unavailable=False), 410

    if collection.expiry_time and datetime.utcnow() > collection.expiry_time:
        return render_template('collection_landing.html', not_found=False, expired=True, revoked=False, file_unavailable=False), 410

    # Check physical file availability
    all_files_exist = all(
        os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], cf.stored_filename))
        for cf in collection.files
    )
    if not all_files_exist:
        app.logger.warning(f"[collection_landing] One or more physical files missing for collection public_id={public_id}")
        return render_template('collection_landing.html', not_found=False, expired=False, revoked=False, file_unavailable=True), 410

    is_ghost = False
    alias = 'OBSIDIAN_NODE'
    try:
        if collection.user_id:
            is_ghost = get_user_setting(collection.user_id, 'ghost_mode') == 'true'
            alias = get_user_setting(collection.user_id, 'alias', 'OBSIDIAN_NODE')
    except Exception:
        pass

    files_meta = [{
        'file_id': cf.file_id,
        'original_name': f"Hidden file {cf.id}" if is_ghost else cf.original_name,
        'file_size': cf.file_size,
        'mime_type': cf.mime_type or 'application/octet-stream'
    } for cf in collection.files]

    return render_template(
        'collection_landing.html',
        collection=collection,
        files=files_meta,
        alias=alias,
        not_found=False,
        expired=False,
        revoked=False,
        file_unavailable=False
    )


@app.route('/api/v2/collection/<public_id>/manifest')
def get_collection_manifest(public_id):
    """Returns collection metadata and file inventory for browser-side decryption & ZIP assembly."""
    collection = ShareCollection.query.filter_by(public_id=public_id).first()
    if not collection or not collection.is_finalized:
        return jsonify({'error': 'Collection not found'}), 404

    if collection.is_revoked:
        return jsonify({'error': 'Collection revoked'}), 410

    if collection.expiry_time and datetime.utcnow() > collection.expiry_time:
        return jsonify({'error': 'Collection expired'}), 410

    is_ghost = False
    try:
        if collection.user_id:
            is_ghost = get_user_setting(collection.user_id, 'ghost_mode') == 'true'
    except Exception:
        pass

    files_meta = [{
        'file_id': cf.file_id,
        'original_name': f"Hidden file {cf.id}" if is_ghost else cf.original_name,
        'file_size': cf.file_size,
        'mime_type': cf.mime_type or 'application/octet-stream'
    } for cf in collection.files]

    # Issue single-use, short-lived acknowledgement token for download metric protection
    ack_token = secrets.token_urlsafe(32)
    download_token_record = CollectionDownloadToken(
        collection_id=collection.id,
        token=ack_token,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=15),
        is_used=False
    )
    db.session.add(download_token_record)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'public_id': collection.public_id,
        'file_count': collection.file_count,
        'total_size': collection.total_size,
        'expiry_time': collection.expiry_time.isoformat() + 'Z',
        'download_token': ack_token,
        'files': files_meta
    })


@app.route('/api/v2/collection/<public_id>/file/<file_id>')
def get_collection_file(public_id, file_id):
    """Serves an encrypted file blob belonging to a collection."""
    collection = ShareCollection.query.filter_by(public_id=public_id).first()
    if not collection or not collection.is_finalized:
        return "Collection not found", 404

    if collection.is_revoked:
        return "Collection revoked", 410

    if collection.expiry_time and datetime.utcnow() > collection.expiry_time:
        return "Collection expired", 410

    col_file = CollectionFile.query.filter_by(collection_id=collection.id, file_id=file_id).first()
    if not col_file:
        return "File not found in collection", 404

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], col_file.stored_filename)
    if not os.path.exists(file_path):
        app.logger.warning(f"[get_collection_file] Physical file missing for collection public_id={public_id} file_id={file_id}")
        return "File is no longer available", 410

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        col_file.stored_filename,
        as_attachment=True,
        download_name=col_file.stored_filename
    )


@app.route('/api/v2/collection/<public_id>/record_download', methods=['POST'])
def record_collection_download(public_id):
    """Atomically records recipient download completion for the entire ZIP collection.
    Requires a valid, unexpired, single-use acknowledgement token issued during manifest retrieval.
    """
    collection = ShareCollection.query.filter_by(public_id=public_id).first()
    if not collection or not collection.is_finalized:
        return jsonify({'error': 'Collection not found'}), 404

    if collection.is_revoked:
        return jsonify({'error': 'Collection revoked'}), 410

    if collection.expiry_time and datetime.utcnow() > collection.expiry_time:
        return jsonify({'error': 'Collection expired'}), 410

    data = request.get_json(silent=True) or {}
    token = data.get('token')
    if not token or not isinstance(token, str):
        return jsonify({'error': 'Missing or invalid download acknowledgement token'}), 400

    token_record = CollectionDownloadToken.query.filter_by(
        token=token, collection_id=collection.id
    ).first()

    if not token_record:
        return jsonify({'error': 'Invalid download acknowledgement token'}), 400

    if token_record.is_used:
        return jsonify({'error': 'Download acknowledgement token already used'}), 409

    if datetime.utcnow() > token_record.expires_at:
        return jsonify({'error': 'Download acknowledgement token expired'}), 410

    # Mark token used atomically and commit
    token_record.is_used = True
    db.session.commit()

    increment_collection_download_count(collection.id)
    return jsonify({'status': 'success'})

# --- STARTUP ---

# Start background cleanup unconditionally so it runs under both
# local development (python app.py) and Gunicorn (gunicorn app:app).
cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f" * System Active on Port: {port} (Enterprise Mode)")
    app.run(host='0.0.0.0', port=port)
