# Deployment Guide — Obsidian Secure

This document provides deployment guidelines for Obsidian Secure, covering local setups, production parameters, and database performance configurations.

---

## Local Development

### Installation Steps

1. **Verify Python Installation**:
   Ensure Python 3.11+ is installed:
   ```bash
   python --version
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize Local Database**:
   Run the application:
   ```bash
   python app.py
   ```
   The application will automatically detect that no local database exists and create `qr_app.db` with all schemas initialized.

---

## Environment Variables

The application reads configurations from the system environment. For local development, copy `.env.example` to `.env` and adjust variables.

| Variable | Type | Default | Required in Production | Description |
| :--- | :--- | :--- | :--- | :--- |
| `SECRET_KEY` | String | *Random token* | **Yes** | Key used to sign Flask session cookies. Must remain static. |
| `DATABASE_URL` | String | `sqlite:///qr_app.db` | **Yes** | Database connection URI (e.g. `postgresql://...`). |
| `RENDER` | String | `false` | **Yes** (set to `"1"`) | Toggles production security parameters (HSTS, secure cookies). |
| `PUBLIC_BASE_URL` | String | *Derived from request* | **Yes** | Canonical URL of the service (`https://obsidian-secure-ootw.onrender.com`). |
| `PERSISTENT_DISK_PATH` | String | *Project root* | Optional | Mount path for storing uploaded files on persistent storage. |

---

## SQLite WAL Configuration

For local development or single-node deployments using SQLite, the application configures performance and concurrency settings inside the connect hook:

1. **PRAGMA journal_mode=WAL**:
   Enables Write-Ahead Logging. This allows concurrent readers to access the database without being blocked by active write transactions, improving response times.
2. **PRAGMA synchronous=NORMAL**:
   Reduces synchronization overhead, allowing SQLite to run faster.
3. **PRAGMA busy_timeout=30000**:
   Sets the database busy timeout to 30 seconds. If the database is locked, connection operations will wait up to 30 seconds for the lock to clear rather than failing immediately.

These parameters are registered via SQLAlchemy's connection listener:
```python
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
```

---

## Render Deployment

Obsidian Secure includes a `render.yaml` configuration to set up a production stack automatically.

### Persistent Disk Setup
Because Render containers use ephemeral filesystems, files uploaded directly to the container will be deleted on redeployments or container restarts.
- **Disk Mount**: Render provisions a Persistent Disk (`obsidian-data`, 10 GB size) mounted at `/var/lib/obsidian/data`.
- **Mapping**: The app reads `PERSISTENT_DISK_PATH` and sets the file storage path (`UPLOAD_FOLDER`) inside this persistent volume.

---

## Troubleshooting

### 1. `sqlite3.OperationalError: database is locked`
- **Cause**: SQLite only supports one concurrent writer. If background threads (e.g. `background_cleanup`) or registration handlers hold a transaction open without closing it, subsequent writes will block.
- **Remedy**:
  - Ensure all threads close their sessions using `db.session.remove()`.
  - Confirm the SQLAlchemy connect listener executes `PRAGMA busy_timeout=30000;`.
  - Check that CPU-heavy actions (like password hashing) are executed before database transactions.

### 2. Missing Environment Variables / Session Invalidations
- **Issue**: Users get logged out or see `500 Internal Server Error` when the app restarts.
- **Cause**: If `SECRET_KEY` is not set explicitly in the environment, the app generates a random token at startup. Every restart regenerates this token, rendering existing session cookies invalid.
- **Remedy**: Set a static, high-entropy `SECRET_KEY` in the production environment settings.

---

## Production Recommendations

- **Transition to PostgreSQL**: For multi-user environments or multi-node scaling, configure `DATABASE_URL` to point to a PostgreSQL instance. This provides true concurrent write capabilities that SQLite cannot support.
- **Set Up SSL/TLS**: Ensure the application is accessed exclusively over HTTPS.
- **Configure Session Lifetime**: Maintain default permanent session limits to minimize stale sessions.
