# Release Notes — Obsidian Secure v1.0.0

We are proud to present **Obsidian Secure v1.0.0**, the initial production-ready release of our zero-knowledge file and message-sharing platform. This release marks the completion of our stabilization pass, security hardening pass, and open-source readiness pass.

---

## Core Features

- **Client-Side File Encryption (AES-GCM)**: All files are encrypted chunk-by-chunk in the browser before transmission, preserving file integrity and confidentiality.
- **Client-Side Message Encryption (AES-GCM)**: Ephemeral messages and text can be encrypted client-side and shared via URL.
- **Burn-after-Read Messaging**: Cipher messages can be set to be read exactly once. Upon confirmation, the ciphertext is permanently disabled from access on the database.
- **Automatic Expiration**: Uploaded file links expire automatically (default: 1 hour for auto-revoke shares, 7 days for standard shares).
- **Periodic Background Cleanup**: The server runs a background cleanup thread to delete expired files from disk and the database, preventing storage bloating and ensuring security hygiene.
- **Dynamic CSS Design System**: Responsive glassmorphic UI utilizing custom HSL color palettes and micro-animations.
- **Administrative Settings Panel**: Seeded global settings allowing administrators to adjust system aliases, enforce auto-revocation, or toggle ghost mode.
- **Asynchronous Metrics Logging**: Thread-safe batching system (`MetricsBatcher`) to queue database writes for downloads, improving response latency.

---

## Security Model & Cryptography

Obsidian Secure operates on a strict **Zero-Knowledge Model**:
- **Zero Key Knowledge**: The host server never sees, stores, or handles the decryption keys. Keys are appended as URL fragment identifiers (`#key`) which remain strictly client-side.
- **Rate-Limiting Hardening**: Login attempts are rate-limited to 5 failed attempts per 15 minutes per IP address. Registration is rate-limited to 5 attempts per hour per IP.
- **Session Protection**: HttpOnly, SameSite (Lax), and Secure session cookies.
- **CSP Hardening**: A strict Content Security Policy (`default-src 'self'`) is enforced on all HTTP responses, blocking external script execution or third-party asset loading.
- **CSRF Protection**: Standard anti-forgery tokens are validated across all state-changing endpoints (Upload, Settings, Logins).
- **Directory Traversal Mitigation**: Safe filename checking via `secure_filename()` combined with explicit path containment checks prevents local file extraction.

---

## Technical Architecture

Obsidian Secure is structured as a modern lightweight Flask-SQLAlchemy application:
- **Backend Framework**: Flask 3.0.3, SQLAlchemy 2.0.38 (supporting SQLite for development and PostgreSQL for production).
- **Asynchronous IO**: Multi-threaded request serving using Gunicorn (production WSGI server).
- **Frontend Core**: Semantic HTML5, customized Vanilla CSS3 variables, and vanilla JavaScript.
- **Dependencies**: Streamlined production footprint (Flask, Flask-SQLAlchemy, Flask-Login, psycopg2-binary, gunicorn, werkzeug).

---

## Known Limitations

- **Browser Memory Boundaries**: Files larger than 2GB may crash browser tabs during encryption/decryption due to JavaScript heap size limits.
- **Mobile Device Downloading**: Constrained mobile RAM may fail to save large decrypted file blobs (typically files > 1GB).
- **In-App URL Fragment Stripping**: In-app browsers (e.g. inside Facebook, WeChat) may strip the `#key` fragment from URLs when clicked, preventing decryption. Recipient users must open links in standard external browsers.
- **Camera Focus dependency**: Scanning generated QR codes on older mobile devices may be constrained by low camera hardware quality or focus delays.

---

## Deployment Notes

Obsidian Secure is designed to run easily in containerized or cloud PaaS environments:
- **Render Deployment**: Ready-to-use infrastructure definition is supplied via `render.yaml`. Includes persistent disk storage for files and database configuration.
- **WSGI Runner**: Production server utilizes Gunicorn via the configured `Procfile`. Waitress has been deprecated.
- **Bootstrap Command**: The application provides `create_admin.py` to provision administrative users on first-time deployment.
