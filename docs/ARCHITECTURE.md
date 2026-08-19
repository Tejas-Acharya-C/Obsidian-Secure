# Obsidian Secure — Architecture Specification

This document provides a detailed specification of the technical architecture, sequence flows, database models, security designs, asset pipelines, and deployment models for Obsidian Secure.

---

## System Overview

Obsidian Secure is designed around a strictly decoupled zero-knowledge model. The frontend browser context acts as the trusted execution environment for all cryptographic operations, while the backend server acts as an untrusted metadata indexer and storage relay.

```mermaid
graph TD
    User([User Browser])
    Proxy[Proxy Fix / WSGI Gunicorn]
    App[Flask Core App]
    Db[(SQLite / PostgreSQL Database)]
    Disk[(Persistent Disk / Local Storage)]

    User -- "1. AES-GCM Encrypted Payloads" --> Proxy
    Proxy --> App
    App -- "2. Metadata & Rate Limits" --> Db
    App -- "3. Encrypted Blobs" --> Disk
```

---

## Application Structure & View Separation

The application enforces a structural separation between file creation, active share management, secure messaging, settings, and public recipient flows:

```text
/                      -> Public Brand Homepage (landing.html)
/dashboard             -> Secure Share Creation Workflow (dashboard.html, current_page='files')
/active-shares         -> Dedicated Active Shares Ledger (active_shares.html, current_page='active_shares')
/shared                -> Alias route pointing to /active-shares
/cipher                -> Secure Message Cipher Creation (dashboard.html, current_page='cipher')
/settings              -> User Preferences & Key-Value Config (dashboard.html, current_page='settings')
/security              -> Security Standards Documentation (dashboard.html, current_page='security')
/download/<filename>   -> Recipient File Download Landing (landing_page.html)
/decrypt/<public_id>   -> Recipient Message Decryption View (cipher_read.html)
```

---

## Authentication Flow

Authentication is managed server-side using Werkzeug PBKDF2 security hashes. Endpoints are protected by rate-limiting counters mapped against incoming IP addresses.

```mermaid
sequenceDiagram
    autonumber
    actor User as Client Browser
    participant App as Flask Backend
    participant Db as Database

    User->>App: POST /login {username, password, csrf_token}
    Note over App: 1. Validate CSRF token
    Note over App: 2. Query LoginAttempt rate limit
    App->>Db: SELECT * FROM login_attempt WHERE ip = ?
    Db-->>App: Return attempts count
    Note over App: 3. Verify attempts < 5
    App->>Db: SELECT * FROM user WHERE username = ?
    Db-->>App: Return user record (password hash)
    Note over App: 4. Verify password hash
    alt Successful Login
        App->>Db: DELETE FROM login_attempt WHERE ip = ?
        App->>User: Set HttpOnly Session Cookie (302 Redirect)
    else Invalid Password
        App->>Db: INSERT / UPDATE login_attempt (increment count)
        App->>User: Render login.html with ACCESS_DENIED
    end
```

---

## File Sharing V2 Flow

The V2 File Sharing architecture uses a single-request design that handles encryption entirely in-memory using standard Web Crypto API components.

```mermaid
sequenceDiagram
    autonumber
    actor Sender as Sender (Browser)
    participant Server as Flask Backend
    participant Db as Database
    participant Disk as Storage (Disk)
    actor Recipient as Recipient (Browser)

    Note over Sender: 1. Generate AES-GCM 256-bit Key
    Note over Sender: 2. Read File buffer & encrypt<br/>Payload = [12-byte IV][Ciphertext]
    Sender->>Server: 3. POST /api/v2/upload (multipart form, no key)
    Note over Server: 4. Save encrypted blob
    Server->>Disk: Write filename to shared_files/
    Note over Server: 5. Store metadata
    Server->>Db: INSERT INTO share (filename, original_name, mime_type, version=2)
    Server-->>Sender: 6. Return json { status: "success", public_url }
    Note over Sender: 7. Append key to URL: url#key=BASE64
    Sender->>Recipient: 8. Send share link (with #key fragment)
    Recipient->>Server: 9. GET /download/<filename>
    Server->>Db: SELECT * FROM share WHERE filename = ?
    Db-->>Server: Return metadata
    Server-->>Recipient: 10. Render landing_page.html (Metadata, no key)
    Recipient->>Server: 11. GET /api/v2/get/<filename>
    Server->>Disk: Read encrypted file
    Disk-->>Server: Stream binary
    Server-->>Recipient: 12. Return binary stream
    Note over Recipient: 13. Read #key fragment from location.hash
    Note over Recipient: 14. Decrypt in memory & download file
```

---

## Dedicated Active Shares Architecture

The `/active-shares` ledger is decoupled from the main upload dashboard:
- **Status Classification Rules**:
  - `EXPIRED`: `expiry_time <= current_utc_time`
  - `EXPIRING SOON`: `expiry_time > current_utc_time AND remaining <= 15 minutes`
  - `ACTIVE`: `expiry_time > current_utc_time AND remaining > 15 minutes`
- **Revocation Safety**: Share deletion requests (`POST /revoke`) verify CSRF tokens and user ownership, deleting both DB metadata and disk binary blobs. Decryption keys are never stored or displayed on the Active Shares interface.

---

## Secure Message Flow

Message ciphers are encrypted in the browser, stored as base64 strings, and support optional self-destruction (burn-on-read).

```mermaid
sequenceDiagram
    autonumber
    actor Sender as Sender (Browser)
    participant Server as Flask Backend
    participant Db as Database
    actor Recipient as Recipient (Browser)

    Note over Sender: 1. Encrypt message locally with AES-256-GCM
    Sender->>Server: 2. POST /cipher/create {content, burn_on_read}
    Note over Server: 3. Generate public_id
    Server->>Db: INSERT INTO cipher (content, public_id, burn_on_read, sender_alias)
    Server-->>Sender: 4. Return decrypt URL (with #key fragment)
    Sender->>Recipient: 5. Share decrypt URL
    Recipient->>Server: 6. GET /decrypt/<public_id>
    Server->>Db: SELECT * FROM cipher WHERE public_id = ? AND is_read = False
    Db-->>Server: Return cipher record
    Server-->>Recipient: 7. Render cipher_read.html (encrypted value, no key)
    Note over Recipient: 8. Decrypt message using #key
    alt Burn-on-read Enabled
        Recipient->>Server: 9. POST /api/cipher/confirm_read/<public_id>
        Server->>Db: UPDATE cipher SET is_read = True WHERE public_id = ?
        Server-->>Recipient: Return success
    end
```

---

## Asset Pipeline & Design System Architecture

- **Visual Theme & Backgrounds**:
  - Authenticated Application Pages (`/dashboard`, `/active-shares`, `/cipher`, `/settings`, `/security`): Enforce `body_class = 'app-dashboard-page'` and display `internal-background-pattern.webp` with fixed position dark mineral styling.
  - Public Pages (`/`, `/download/*`, `/decrypt/*`, `/login`, `/register`): Use `background-pattern.webp` / `landing-bg.webp`.
- **Image Optimization & Dual Format**:
  - All raster image assets are compressed as optimized WebP files (`logo.webp`, `landing-bg.webp`, `background-pattern.webp`, `internal-background-pattern.webp`) accompanied by original PNG fallbacks (`logo.png`, `landing-bg.png`, `background-pattern.png`, `internal-background-pattern.png`).

---

## Database Architecture

Obsidian Secure uses the following entity schema:

```mermaid
erDiagram
    USER ||--o{ SHARE : "owns"
    USER ||--o{ USER_SETTING : "has"
    SHARE ||--o{ TRANSFER : "logs"

    USER {
        int id PK
        string username
        string password_hash
        datetime created_at
    }

    SHARE {
        int id PK
        string filename
        string original_name
        string mime_type
        datetime upload_time
        datetime expiry_time
        int download_count
        string public_url
        int user_id FK
        int version
    }

    TRANSFER {
        int id PK
        int share_id FK
        datetime timestamp
    }

    CIPHER {
        int id PK
        string content
        string public_id UK
        boolean burn_on_read
        boolean is_read
        datetime created_at
        string sender_alias
    }

    USER_SETTING {
        int id PK
        int user_id FK
        string key
        string value
    }

    LOGIN_ATTEMPT {
        string ip PK
        int attempts
        datetime last_attempt
    }

    REGISTRATION_ATTEMPT {
        string ip PK
        int attempts
        datetime last_attempt
    }
```

---

## Security Architecture

### 1. Client-Side Encryption
All files and message contents are encrypted inside the browser using `AES-GCM` with a 256-bit key length. A cryptographically secure random 12-byte initialization vector (IV) is generated for each operation. Files are read into an `ArrayBuffer` and encrypted in one operation.

### 2. Server Storage
The server receives and writes raw binary payloads containing `[12-byte IV][ciphertext]`. Because the server is never sent the decryption key, the server cannot read or inspect the files. Files are identified by randomized filename hashes to prevent enumeration attacks.

### 3. Key Isolation & URL Fragments
Keys are stored in the URL fragment identifier (`#key=...`). The fragment identifier is parsed exclusively on the client. It is never sent in the HTTP request line or headers, preventing web servers, proxies, or logs from capturing the key.

### 4. SEO & Privacy Boundary Architecture
- **Indexable Boundary**: Root homepage (`GET /`) is indexable by search engines, serving canonical tags, Open Graph, Twitter cards, and JSON-LD schema.
- **Protected Non-Indexable Boundary**: All authenticated pages (`/dashboard`, `/active-shares`, `/cipher`, `/settings`, `/security`), API endpoints, and dynamic share/cipher pages serve `X-Robots-Tag: noindex, nofollow` headers and meta noindex tags, with `robots.txt` explicitly disallowing automated crawling.

---

## Deployment Architecture

On the Render platform, the application uses:
- **PaaS Web Service**: Python web worker running Gunicorn WSGI.
- **Managed Database**: PostgreSQL database storing user, cipher metadata, and settings.
- **Persistent Disk Volume**: A 10 GB persistent disk mounted at `/var/lib/obsidian/data/` to host the encrypted binary blobs.
- **SQLite Fallback**: Local development defaults to SQLite with Write-Ahead Logging (WAL) and synchronous NORMAL mode enabled to ensure high concurrent reliability.
