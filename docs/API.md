# API Reference — Obsidian Secure

This document specifies all endpoints, methods, parameters, and responses for the Obsidian Secure Flask application.

---

## Authentication Routes

### `GET /register`
* **Purpose**: Renders the registration HTML interface.
* **Authentication**: None.
* **Response**: HTML template (`register.html`).

### `POST /register`
* **Purpose**: Registers a new user.
* **Authentication**: None.
* **Request Parameters**:
  - `username` (form-data): Alphanumeric username (max 50 chars).
  - `password` (form-data): User password (min 8 chars).
  - `confirm_password` (form-data): Matching password confirmation.
  - `csrf_token` (form-data): Active CSRF token.
* **Response**:
  - `302 Redirect` to `/dashboard` on success.
  - `200 OK` rendering `register.html` with error code query parameter on validation failure.
* **Errors**:
  - `FIELDS_REQUIRED`: Missing input parameters.
  - `PASSWORDS_DONT_MATCH`: Confirmation does not match password.
  - `INVALID_USERNAME`: Username contains non-alphanumeric/underscore characters or exceeds length.
  - `INVALID_PASSWORD`: Password fails length requirements.
  - `USER_EXISTS`: Username is already registered.
  - `RATE_LIMIT_EXCEEDED`: More than 5 registration attempts from the client IP within an hour.
  - `CSRF_VALIDATION_FAILED`: CSRF verification failed.

### `GET /login`
* **Purpose**: Renders the login HTML interface.
* **Authentication**: None.
* **Response**: HTML template (`login.html`).

### `POST /login`
* **Purpose**: Authenticates a user and starts a session.
* **Authentication**: None.
* **Request Parameters**:
  - `username` (form-data): Registered username.
  - `password` (form-data): User password.
  - `csrf_token` (form-data): Active CSRF token.
  - `remember` (form-data): Optional string `"true"` to persist session across restarts.
* **Response**:
  - `302 Redirect` to `/dashboard` on successful login.
  - `200 OK` rendering `login.html` with error parameters on failure.
* **Errors**:
  - `RATE_LIMIT_EXCEEDED`: More than 5 failed logins within 15 minutes.
  - `ACCESS_DENIED`: Incorrect credentials.
  - `CSRF_VALIDATION_FAILED`: Invalid CSRF token.

### `POST /logout`
* **Purpose**: Terminate session.
* **Authentication**: Required.
* **Request Parameters**:
  - `csrf_token` (form-data): Active CSRF token.
* **Response**: `302 Redirect` to `/login`.
* **Errors**: `403 Forbidden` if CSRF validation fails.

---

## File Sharing & Active Shares Routes

### `POST /api/v2/upload`
* **Purpose**: Accepts a single encrypted Blob payload up to 100 MB.
* **Authentication**: Required.
* **Headers**:
  - `X-CSRF-Token`: Active CSRF token.
  - `X-Original-Name`: Base64 encoded original filename.
  - `X-Mime-Type`: MIME type of the file.
* **Request Body**: `file` (multipart/form-data payload).
* **Response (JSON)**:
  ```json
  {
    "status": "success",
    "redirect": "/dashboard",
    "public_url": "https://your-domain/download/filename",
    "share": {
      "original_name": "filename",
      "public_url": "https://your-domain/download/filename",
      "download_count": 0,
      "upload_time": "2026-06-21T10:00:00Z",
      "expiry_time": "2026-06-21T11:00:00Z",
      "last_accessed_at": null
    }
  }
  ```
* **Errors**:
  - `400 Bad Request`: Missing file parameters or empty size.
  - `403 Forbidden`: CSRF validation failed.

### `POST /upload/stream`
* **Purpose**: Accepts sequential encrypted file chunks (OBSv2 format) for chunked streaming.
* **Authentication**: Required.
* **Headers**:
  - `X-CSRF-Token`: Active CSRF token.
  - `X-Upload-ID`: Alphanumeric unique upload session token.
  - `X-Chunk-Index`: Zero-based integer index of the chunk.
  - `X-Total-Chunks`: Total number of chunks in transmission.
  - `X-Original-Name`: Base64 encoded original filename.
  - `X-Mime-Type`: MIME type of the file.
* **Response (JSON)**:
  - `{"status": "continue"}` on non-final chunks.
  - Standard V2 metadata JSON block on final chunk completion.
* **Errors**:
  - `400 Bad Request`: Missing or invalid headers.
  - `403 Forbidden`: CSRF validation failed.

### `POST /upload`
* **Purpose**: Deprecated V1 upload endpoint.
* **Response**: `410 Gone`.

### `GET /download/<filename>`
* **Purpose**: Renders the recipient share landing download interface.
* **Authentication**: None.
* **Response**: HTML template (`landing_page.html`). Contains metadata (file size, name, expiry status).
* **Errors**: Renders `landing_page.html` with an `expired` template flag if the share doesn't exist or is expired.

### `GET /get/<filename>`
* **Purpose**: Serves encrypted file payload downloads (supports both legacy and current downloads).
* **Authentication**: None.
* **Response**: Binary file stream (`[12-byte IV][Ciphertext]`).
* **Errors**:
  - `404 Not Found`: Share metadata not present.
  - `410 Gone`: Expiration date passed or physical file missing.

### `GET /api/v2/get/<filename>`
* **Purpose**: Streams the complete encrypted Blob (V2 architecture).
* **Authentication**: None.
* **Response**: Binary file stream.
* **Errors**: Same as `/get/<filename>`.

### `GET /active-shares` and `GET /shared`
* **Purpose**: Dedicated active shares ledger management interface.
* **Authentication**: Required.
* **Response**: HTML template (`active_shares.html`). Renders active share items, search, filters (`All`, `Active`, `Expiring Soon`, `Expired`), sorting controls, and revocation options.

### `POST /revoke`
* **Purpose**: Revoke/delete a shared file link and delete its physical payload from disk.
* **Authentication**: Required (must be the owner of the share link).
* **Request Parameters**:
  - `public_url` (form-data): Full URL of the link to revoke.
  - `csrf_token` (form-data): Active CSRF token.
* **Response**: `302 Redirect` back to `/active-shares`.
* **Errors**: `403 Forbidden` if CSRF validation fails or user does not own the share.

---

## Cipher Routes

### `GET /cipher`
* **Purpose**: Renders the list of active unread ciphers owned by the user.
* **Authentication**: Required.
* **Response**: HTML template (`dashboard.html` with `current_page='cipher'`).

### `POST /cipher/create`
* **Purpose**: Creates an encrypted text cipher.
* **Authentication**: Required.
* **Request Parameters**:
  - `content` (form-data): Encrypted base64 ciphertext string.
  - `burn_on_read` (form-data): Optional checkbox indicating self-destruction.
  - `csrf_token` (form-data): Active CSRF token.
* **Response**: `302 Redirect` back to cipher creation page with success messages.

### `GET /decrypt/<public_id>`
* **Purpose**: Serves the cipher page containing the encrypted ciphertext for recipient decryption.
* **Authentication**: None.
* **Response**: HTML template (`cipher_read.html`).
* **Errors**: Renders `cipher_read.html` with an `expired` flag if not found or already read.

### `POST /api/cipher/confirm_read/<public_id>`
* **Purpose**: Deletes/disables access to a burn-on-read cipher after decryption.
* **Authentication**: None.
* **Response (JSON)**: `{"status": "success"}`.

---

## Settings & Security Routes

### `GET /settings`
* **Purpose**: Renders user configurations, storage statistics, and security management.
* **Authentication**: Required.
* **Response**: HTML template (`dashboard.html` with `current_page='settings'`).

### `GET /security`
* **Purpose**: Renders platform security standards page.
* **Authentication**: Required.
* **Response**: HTML template (`dashboard.html` with `current_page='security'`).

### `POST /settings/password`
* **Purpose**: Updates user password.
* **Authentication**: Required.
* **Request Parameters**:
  - `current_password` (form-data): Current active password.
  - `new_password` (form-data): New password (min 8 chars).
  - `confirm_password` (form-data): Matching new password confirmation.
  - `csrf_token` (form-data): Active CSRF token.
* **Response**: `302 Redirect` back to Settings.

### `POST /api/settings`
* **Purpose**: Updates JSON user settings values.
* **Authentication**: Required.
* **Headers**:
  - `X-CSRF-Token`: Active CSRF token.
* **Request Body (JSON)**: Dictionary of key-value pairs (e.g. `{"alias": "Acharya", "auto_revoke": "true", "ghost_mode": "false"}`).
* **Response (JSON)**: `{"status": "success"}`.
* **Errors**: `403 Forbidden` if CSRF validation fails.

---

## Discoverability & SEO Routes

### `GET /`
* **Purpose**: Renders the home landing page.
* **Authentication**: None.
* **Response**:
  - `302 Redirect` to `/dashboard` if already authenticated.
  - `200 OK` rendering `landing.html` if unauthenticated.

### `GET /robots.txt`
* **Purpose**: Serves search engine crawling instructions. Allows public homepage indexing and disallows private/application endpoints.
* **Authentication**: None.
* **Response**: Plain text (`text/plain`).

### `GET /sitemap.xml`
* **Purpose**: Serves XML sitemap featuring the production homepage.
* **Authentication**: None.
* **Response**: XML document (`application/xml`).

### `GET /dashboard`
* **Purpose**: Renders main secure file creation and upload workspace.
* **Authentication**: Required.
* **Response**: HTML template (`dashboard.html` with `current_page='files'`).
