# Security Specification — Obsidian Secure

This document specifies the security goals, cryptographic standards, threats modeled, privacy boundaries, and security limitations of the Obsidian Secure platform.

---

## Security Goals

1. **Confidentiality**: The server and network intermediaries must have zero knowledge of the contents of shared files and messages.
2. **Integrity**: Any tampering or corruption of encrypted payloads must be detected during decryption, preventing corrupted files or scripts from being executed.
3. **Availability**: Enforce client rate-limiting controls to mitigate denial-of-service attempts.
4. **Access Control**: Users must have absolute authority to revoke shared file links at any moment.

---

## Zero-Knowledge Design

Obsidian Secure operates on a **zero-knowledge model**. The server acts as a blind relay that hosts encrypted payloads. The backend database stores only metadata (such as timestamps, expiration ranges, and file hashes) but lacks the keys needed to read the files or messages. 

---

## Encryption Architecture

### AES-256-GCM Usage
- **Encryption Algorithm**: Advanced Encryption Standard in Galois/Counter Mode (`AES-GCM`) with a 256-bit key size.
- **Initialization Vector (IV)**: A cryptographically secure random 12-byte initialization vector is generated using `crypto.getRandomValues()` for every encryption operation.
- **Payload Layout**: Encrypted files are stored on disk as a single block with the following layout:
  ```text
  +--------------------------+-----------------------------------+
  |  12-Byte Random IV       |  Encrypted Ciphertext + Auth Tag  |
  +--------------------------+-----------------------------------+
  ```
- **Galois Message Authentication**: The GCM mode appends a 16-byte authentication tag at the end of the ciphertext. This tag is verified by the browser during decryption, ensuring that any modification of the stored ciphertext results in a decryption failure.

### Key Management & URL Fragment Strategy
Decryption keys are generated in the browser and are never transmitted to the host server.
1. **URL Hash Isolation**: When a file is uploaded, the backend returns a canonical sharing link (e.g. `/download/<filename>`).
2. **Client-Side Assembly**: The frontend appends the base64-encoded key using the URL hash fragment syntax:
   `https://domain/download/<filename>#key=<base64_encoded_key>`
3. **HTTP Fragment Standard**: Under HTTP specifications, browsers do not transmit the URL fragment (anything following the `#` symbol) to the server during HTTP requests. This isolates the decryption key strictly within the recipient browser's runtime memory.
4. **Revocation & Management Isolation**: Decryption keys are never displayed or stored on management pages (e.g. `/active-shares`). Copy Link actions are intentionally omitted from Active Shares to preserve client key isolation.

---

## Authentication & Session Security

### Password Hashing
User passwords are hashed server-side before database storage using PBKDF2 security algorithms:
- **Hashing Function**: PBKDF2 with SHA-256 HMAC.
- **Salts**: Random salt values are generated automatically per user by Werkzeug's security framework.
- **Iteration Count**: Configured to match modern security guidelines (defaulting to 600,000 iterations).

### Session Management
- **HttpOnly Cookies**: The Flask session cookie is configured with the `HttpOnly` attribute, preventing client-side scripts from reading session identifiers.
- **SameSite Attribute**: Configured with `SameSite=Lax` to protect against cross-site request forgery attacks.
- **Secure Attribute**: In production environments (where `RENDER` is set to true), cookies enforce the `Secure` attribute, ensuring transmission occurs exclusively over HTTPS.

### CSRF Protection
- **Anti-Forgery Tokens**: Every state-changing request (POST, PUT, DELETE) requires validation of an anti-forgery CSRF token.
- **Verification Channel**: Tokens are validated by matching request parameters or headers (`X-CSRF-Token`) against the user's active session state.

### Rate Limiting
To protect login and registration endpoints from dictionary and brute-force attacks:
- **Login Rate Limit**: Capped at 5 attempts per 15 minutes per IP address.
- **Registration Rate Limit**: Capped at 5 attempts per hour per IP address.
- **IP Extraction Protection**: Implements `ProxyFix` middleware to resolve the actual client IP (`remote_addr`) when running behind proxies like Gunicorn, Render, or Cloudflare.

---

## Privacy Boundary & Discoverability

Search-engine discoverability (`robots.txt`, meta directives, `X-Robots-Tag`) is decoupled from access-control authorization:

### Public / Indexable Boundary
* **Homepage (`GET /`)**: Publicly indexable for search engines. Contains meta description, canonical URL (`https://obsidian-secure-ootw.onrender.com`), Open Graph tags, Twitter metadata, and JSON-LD `SoftwareApplication` schema.

### Private / Non-Indexable Boundary
* **Authenticated Application Pages** (`/dashboard`, `/active-shares`, `/shared`, `/cipher`, `/settings`, `/security`): Protected by login authentication AND serve `noindex, nofollow` headers to block search engine indexing.
* **Dynamic File & Message Endpoints** (`/download/*`, `/decrypt/*`, `/get/*`, `/api/*`): Enforce `noindex, nofollow` headers to ensure recipient payloads and expired share links are excluded from web crawler indexes.
* **Robots Rule Disallows**: `robots.txt` explicitly disallows crawling of `/dashboard`, `/active-shares`, `/shared`, `/cipher`, `/settings`, `/security`, `/api/`, `/upload`, `/revoke`, and `/get/`.

---

## Threat Model

### Protected Against
* **Database Breach**: If the PostgreSQL or SQLite database is fully compromised, attackers only gain access to metadata, user settings, password hashes, and encrypted message ciphers. They cannot decrypt the ciphers or files.
* **Storage Theft**: If the persistent disk volumes are compromised, attackers obtain raw encrypted binaries containing random IVs. Without the keys (which are isolated on clients), these payloads remain unreadable.
* **Server Compromise**: If the server host environment is compromised, historic files remain secure because historic keys were never transmitted to the server. (Active sessions or future uploads could, however, be intercepted if the server's served JS files are modified).
* **Brute-Force Attacks**: Mitigated by strict IP-based rate limiting on registration and login endpoints.

### Not Protected Against
* **Compromised Endpoints**: If the client's operating system or web browser is compromised (e.g. keyloggers or malicious extensions), attackers can extract keys directly from memory.
* **Malicious Server Updates**: If the server itself is compromised and serves a modified, malicious version of `app.js` or `crypto.js`, the script could send keys back to the attacker.
* **Phishing**: Attackers copying the landing pages could trick users into entering or exposing sharing URLs containing key fragments.
* **Endpoint Malware**: Malware running on sender or recipient devices can capture decrypted file buffers during processing.

---

## Security Limitations

- **Memory Buffers**: Because file encryption and decryption are processed in browser memory (`ArrayBuffer`), the maximum file size is capped at 100 MB. Uploading very large files on devices with constrained RAM (like mobile browsers) can cause browser tab crashes.
- **In-App Browser Stripping**: Certain in-app browsers (e.g. inside Facebook, Instagram, WeChat) strip the `#key` hash fragment when opening URLs. Users must open links in external browsers.

---

## Responsible Disclosure

If you discover a security vulnerability in Obsidian Secure, please follow these guidelines:
1. **Do not create public GitHub issues** to report security flaws.
2. Report vulnerabilities privately by submitting a GitHub Security Advisory or by emailing the project security contact at: `security-contact@example.com`.
3. Provide detailed steps, scripts, or proof-of-concepts to reproduce the vulnerability.
4. Allow reasonable time for the maintainers to investigate and resolve the issue before disclosing it publicly.
