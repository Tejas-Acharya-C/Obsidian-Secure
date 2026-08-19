# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v2.2.0] - 2026-08-19

### Active Shares Separation & Visual Refinement

### Added
- **Dedicated Active Shares Page (`/active-shares`)**: Architectural and UI separation extracting active share management into a dedicated authenticated view, preserving `/shared` as a legacy route alias.
- **Search, Filters & Sorting**: Real-time filename search, status filters (`All`, `Active`, `Expiring Soon`, `Expired`), and timestamp/expiration sorting controls.
- **Unified Application Background**: Standardized `body.app-dashboard-page` background visual system (`internal-background-pattern.webp`) across all authenticated application pages (`/dashboard`, `/active-shares`, `/cipher`, `/settings`, `/security`).
- **Clean Pytest Suite Rebuild**: Completely replaced historical ad-hoc test scripts with a clean 24-test pytest suite covering routing, auth, authorization, share lifecycle (15m rule), zero-knowledge key isolation, CSRF security, SEO, and privacy disclosures.

### Changed
- **15-Minute Expiring Soon Threshold**: Centralized dynamic status badge threshold to 15 minutes (`EXPIRING_SOON_MS = 15 * 60 * 1000`).

### Removed
- **Copy Link Action**: Removed Copy Link action from Active Shares management table and mobile cards to enforce strict client-side key isolation.

---

## [v2.1.0] - 2026-08-18

### SEO Discoverability & Image Asset Optimization

### Added
- **Google Discoverability Architecture**: Integrated production sitemap (`/sitemap.xml`), crawling rules (`/robots.txt`), Open Graph metadata, Twitter cards, and JSON-LD `SoftwareApplication` structured schema on the root homepage (`/`).
- **Private Route Protection**: Configured `X-Robots-Tag: noindex, nofollow` headers and meta noindex protection across all authenticated workspace pages and dynamic file/cipher recipient endpoints.
- **Optimized WebP Image Pipeline**: Optimized all raster image assets to WebP (`logo.webp`, `landing-bg.webp`, `background-pattern.webp`, `internal-background-pattern.webp`) while maintaining PNG fallbacks for legacy browsers.

---

## [v2.0.0] - 2026-06-21

### Major Architecture Overhaul & Concurrency Fixes

### Added
- **Single-Request Architecture**: File sharing is transitioned to a single-request flow. File uploads are completed via a single `POST /api/v2/upload` request, and downloads are served via `GET /api/v2/get`, increasing reliability.
- **In-Memory Encryption**: Web Crypto API `AES-256-GCM` encryption/decryption is processed entirely within browser memory, removing chunk framing overhead.
- **SQLite Concurrency Enhancements**: Configured `PRAGMA busy_timeout=30000;` on the database engine connection hook to prevent write contention timeouts.
- **Background Session Teardowns**: Explicit `db.session.remove()` execution within the background cleanup daemon and the metrics batcher flusher loop, preventing connection leaks.
- **Single-Transaction Registration**: Refactored the user registration flow to perform all inputs validations and CPU-heavy password hashing *before* database write calls, committing user and rate-limiting updates in a single transaction.
- **Persistent Disk Integration**: Render deployments support mounting a persistent volume to preserve encrypted file payloads across container rebuilds.

### Changed
- **Preserved MIME Types**: File uploads store file MIME types in the database, allowing decrypted files to be reconstructed with correct extensions and MIME headers.
- **100 MB Upload Limit**: Configured a client-side limit of 100 MB to avoid browser memory exhaust issues during in-memory encryption on resource-constrained devices.

### Removed
- **Streaming Chunks**: Deprecated chunked file streaming endpoints and framing.
- **JSZip Dependency**: Removed multi-file zip archiving to simplify the client-side code footprint.
- **File System Access API**: Standardized downloads on the `<a download>` anchor trigger to avoid browser compatibility issues with `showSaveFilePicker`.

---

## [v1.0.0] - 2026-06-09

### Initial Release

### Added
- **Zero-Knowledge Architecture**: Symmetric encryption keys are generated client-side and appended to sharing links using browser-only URL fragment tags (`#key`), keeping them isolated from backend servers.
- **Burn-after-Read Messaging**: Messages can be configured to self-destruct upon decryption, removing the cipher from the database.
- **Rate Limiting Protection**: Configured login attempts rate-limiting (5 per 15 minutes) and registration rate-limiting (5 per hour) to protect against brute-force attacks.
- **Strict CSP Headers**: Restrictive Content Security Policy configuration.
- **User Settings Ledger**: Control alias display names, Ghost Mode (filename masking), and default link expirations (1 hour vs 7 days).
- **Asynchronous Metrics logging**: Thread-safe `MetricsBatcher` buffers download telemetry writes to minimize write frequency.
