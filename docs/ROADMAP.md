# Product Roadmap — Obsidian Secure

This document outlines the development roadmap, completed architecture milestones, and planned expansions for the Obsidian Secure platform.

---

## Recently Completed Milestones

### 1. Dedicated Active Shares Management (`/active-shares`) [COMPLETED]
- **Separation**: Decoupled active share management from the main upload dashboard into a dedicated `/active-shares` view with search, filter controls (`All`, `Active`, `Expiring Soon`, `Expired`), 15-minute status thresholds, and revocation controls.

### 2. Google Discoverability & SEO Architecture [COMPLETED]
- **Public & Private Boundaries**: Implemented root homepage discoverability (`robots.txt`, `sitemap.xml`, Open Graph, JSON-LD schema) alongside `noindex, nofollow` header protections for private/application endpoints.

### 3. Lossless Image Asset Pipeline [COMPLETED]
- **Optimization**: Converted raster assets to optimized WebP images (`logo.webp`, `landing-bg.webp`, `background-pattern.webp`, `internal-background-pattern.webp`) with PNG fallbacks for legacy browser support.

### 4. Design System & Background Synchronization [COMPLETED]
- **Consistency**: Unified internal authenticated application pages (`/dashboard`, `/active-shares`, `/cipher`, `/settings`, `/security`) under a single dark mineral background pattern (`body.app-dashboard-page`).

---

## Near-Term (Q3 - Q4 2026)

### 1. Production PostgreSQL Storage Migration [PLANNED]
- **Objective**: Transition the default database container configuration on Render from SQLite to PostgreSQL.
- **Goal**: Enable fully concurrent write locks, eliminating write contention under heavy client load.

### 2. Multi-Cloud Object Storage Integration [PLANNED]
- **Objective**: Replace Gunicorn persistent disk mounts with AWS S3 or Cloudflare R2 object storage APIs.
- **Goal**: Enable horizontal scalability of Flask backend instances, removing reliance on node-local storage.

### 3. Share Password Protection [PLANNED]
- **Objective**: Add optional, user-defined passwords for file shares.
- **Goal**: Encrypt files client-side using a key derived from both a random token and the password (via PBKDF2 in the browser), adding a second factor of decryption security.

---

## Medium-Term (2027)

### 1. Global CDN Delivery [PLANNED]
- **Objective**: Integrate a CDN (such as Cloudflare) to cache frontend static resources (`crypto.js`, `app.js`, styles, and assets).
- **Goal**: Reduce loading latency for users globally.

### 2. Team Spaces & Sharing [PLANNED]
- **Objective**: Introduce cryptographic user group spaces.
- **Goal**: Allow members of a team to share files securely using public/private key pairs (e.g. encrypting file keys with team member public keys).

### 3. Burn-After-Time Expiring Ciphers [PLANNED]
- **Objective**: Add configurable hourly/daily auto-delete schedules for ciphers, similar to the file sharing expiry design.
- **Goal**: Clean up unread secure messages automatically.

---

## Long-Term (2028+)

### 1. Advanced Zero-Knowledge Analytics [PLANNED]
- **Objective**: Implement cryptographic telemetry collection.
- **Goal**: Provide user feedback on access logs without exposing IP addresses or decryption statistics to the server.

### 2. Native Sync Desktop Clients [PLANNED]
- **Objective**: Develop cross-platform desktop applications (Electron, Rust, or Go) to sync local directories securely.
- **Goal**: Automate file encryption and upload from the desktop.
