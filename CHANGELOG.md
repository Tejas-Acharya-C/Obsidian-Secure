# Changelog

All notable changes to this project will be documented in this file.

## [v2.0.0] - 2026-06-09

### Major Architecture Overhaul
Obsidian Secure has been transitioned to a V2 single-request architecture, moving away from the complex and crash-prone streaming model of V1.

### Added
- **Single-Request Architecture:** Uploads and downloads are now handled via a single `POST /api/v2/upload` and single `GET /api/v2/get` request, increasing reliability on mobile networks.
- **In-Memory Encryption:** AES-256-GCM encryption and decryption are processed entirely within browser memory for a streamlined and secure workflow.
- **Persistent Disk:** Render deployment is mapped to a persistent volume, ensuring files survive container restarts.

### Changed
- **Upload Limit Enforced:** A hard limit of 100 MB has been introduced. This is necessary because in-memory encryption of massive files leads to tab crashes on mobile devices with constrained RAM.
- **Legacy Fallback:** The client retains V1 (`OBSv2`) chunk decryption capabilities so existing file links remain active during the migration period.

### Removed
- **Streaming Chunks:** Removed `OBSv2` custom chunk framing logic.
- **JSZip:** Multi-file archiving logic has been stripped out.
- **File System Access API:** Removed `showSaveFilePicker` exceptions. Files now download reliably via the `<a download>` trigger.
