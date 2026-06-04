# Obsidian Secure — Zero-Knowledge File & Message Sharing Platform

Obsidian Secure is a platform designed to facilitate the secure exchange of files and messages. Files are encrypted client-side before upload, ensuring that decryption keys remain entirely outside the server. Recipients do not require an account to retrieve shared data, supporting seamless and secure file sharing and encrypted messages.

## Features

* Secure file sharing
* Secure message sharing
* AES-GCM client-side encryption
* QR code sharing
* Link expiration
* Burn-after-read messages
* User accounts
* Admin configuration
* Rate limiting
* CSRF protection

## Security Architecture

Obsidian Secure employs a zero-knowledge architecture:

1. **Selection:** A file is selected by the sender.
2. **Encryption:** The file is encrypted locally in the browser.
3. **Upload:** The encrypted payload is uploaded to the server.
4. **Key Retention:** The decryption key is retained entirely client-side and appended as a URL fragment (`#key`).
5. **Sharing:** The recipient receives the sharing link containing the key fragment.
6. **Decryption:** The recipient's browser fetches the encrypted payload and decrypts it locally.

## Tech Stack

**Backend:**
* Flask
* SQLAlchemy
* Flask-Login
* PostgreSQL / SQLite

**Frontend:**
* HTML
* CSS
* JavaScript

**Security:**
* Web Crypto API
* AES-GCM
* CSRF protection
* Rate limiting

**Deployment:**
* Render

## Deployment

Obsidian Secure can be deployed using Docker, WSGI servers like Gunicorn/Waitress, or PaaS providers like Render.

### Environment Variables

* `SECRET_KEY`: A highly secure random string used for session signing and CSRF protection.
* `DATABASE_URL` (optional): PostgreSQL connection string. If omitted, SQLite is used.

Note: Public registration is enabled by default.

### Database Setup

Upon first startup, the application context automatically initializes the database tables and populates default settings if they do not exist.

### Admin Bootstrap

To create the initial administrator account, run the included bootstrap script from the terminal:

```bash
python create_admin.py
```
This script securely prompts for the administrator password and creates the "Tejas" admin user.

## Administration

* **create_admin.py**: A one-time bootstrap script that securely provisions the primary administrator account ("Tejas") without exposing passwords or relying on environment variables.
* **Admin Privileges**: Administrators have exclusive access to modify global configuration settings, toggle protocols, and revoke active shares across all users.
* **Standard User Permissions**: Standard users can securely share files, create encrypted messages, view their own active shares, and revoke their own files. They can view the application's global configuration but cannot modify it.

## Project Structure

```text
├── app.py
├── models.py
├── templates/
├── static/
├── tests/
└── create_admin.py
```

## Screenshots

*Landing Page Placeholder*
![Landing Page]()

*Dashboard Placeholder*
![Dashboard]()

*Recipient Download Placeholder*
![Recipient Download]()

*Settings Placeholder*
![Settings]()

## Security Disclaimer

The project is designed for secure personal and educational use. Users should independently audit the code before handling sensitive production workloads.
