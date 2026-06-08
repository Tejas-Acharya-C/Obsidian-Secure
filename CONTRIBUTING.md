# Contributing to Obsidian Secure

Thank you for your interest in contributing to Obsidian Secure! We welcome contributions to improve our security posture, code quality, developer experience, and frontend features.

---

## Setup for Development

1. **Fork and Clone**: Fork this repository on GitHub and clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Obsidian-Secure.git
   cd Obsidian-Secure
   ```

2. **Python Virtual Environment**: Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Dependencies**: Install dev and production dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration**: Propose a local `.env` file using the example:
   ```bash
   cp .env.example .env
   ```

---

## Running Locally

To start the Flask development server:
```bash
python app.py
```
By default, the server runs on `http://127.0.0.1:5000`.



## Running Tests

Before submitting any code changes, verify that the existing tests pass and no security regressions are introduced:

1. **Security Hardening Verifications**:
   ```bash
   python tests/verify_hardening.py
   ```

2. **Full Regression and Stability Audit**:
   ```bash
   python tests/audit_regression.py
   ```

Make sure both output `ALL TESTS PASSED` before committing your changes.

---

## Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names (e.g., `fix/rate-limit-bypass` or `feat/custom-expiration`).
2. **Commit Messages**: Follow standard commit message guidelines (e.g., `docs: update deployment details` or `fix: handle empty cipher input`).
3. **No Secrets/Credentials**: Double-check that no test credentials, passwords, local paths, or personal keys are included in any modified or added files.
4. **Preserve E2EE Behavior**: Avoid modifications to client-side encryption logic in `static/js/crypto.js` unless addressing specific audited cryptographic issues.
5. **PR Description**: Include a detailed description of what changes were made and how they were verified.
