# Contributor Guidelines — Obsidian Secure

Thank you for contributing to Obsidian Secure. Please review the setup, testing, and pull request guidelines below to help keep the project's quality high.

---

## Setup for Development

1. **Fork & Clone**: Fork the repository on GitHub and clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Obsidian-Secure.git
   cd Obsidian-Secure
   ```

2. **Configure Python Virtual Environment**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration**:
   Create a local configuration using the template:
   ```bash
   cp .env.example .env
   ```
   Generate a secure, random `SECRET_KEY` and set it in your `.env`.

---

## Run Server Locally

Start the Flask development server:
```bash
python app.py
```
The server will run on `http://127.0.0.1:5000`. On first run, it initializes the SQLite database (`qr_app.db`) and runs migrations automatically.

---

## Testing Requirements

Before submitting a Pull Request, you must verify that all automated validation tests pass:

1. **JavaScript Syntax Verification**:
   ```bash
   node --check static/js/app.js
   node --check static/js/crypto.js
   ```

2. **Pytest Security & Integration Suite**:
   ```bash
   pytest
   ```

Make sure all tests pass cleanly with zero errors before committing changes.

---

## Git Branching Strategy

- **`main`**: Production branch. This branch must remain stable and deployable.
- **Feature Branches**: Create branches off `main` using structured prefixes:
  - `feat/`: New functionality or enhancements.
  - `fix/`: Bug fixes or concurrency corrections.
  - `docs/`: Documentation additions or revisions.
  - `test/`: Adding or modifying verification tests.

---

## Pull Request Process

1. **Sync**: Ensure your branch is updated with the latest commits from the upstream `main` branch.
2. **Secrets**: Double-check that no test credentials, passwords, local paths, or personal keys are included in any modified or added files.
3. **No Code Formatting Bloat**: Keep diffs focused. Avoid formatting unrelated files.
4. **Preserve E2EE Behavior**: Do not modify client-side encryption logic in `static/js/crypto.js` unless addressing a specific audited cryptographic issue.
5. **Description**: Complete the Pull Request template detailing the changes, reasoning, and test results.
