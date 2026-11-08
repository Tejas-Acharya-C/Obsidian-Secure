/* =================================================================
   OBSIDIAN SECURE - APPLICATION CONTROLLER
   Production-hardened interaction logic.
   ================================================================= */

const ObsidianSecure = (() => {
    'use strict';

    let uploadInProgress = false;
    let cipherInProgress = false;
    let defaultDropzoneMarkup = '';

    // --- Toast System ---
    function showToast(message, type = 'success') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast--${type} toast-enter`;
        toast.setAttribute('role', 'status');

        let icon = 'check_circle';
        if (type === 'error') icon = 'warning';
        if (type === 'info') icon = 'info';

        toast.innerHTML = `
            <span class="material-symbols-outlined toast-icon" aria-hidden="true">${icon}</span>
            <span class="toast-message">${escapeHtml(message)}</span>
            <button class="toast-close-btn" aria-label="Close notification" type="button">
                <span class="material-symbols-outlined">close</span>
            </button>
        `;

        toast.querySelector('.toast-close-btn')?.addEventListener('click', () => dismissToast(toast));
        container.appendChild(toast);
        window.setTimeout(() => dismissToast(toast), 4500);
    }

    function dismissToast(toast) {
        if (!toast || !toast.parentNode) return;
        toast.classList.remove('toast-enter');
        toast.classList.add('toast-exit');
        window.setTimeout(() => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 300);
    }

    // --- Utilities ---
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str ?? '';
        return div.innerHTML;
    }

    function sleep(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    function getCSRFToken() {
        return document.querySelector('input[name="csrf_token"]')?.value || '';
    }

    function formatUtcLabel(isoString) {
        if (!isoString) return 'recently';
        const date = new Date(isoString);
        if (Number.isNaN(date.getTime())) return 'recently';
        const pad = (value) => String(value).padStart(2, '0');
        return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
    }

    // --- Clipboard ---
    function setCopiedButtonState(button) {
        if (!button || button.classList.contains('btn-copy-success')) return;

        const originalHTML = button.innerHTML;
        const iconSpan = button.querySelector('.material-symbols-outlined');
        const iconSizeClass = iconSpan ? [...iconSpan.classList].find((c) => c.startsWith('text-')) || 'text-[16px]' : 'text-[16px]';
        const isSmallButton = button.classList.contains('text-[11px]');
        const mrClass = isSmallButton ? 'mr-1' : '';

        button.classList.add('btn-copy-success');
        button.innerHTML = `
            <span class="material-symbols-outlined ${mrClass} ${iconSizeClass}" aria-hidden="true">check</span>
            <span>Copied!</span>
        `;

        window.setTimeout(() => {
            button.classList.remove('btn-copy-success');
            button.innerHTML = originalHTML;
        }, 2000);
    }

    function fallbackCopyText(text, button = null) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'absolute';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showToast('Link copied to clipboard');
            setCopiedButtonState(button);
        } catch (_) {
            window.prompt('Copy the link below:', text);
        }
        document.body.removeChild(textarea);
    }

    function copyText(text, button = null) {
        if (!text) {
            showToast('No link available', 'error');
            return;
        }

        const onSuccess = () => {
            showToast('Link copied to clipboard');
            setCopiedButtonState(button);
        };

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(onSuccess).catch(() => fallbackCopyText(text, button));
        } else {
            fallbackCopyText(text, button);
        }
    }

    function bindCopyUrlButton(button) {
        if (!button || button.dataset.copyBound === 'true') return;
        button.dataset.copyBound = 'true';
        button.addEventListener('click', (event) => {
            event.preventDefault();
            copyText(button.dataset.copyUrl, button);
        });
    }

    function bindCopyShareButton(button) {
        if (!button || button.dataset.copyBound === 'true') return;
        button.dataset.copyBound = 'true';
        button.addEventListener('click', () => {
            const input = document.getElementById(button.dataset.copyShare);
            if (input) copyText(input.value.trim(), button);
        });
    }

    function initCopyButtons() {
        document.querySelectorAll('[data-copy-url]').forEach(bindCopyUrlButton);
        document.querySelectorAll('[data-copy-share]').forEach(bindCopyShareButton);
    }

    // --- Upload Progress ---
    function updateLinearProgress(barId, percent) {
        const bar = document.getElementById(barId);
        if (bar) bar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
    }

    function updateProgressText(nodeId, percent) {
        const node = document.getElementById(nodeId);
        if (node) node.textContent = `${Math.max(0, Math.min(100, percent))}%`;
    }

    function updateUploadStage(label, percent) {
        const labelNode = document.getElementById('upload-stage-label');
        const percentNode = document.getElementById('upload-stage-percent');
        if (labelNode) labelNode.textContent = label;
        if (percentNode) percentNode.textContent = `${Math.max(0, Math.min(100, percent))}%`;
        updateLinearProgress('upload-stage-bar', percent);
    }

    function setUploadStep(stepName) {
        const steps = document.querySelectorAll('.upload-step');
        let reached = false;

        steps.forEach((step) => {
            const name = step.dataset.step;
            if (name === stepName) {
                step.className = 'upload-step active';
                reached = true;
            } else if (!reached) {
                step.className = 'upload-step done';
            } else {
                step.className = 'upload-step';
            }
        });
    }

    function resetUploadProgressUI() {
        setUploadStep('select');
        updateUploadStage('Preparing upload', 0);
        updateProgressText('encrypt-percent', 0);
        updateProgressText('upload-percent', 0);
        updateLinearProgress('encrypt-progress-bar', 0);
        updateLinearProgress('upload-progress-bar', 0);
    }

    function setDropzoneBusyState(detail) {
        const dropzone = document.getElementById('dropzone');
        if (!dropzone) return;

        dropzone.innerHTML = `
            <span class="material-symbols-outlined text-4xl text-sage mb-3 block animate-gentle-pulse" aria-hidden="true">shield</span>
            <h3 class="text-lg font-medium text-ink-primary mb-1">Processing securely...</h3>
            <p class="text-sm text-ink-secondary">${escapeHtml(detail)}</p>
        `;
        dropzone.style.pointerEvents = 'none';
    }

    function restoreDropzoneState() {
        const dropzone = document.getElementById('dropzone');
        if (!dropzone || !defaultDropzoneMarkup) return;
        dropzone.innerHTML = defaultDropzoneMarkup;
        dropzone.style.pointerEvents = '';
    }

    function setShareResultUrl(url) {
        const input = document.getElementById('share-url');
        if (input) input.value = url;
        const copyButton = document.getElementById('copy-btn');
        if (copyButton) copyButton.dataset.copyShare = 'share-url';
    }

    function revealUploadSuccess(url) {
        const successPanel = document.getElementById('success-panel');
        const awaitingPanel = document.getElementById('awaiting-panel');

        setShareResultUrl(url);
        if (successPanel) {
            successPanel.classList.remove('hidden');
            successPanel.classList.add('success-glow');
            // Scroll into view on mobile where the panel may be below the fold
            if (window.innerWidth < 768) {
                setTimeout(() => successPanel.scrollIntoView({ behavior: 'smooth', block: 'start' }), 150);
            }
        }
        if (awaitingPanel) awaitingPanel.classList.add('hidden');

        generateQRCode('qr-container', url);
        bindCopyShareButton(document.getElementById('copy-btn'));
    }

    function renderExpiryCountdownText(date) {
        const diff = date.getTime() - Date.now();
        if (diff <= 0) return 'Expired';

        const minute = 60 * 1000;
        const hour = 60 * minute;
        const day = 24 * hour;

        if (diff < hour) {
            const minutes = Math.max(1, Math.floor(diff / minute));
            return `Expires in ${minutes} minute${minutes === 1 ? '' : 's'}`;
        }
        if (diff < day) {
            const hours = Math.max(1, Math.floor(diff / hour));
            return `Expires in ${hours} hour${hours === 1 ? '' : 's'}`;
        }

        const days = Math.max(1, Math.floor(diff / day));
        return `Expires in ${days} day${days === 1 ? '' : 's'}`;
    }

    function refreshExpiryCountdowns() {
        document.querySelectorAll('.expiry-countdown').forEach((node) => {
            const raw = node.dataset.expiryTime;
            if (!raw) return;

            const date = new Date(raw);
            if (Number.isNaN(date.getTime())) return;

            const label = renderExpiryCountdownText(date);
            node.textContent = label;
            node.classList.toggle('text-destructive', label === 'Expired');
        });
    }

    function initExpiryCountdowns() {
        if (document.querySelectorAll('.expiry-countdown').length === 0) return;
        refreshExpiryCountdowns();
        window.setInterval(refreshExpiryCountdowns, 60000);
    }

    function prependShareRow(share) {
        const tableBody = document.getElementById('shares-table-body');
        const cardsContainer = document.getElementById('shares-cards-container');
        const legacyList = document.getElementById('active-shares-list');
        const panel = document.getElementById('active-shares-panel');
        const emptyState = document.getElementById('active-shares-empty');
        if (!share || !share.public_url) return;
        if (!tableBody && !cardsContainer && !legacyList) return;

        emptyState?.classList.add('hidden');
        panel?.classList.remove('hidden');

        const uploadDate = share.upload_time ? new Date(share.upload_time) : new Date();
        const uploadEpoch = uploadDate.getTime();
        const uploadIso = uploadDate.toISOString();
        const expiryDate = share.expiry_time ? new Date(share.expiry_time) : null;
        const expiryEpoch = expiryDate ? expiryDate.getTime() : 0;
        const expiryIso = expiryDate ? expiryDate.toISOString() : '';
        const nameEscaped = escapeHtml(share.original_name || 'Shared file');
        const mimeEscaped = escapeHtml(share.mime_type || 'encrypted payload');
        const iconName = share.is_collection ? 'folder_zip' : 'description';

        if (tableBody) {
            const tr = document.createElement('tr');
            tr.className = 'share-item-row group';
            tr.dataset.name = (share.original_name || '').toLowerCase();
            tr.dataset.upload = uploadIso;
            tr.dataset.expiry = expiryIso;
            tr.dataset.uploadEpoch = String(uploadEpoch);
            tr.dataset.expiryEpoch = String(expiryEpoch);
            tr.innerHTML = `
                <td class="col-file">
                    <div class="flex items-center gap-2.5 min-w-0">
                        <span class="material-symbols-outlined text-[20px] text-sage shrink-0" aria-hidden="true">${iconName}</span>
                        <div class="min-w-0">
                            <div class="share-filename-primary truncate title-cell" title="${nameEscaped}">${nameEscaped}</div>
                            <div class="share-mime-secondary truncate">${mimeEscaped}</div>
                        </div>
                    </div>
                </td>
                <td class="col-security">
                    <div class="flex items-center justify-center gap-1.5">
                        <span class="material-symbols-outlined text-[15px] text-sage shrink-0" aria-hidden="true">lock</span>
                        <span class="badge-security-standard">Standard</span>
                    </div>
                </td>
                <td class="col-created text-ink-secondary text-[11px]">Just now</td>
                <td class="col-expiration text-ink-secondary text-[11px]">
                    <span class="expiry-countdown block font-mono text-[11px]" data-expiry-time="${escapeHtml(expiryIso)}"></span>
                </td>
                <td class="col-accesses text-ink-secondary text-[11px]">
                    <span class="font-semibold text-ink-primary text-xs">0</span>
                    <span class="text-ink-muted text-[10px] block">accesses</span>
                </td>
                <td class="col-status status-cell">
                    <span class="status-badge inline-flex items-center justify-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-sage/10 text-sage border border-sage/20">
                        <span class="w-1.5 h-1.5 rounded-full bg-sage"></span>
                        <span>Active</span>
                    </span>
                </td>
                <td class="col-actions">
                    <form action="/revoke" method="POST" class="inline confirm-destructive">
                        <input type="hidden" name="csrf_token" value="${escapeHtml(getCSRFToken())}">
                        <input type="hidden" name="public_url" value="${escapeHtml(share.public_url)}">
                        <button type="submit" class="btn-destructive py-1.5 px-3 text-[11px] min-h-[32px] hover:bg-destructive/10 inline-flex items-center justify-center gap-1" aria-label="Revoke access to ${nameEscaped}">
                            <span class="material-symbols-outlined text-[14px]" aria-hidden="true">delete</span>
                            <span>Revoke</span>
                        </button>
                    </form>
                </td>
            `;
            tableBody.prepend(tr);
        }

        if (cardsContainer) {
            const card = document.createElement('div');
            card.className = 'share-item-card bg-archival-soft border border-archival-border rounded-lg p-4 space-y-3';
            card.dataset.name = (share.original_name || '').toLowerCase();
            card.dataset.upload = uploadIso;
            card.dataset.expiry = expiryIso;
            card.dataset.uploadEpoch = String(uploadEpoch);
            card.dataset.expiryEpoch = String(expiryEpoch);
            card.innerHTML = `
                <div class="flex items-start justify-between gap-2">
                    <div class="flex items-center gap-2 min-w-0">
                        <span class="material-symbols-outlined text-[20px] text-sage shrink-0" aria-hidden="true">${iconName}</span>
                        <div class="min-w-0">
                            <h4 class="text-xs font-semibold text-ink-primary truncate title-cell">${nameEscaped}</h4>
                            <div class="text-[10px] text-ink-muted font-mono">${mimeEscaped}</div>
                        </div>
                    </div>
                    <span class="status-cell shrink-0">
                        <span class="status-badge inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-sage/10 text-sage border border-sage/20">
                            <span class="w-1.5 h-1.5 rounded-full bg-sage"></span>
                            <span>Active</span>
                        </span>
                    </span>
                </div>
                <div class="grid grid-cols-2 gap-2 text-[11px] py-2 border-y border-archival-border/40 text-ink-secondary">
                    <div><span class="text-ink-muted text-[10px] block">Created</span><span>Just now</span></div>
                    <div><span class="text-ink-muted text-[10px] block">Expiration</span><span class="expiry-countdown font-mono text-[11px]" data-expiry-time="${escapeHtml(expiryIso)}"></span></div>
                    <div><span class="text-ink-muted text-[10px] block">Accesses</span><span class="font-semibold text-ink-primary">0</span> accesses</div>
                    <div><span class="text-ink-muted text-[10px] block">Security</span><span>Standard</span></div>
                </div>
                <div class="pt-1">
                    <form action="/revoke" method="POST" class="w-full confirm-destructive">
                        <input type="hidden" name="csrf_token" value="${escapeHtml(getCSRFToken())}">
                        <input type="hidden" name="public_url" value="${escapeHtml(share.public_url)}">
                        <button type="submit" class="btn-destructive w-full py-2 px-3 text-xs min-h-[44px] justify-center hover:bg-destructive/10 inline-flex items-center gap-1.5" aria-label="Revoke access to ${nameEscaped}">
                            <span class="material-symbols-outlined text-[16px]" aria-hidden="true">delete</span>
                            <span>Revoke</span>
                        </button>
                    </form>
                </div>
            `;
            cardsContainer.prepend(card);
        }

        if (legacyList) {
            const wrapper = document.createElement('div');
            wrapper.className = 'flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-archival-soft border border-archival-border rounded hover:border-sage/40 transition-colors gap-3 group';
            wrapper.innerHTML = `
                <div class="min-w-0 flex-1">
                    <h4 class="text-xs font-semibold text-ink-primary mb-1 truncate group-hover:text-sage transition-colors">${nameEscaped}</h4>
                    <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-ink-muted">
                        <span class="flex items-center gap-1.5 text-sage font-semibold">
                            <span class="w-1.5 h-1.5 bg-sage rounded-full"></span>
                            <span>Active</span>
                        </span>
                        <span class="w-1 h-1 rounded-full bg-archival-border hidden sm:block" aria-hidden="true"></span>
                        <span class="text-ink-secondary hidden sm:inline">Uploaded Just now</span>
                        <span class="w-1 h-1 rounded-full bg-archival-border hidden sm:block" aria-hidden="true"></span>
                        <span class="text-ink-secondary expiry-countdown" data-expiry-time="${escapeHtml(expiryIso)}"></span>
                        <span class="w-1 h-1 rounded-full bg-archival-border" aria-hidden="true"></span>
                        <span class="text-ink-secondary">0 accesses</span>
                    </div>
                </div>
                <div class="flex items-center gap-2 self-end sm:self-center shrink-0">
                    <button type="button" data-copy-url="${escapeHtml(share.public_url)}" class="btn-secondary py-1 px-3 text-[11px] min-h-[44px] sm:min-h-[32px]" aria-label="Copy link for ${nameEscaped}">Copy link</button>
                    <form action="/revoke" method="POST" class="inline confirm-destructive">
                        <input type="hidden" name="csrf_token" value="${escapeHtml(getCSRFToken())}">
                        <input type="hidden" name="public_url" value="${escapeHtml(share.public_url)}">
                        <button type="submit" class="btn-destructive py-1 px-3 text-[11px] min-h-[44px] sm:min-h-[32px] hover:bg-destructive/10" aria-label="Revoke access to ${nameEscaped}">Revoke</button>
                    </form>
                </div>
            `;
            legacyList.prepend(wrapper);
            bindCopyUrlButton(wrapper.querySelector('[data-copy-url]'));
        }

        refreshExpiryCountdowns();
        try {
            window.dispatchEvent(new CustomEvent('obsidian:share-created', { detail: share }));
        } catch (_) {}
    }

    // --- Mobile Navigation ---
    function toggleMobileNavigation() {
        const panel = document.getElementById('mobile-nav-panel');
        const backdrop = document.getElementById('mobile-nav-backdrop');
        const button = document.getElementById('mobile-nav-toggle');
        if (!panel || !backdrop) return;

        const isOpen = panel.classList.contains('active');
        panel.classList.toggle('active', !isOpen);
        backdrop.classList.toggle('active', !isOpen);
        document.body.classList.toggle('no-scroll', !isOpen);

        if (button) button.setAttribute('aria-expanded', String(!isOpen));
        panel.setAttribute('aria-hidden', String(isOpen));

        if (!isOpen) {
            const firstLink = panel.querySelector('a');
            if (firstLink) setTimeout(() => firstLink.focus(), 100);
        }
    }

    function closeMobileNavigation() {
        const panel = document.getElementById('mobile-nav-panel');
        const backdrop = document.getElementById('mobile-nav-backdrop');
        const button = document.getElementById('mobile-nav-toggle');

        if (panel && panel.classList.contains('active')) {
            panel.classList.remove('active');
            backdrop?.classList.remove('active');
            document.body.classList.remove('no-scroll');
            panel.setAttribute('aria-hidden', 'true');
        }

        if (button) {
            button.setAttribute('aria-expanded', 'false');
            button.focus();
        }
    }

    function initMobileNavigation() {
        const panel = document.getElementById('mobile-nav-panel');
        document.querySelectorAll('#mobile-nav-toggle').forEach((toggle) => {
            toggle.addEventListener('click', toggleMobileNavigation);
        });
        document.getElementById('mobile-nav-backdrop')?.addEventListener('click', closeMobileNavigation);
        document.getElementById('mobile-nav-close')?.addEventListener('click', closeMobileNavigation);

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') closeMobileNavigation();
            
            // Focus trap
            if (panel && panel.classList.contains('active') && event.key === 'Tab') {
                const focusables = panel.querySelectorAll('a[href], button:not([disabled]), input:not([disabled])');
                if (focusables.length === 0) return;
                const first = focusables[0];
                const last = focusables[focusables.length - 1];
                
                if (event.shiftKey) {
                    if (document.activeElement === first) {
                        event.preventDefault();
                        last.focus();
                    }
                } else {
                    if (document.activeElement === last) {
                        event.preventDefault();
                        first.focus();
                    }
                }
            }
        });

        document.querySelectorAll('#mobile-nav-panel a').forEach((link) => {
            link.addEventListener('click', closeMobileNavigation);
        });
    }

    // --- Settings ---
    function updateSettings(data) {
        fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCSRFToken() },
            body: JSON.stringify(data)
        }).then((response) => {
            if (!response.ok) showToast('Unable to save settings', 'error');
        }).catch(() => {
            showToast('Connection error. Please try again.', 'error');
        });
    }

    function initProtocolToggles() {
        document.querySelectorAll('[data-action="toggle-protocol"]').forEach((button) => {
            button.addEventListener('click', () => {
                const key = button.dataset.key;
                const newState = button.dataset.state === 'true' ? 'false' : 'true';
                button.dataset.state = newState;
                button.setAttribute('aria-checked', newState);

                if (newState === 'true') {
                    button.classList.replace('bg-ink-secondary/20', 'bg-sage');
                    button.querySelector('.switch-knob')?.classList.add('translate-x-5');
                } else {
                    button.classList.replace('bg-sage', 'bg-ink-secondary/20');
                    button.querySelector('.switch-knob')?.classList.remove('translate-x-5');
                }

                updateSettings({ [key]: newState });
            });
        });
    }

    function initAliasSave() {
        const button = document.getElementById('alias-save-btn');
        if (!button) return;

        button.addEventListener('click', () => {
            const input = document.getElementById('alias-input');
            if (!input || !input.value.trim()) return;
            updateSettings({ alias: input.value.trim() });
            showToast('Recipient name updated');
        });
    }

    // --- Multi-File Staging and Validation Constants ---
    const MAX_COLLECTION_FILES = 10;
    const MAX_COLLECTION_SIZE = 50 * 1024 * 1024; // 50 MB
    let stagedFiles = [];

    function formatBytes(bytes) {
        if (bytes >= 1048576) {
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }
        return (bytes / 1024).toFixed(1) + ' KB';
    }

    function renderStagedFiles() {
        const panel = document.getElementById('staged-files-panel');
        const list = document.getElementById('staged-files-list');
        const countSpan = document.getElementById('staged-count');
        const totalSizeSpan = document.getElementById('staged-total-size');
        const errorDiv = document.getElementById('staged-validation-error');
        const actionContainer = document.getElementById('staged-action-buttons');

        if (!panel || !list) return;

        if (stagedFiles.length === 0) {
            panel.classList.add('hidden');
            list.innerHTML = '';
            if (errorDiv) errorDiv.classList.add('hidden');
            return;
        }

        panel.classList.remove('hidden');

        const totalBytes = stagedFiles.reduce((acc, f) => acc + f.size, 0);
        if (countSpan) countSpan.textContent = stagedFiles.length;
        if (totalSizeSpan) totalSizeSpan.textContent = `${formatBytes(totalBytes)} / 50 MB`;

        // Validation
        let errorMsg = '';
        if (stagedFiles.length > MAX_COLLECTION_FILES) {
            errorMsg = `Maximum ${MAX_COLLECTION_FILES} files allowed per collection. Please remove ${stagedFiles.length - MAX_COLLECTION_FILES} file(s).`;
        } else if (totalBytes > MAX_COLLECTION_SIZE) {
            errorMsg = `Total collection size exceeds 50 MB limit (${formatBytes(totalBytes)} selected). Please remove some files.`;
        }

        if (errorDiv) {
            if (errorMsg) {
                errorDiv.textContent = errorMsg;
                errorDiv.classList.remove('hidden');
            } else {
                errorDiv.classList.add('hidden');
            }
        }

        // Render file list
        list.innerHTML = '';
        stagedFiles.forEach((file, index) => {
            const row = document.createElement('div');
            row.className = 'flex items-center justify-between p-2 bg-archival-bg border border-archival-border/60 rounded text-xs gap-2 group';
            row.innerHTML = `
                <div class="flex items-center gap-2 min-w-0">
                    <span class="material-symbols-outlined text-[16px] text-sage shrink-0" aria-hidden="true">description</span>
                    <span class="font-mono text-ink-primary truncate" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
                    <span class="text-ink-muted text-[11px] shrink-0 font-mono">(${formatBytes(file.size)})</span>
                </div>
                <button type="button" class="text-ink-muted hover:text-destructive p-1 rounded transition-colors shrink-0 remove-file-btn" data-index="${index}" aria-label="Remove ${escapeHtml(file.name)}">
                    <span class="material-symbols-outlined text-[16px]">close</span>
                </button>
            `;
            list.appendChild(row);
        });

        list.querySelectorAll('.remove-file-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.dataset.index, 10);
                removeStagedFile(idx);
            });
        });

        // Render action buttons
        if (actionContainer) {
            const hasError = !!errorMsg;
            if (stagedFiles.length === 1) {
                actionContainer.innerHTML = `
                    <button type="button" id="start-single-upload-btn" class="btn-secondary py-1.5 px-3 text-xs inline-flex items-center gap-1 font-medium" ${hasError ? 'disabled' : ''}>
                        <span class="material-symbols-outlined text-[14px]">file_upload</span>
                        <span>Share Single File</span>
                    </button>
                    <button type="button" id="start-collection-upload-btn" class="btn-primary py-1.5 px-3.5 text-xs inline-flex items-center gap-1.5 font-medium" ${hasError ? 'disabled' : ''}>
                        <span class="material-symbols-outlined text-[14px]">folder_zip</span>
                        <span>Share as ZIP Collection</span>
                    </button>
                `;
            } else {
                actionContainer.innerHTML = `
                    <button type="button" id="start-collection-upload-btn" class="btn-primary py-2 px-4 text-xs inline-flex items-center gap-1.5 font-medium" ${hasError ? 'disabled' : ''}>
                        <span class="material-symbols-outlined text-[16px]">lock</span>
                        <span>Encrypt &amp; Share Collection (${stagedFiles.length} files as ZIP)</span>
                    </button>
                `;
            }

            const singleBtn = document.getElementById('start-single-upload-btn');
            if (singleBtn) {
                singleBtn.addEventListener('click', () => {
                    if (stagedFiles.length > 0 && !uploadInProgress) {
                        uploadSingleFile(stagedFiles[0]);
                    }
                });
            }

            const collectionBtn = document.getElementById('start-collection-upload-btn');
            if (collectionBtn) {
                collectionBtn.addEventListener('click', () => {
                    if (stagedFiles.length > 0 && !uploadInProgress) {
                        uploadCollection(stagedFiles);
                    }
                });
            }
        }
    }

    function addFilesToStaging(fileList) {
        if (!fileList || fileList.length === 0) return;

        let addedCount = 0;
        let duplicateCount = 0;

        for (let i = 0; i < fileList.length; i++) {
            const file = fileList[i];

            // Prevent duplicate selection (same name and size)
            const isDup = stagedFiles.some(f => f.name === file.name && f.size === file.size && f.lastModified === file.lastModified);
            if (isDup) {
                duplicateCount++;
                continue;
            }

            if (file.size === 0) {
                showToast(`"${file.name}" is empty (0 bytes) and was skipped.`, 'info');
                continue;
            }

            if (file.size > MAX_COLLECTION_SIZE) {
                showToast(`"${file.name}" exceeds the 50MB limit and was skipped.`, 'error');
                continue;
            }

            if (stagedFiles.length >= MAX_COLLECTION_FILES) {
                showToast(`Maximum limit of ${MAX_COLLECTION_FILES} files reached.`, 'error');
                break;
            }

            stagedFiles.push(file);
            addedCount++;
        }

        if (duplicateCount > 0 && addedCount === 0) {
            showToast(`${duplicateCount} duplicate file(s) already in selection.`, 'info');
        }

        renderStagedFiles();
    }

    function removeStagedFile(index) {
        if (index >= 0 && index < stagedFiles.length) {
            stagedFiles.splice(index, 1);
            renderStagedFiles();
        }
    }

    function clearStagedFiles() {
        stagedFiles = [];
        const fileInput = document.getElementById('file-upload');
        if (fileInput) fileInput.value = '';
        renderStagedFiles();
    }

    // --- Dropzone ---
    function initDropzone() {
        const dropzone = document.getElementById('dropzone');
        const fileInput = document.getElementById('file-upload');
        if (!dropzone || !fileInput) return;

        defaultDropzoneMarkup = dropzone.innerHTML;

        dropzone.addEventListener('click', () => fileInput.click());
        dropzone.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                fileInput.click();
            }
        });

        document.getElementById('add-more-files-btn')?.addEventListener('click', () => fileInput.click());
        document.getElementById('clear-staged-btn')?.addEventListener('click', clearStagedFiles);

        ['dragenter', 'dragover'].forEach((eventName) => {
            dropzone.addEventListener(eventName, (event) => {
                event.preventDefault();
                dropzone.classList.add('drag-over');
            });
        });

        ['dragleave', 'drop'].forEach((eventName) => {
            dropzone.addEventListener(eventName, (event) => {
                event.preventDefault();
                dropzone.classList.remove('drag-over');
            });
        });

        dropzone.addEventListener('drop', async (event) => {
            event.preventDefault();
            const items = event.dataTransfer.items;
            if (!items) return;

            const filesArray = [];

            async function traverseEntry(entry, path = '') {
                if (!entry) return;

                if (entry.isFile) {
                    return new Promise((resolve) => {
                        entry.file((file) => {
                            file.zipPath = path ? `${path}/${file.name}` : file.name;
                            filesArray.push(file);
                            resolve();
                        }, () => resolve());
                    });
                }

                if (entry.isDirectory) {
                    const reader = entry.createReader();
                    let entries = [];
                    const readEntries = async () => {
                        const result = await new Promise((resolve) => {
                            reader.readEntries(resolve, () => resolve([]));
                        });
                        if (result.length > 0) {
                            entries = entries.concat(result);
                            await readEntries();
                        }
                    };

                    await readEntries();
                    await Promise.all(entries.map((child) => traverseEntry(child, path ? `${path}/${entry.name}` : entry.name)));
                }
            }

            const tasks = [];
            for (let index = 0; index < items.length; index += 1) {
                const item = items[index];
                if (item.kind !== 'file') continue;
                const entry = item.webkitGetAsEntry();
                if (entry) tasks.push(traverseEntry(entry));
            }

            await Promise.all(tasks);

            if (filesArray.length > 0) {
                addFilesToStaging(filesArray);
            }
        });
    }

    // --- Upload Flow ---
    function initUploadFlow() {
        const uploadForm = document.getElementById('uploadForm');
        const fileInput = document.getElementById('file-upload');
        if (!uploadForm || !fileInput) return;

        fileInput.addEventListener('change', () => {
            const files = Array.from(fileInput.files);
            if (files.length === 0 || uploadInProgress) return;
            addFilesToStaging(files);
            fileInput.value = ''; // Allow selecting the same file again if removed
        });
    }

    async function uploadSingleFile(fileToEncrypt) {
        if (!fileToEncrypt || uploadInProgress) return;

        const progressPanel = document.getElementById('upload-progress');
        const displayFileName = fileToEncrypt.name;

        uploadInProgress = true;
        setDropzoneBusyState(displayFileName);
        document.getElementById('staged-files-panel')?.classList.add('hidden');
        progressPanel?.classList.remove('hidden');
        resetUploadProgressUI();
        updateUploadStage('Preparing upload', 5);

        setUploadStep('select');
        await sleep(300);

        try {
            setUploadStep('encrypt');

            const key = await generateKey();
            const exportedKey = await exportKey(key);

            const csrfToken = getCSRFToken();
            const originalNameB64 = btoa(unescape(encodeURIComponent(displayFileName)));
            const mimeType = fileToEncrypt.type || 'application/octet-stream';

            updateUploadStage('Encrypting locally...', 50);
            updateProgressText('encrypt-percent', 100);
            updateLinearProgress('encrypt-progress-bar', 100);

            const encryptedBlob = await encryptFile(fileToEncrypt, key);

            setUploadStep('upload');
            updateUploadStage('Uploading encrypted file...', 0);

            const formData = new FormData();
            formData.append('file', encryptedBlob, displayFileName);

            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/v2/upload', true);
            xhr.setRequestHeader('X-CSRF-Token', csrfToken);
            xhr.setRequestHeader('X-Original-Name', originalNameB64);
            xhr.setRequestHeader('X-Mime-Type', mimeType);

            xhr.upload.onprogress = (e) => {
                if (e.lengthComputable) {
                    const uploadPercent = Math.round((e.loaded / e.total) * 100);
                    updateProgressText('upload-percent', uploadPercent);
                    updateLinearProgress('upload-progress-bar', uploadPercent);
                    updateUploadStage('Uploading encrypted file...', uploadPercent);
                }
            };

            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    const payload = JSON.parse(xhr.responseText);
                    if (payload.status !== 'success') {
                        uploadInProgress = false;
                        restoreDropzoneState();
                        document.getElementById('staged-files-panel')?.classList.remove('hidden');
                        showToast(payload.error || 'Upload failed', 'error');
                        return;
                    }

                    setUploadStep('link');
                    updateUploadStage('Share created', 100);

                    const shareUrl = appendKeyToUrl(payload.public_url, exportedKey);
                    revealUploadSuccess(shareUrl);
                    prependShareRow({
                        original_name: payload.share?.original_name || displayFileName,
                        public_url: shareUrl,
                        upload_time: payload.share?.upload_time,
                        expiry_time: payload.share?.expiry_time
                    });

                    showToast('Share created successfully');
                    clearStagedFiles();
                    restoreDropzoneState();
                    uploadInProgress = false;
                } else {
                    if (xhr.status === 413) {
                        showToast('File exceeds the maximum server upload limit.', 'error');
                    } else {
                        showToast(`Upload failed with status ${xhr.status}`, 'error');
                    }
                    uploadInProgress = false;
                    restoreDropzoneState();
                    document.getElementById('staged-files-panel')?.classList.remove('hidden');
                }
            };

            xhr.onerror = () => {
                uploadInProgress = false;
                restoreDropzoneState();
                document.getElementById('staged-files-panel')?.classList.remove('hidden');
                showToast('Network error during upload', 'error');
            };

            xhr.send(formData);
        } catch (error) {
            uploadInProgress = false;
            restoreDropzoneState();
            document.getElementById('staged-files-panel')?.classList.remove('hidden');
            console.error(error);
            showToast(error.message || 'Encryption failed. Please try again.', 'error');
        }
    }

    async function uploadCollection(files) {
        if (!files || files.length === 0 || uploadInProgress) return;

        const totalFiles = files.length;
        const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
        const csrfToken = getCSRFToken();
        const progressPanel = document.getElementById('upload-progress');

        uploadInProgress = true;
        setDropzoneBusyState(`Collection: ${totalFiles} files`);
        document.getElementById('staged-files-panel')?.classList.add('hidden');
        progressPanel?.classList.remove('hidden');
        resetUploadProgressUI();

        setUploadStep('select');
        updateUploadStage('Preparing collection upload...', 5);
        await sleep(200);

        let publicId = null;

        try {
            setUploadStep('encrypt');
            updateUploadStage('Generating collection encryption key...', 10);

            // Generate master encryption key for this collection
            const key = await generateKey();
            const exportedKey = await exportKey(key);

            // Initialize collection on server
            const initRes = await fetch('/api/v2/collection/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({
                    file_count: totalFiles,
                    total_size: totalBytes
                })
            });

            if (!initRes.ok) {
                const errJson = await initRes.json().catch(() => ({}));
                throw new Error(errJson.error || `Failed to initialize collection (${initRes.status})`);
            }

            const initData = await initRes.json();
            publicId = initData.public_id;

            // Sequentially encrypt and upload each file (constant memory footprint!)
            for (let i = 0; i < totalFiles; i++) {
                const file = files[i];
                const fileNum = i + 1;

                // Encrypt step for this file
                setUploadStep('encrypt');
                const fileEncryptPct = Math.round((i / totalFiles) * 100);
                updateUploadStage(`Encrypting (${fileNum}/${totalFiles}): ${file.name}...`, fileEncryptPct);
                updateLinearProgress('encrypt-progress-bar', Math.round((fileNum / totalFiles) * 100));
                updateProgressText('encrypt-percent', Math.round((fileNum / totalFiles) * 100));

                // Encrypt using AES-256-GCM (fresh random IV per file!)
                const encryptedBlob = await encryptFile(file, key);

                // Upload step for this file
                setUploadStep('upload');
                const fileUploadPct = Math.round((i / totalFiles) * 100);
                updateUploadStage(`Uploading (${fileNum}/${totalFiles}): ${file.name}...`, fileUploadPct);

                const originalNameB64 = btoa(unescape(encodeURIComponent(file.name)));
                const mimeType = file.type || 'application/octet-stream';

                const formData = new FormData();
                formData.append('file', encryptedBlob, file.name);

                // Upload via XMLHttpRequest to capture individual file upload progress
                await new Promise((resolve, reject) => {
                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', `/api/v2/collection/${publicId}/file`, true);
                    xhr.setRequestHeader('X-CSRF-Token', csrfToken);
                    xhr.setRequestHeader('X-Original-Name', originalNameB64);
                    xhr.setRequestHeader('X-Mime-Type', mimeType);

                    xhr.upload.onprogress = (e) => {
                        if (e.lengthComputable) {
                            const fileRatio = e.loaded / e.total;
                            const overallUploadPercent = Math.round(((i + fileRatio) / totalFiles) * 100);
                            updateProgressText('upload-percent', overallUploadPercent);
                            updateLinearProgress('upload-progress-bar', overallUploadPercent);
                        }
                    };

                    xhr.onload = () => {
                        if (xhr.status >= 200 && xhr.status < 300) {
                            resolve();
                        } else {
                            reject(new Error(`Failed to upload "${file.name}" (Status ${xhr.status})`));
                        }
                    };

                    xhr.onerror = () => reject(new Error(`Network error while uploading "${file.name}"`));
                    xhr.send(formData);
                });
            }

            // Finalize collection on server
            setUploadStep('link');
            updateUploadStage('Finalizing secure collection link...', 95);

            const finRes = await fetch(`/api/v2/collection/${publicId}/finalize`, {
                method: 'POST',
                headers: { 'X-CSRF-Token': csrfToken }
            });

            if (!finRes.ok) {
                const errJson = await finRes.json().catch(() => ({}));
                throw new Error(errJson.error || 'Failed to finalize collection');
            }

            const finData = await finRes.json();
            setUploadStep('link');
            updateUploadStage('Collection created', 100);

            // Append master key to URL fragment (zero-knowledge)
            const collectionShareUrl = appendKeyToUrl(finData.public_url, exportedKey);
            revealUploadSuccess(collectionShareUrl);

            prependShareRow({
                original_name: finData.share?.original_name || `Collection (${totalFiles} files)`,
                public_url: collectionShareUrl,
                upload_time: finData.share?.upload_time,
                expiry_time: finData.share?.expiry_time
            });

            showToast('Secure collection created successfully');
            clearStagedFiles();
            restoreDropzoneState();
            uploadInProgress = false;

        } catch (err) {
            console.error(err);
            uploadInProgress = false;
            restoreDropzoneState();
            document.getElementById('staged-files-panel')?.classList.remove('hidden');

            // Abort partial server collection if one was initialized
            if (publicId) {
                try {
                    await fetch(`/api/v2/collection/${publicId}/abort`, {
                        method: 'POST',
                        headers: { 'X-CSRF-Token': csrfToken }
                    });
                } catch (_) {}
            }

            showToast(err.message || 'Collection upload failed. Please try again.', 'error');
        }
    }

    // --- Fragment Key Management ---
    function appendKeyToUrl(url, key) {
        if (!url || url.includes('#')) return url;
        return `${url}#key=${encodeURIComponent(key)}`;
    }

    function generateQRCode(containerId, url) {
        const container = document.getElementById(containerId);
        if (!container || typeof QRCode === 'undefined') return;

        container.innerHTML = '';
        container.classList.remove('hidden');
        // eslint-disable-next-line no-undef
        new QRCode(container, {
            text: url,
            width: 256,
            height: 256,
            colorDark: '#000000',
            colorLight: '#ffffff',
            correctLevel: QRCode.CorrectLevel.M
        });
    }

    function loadFragmentKeys() {
        const uploadKey = sessionStorage.getItem('uploadKey');
        if (uploadKey) {
            sessionStorage.removeItem('uploadKey');
            let generatedUrl = '';

            document.querySelectorAll('[data-share-type="upload"]').forEach((input) => {
                if (input.value && !input.value.includes('#')) {
                    input.value = appendKeyToUrl(input.value, uploadKey);
                    generatedUrl = input.value;
                }
            });

            document.querySelectorAll('[data-copy-url]').forEach((button) => {
                const url = button.dataset.copyUrl;
                if (url && url.includes('/download/') && !url.includes('#')) {
                    button.dataset.copyUrl = appendKeyToUrl(url, uploadKey);
                }
            });

            if (generatedUrl) generateQRCode('qr-container', generatedUrl);
        }

        const cipherKey = sessionStorage.getItem('cipherKey');
        if (cipherKey) {
            sessionStorage.removeItem('cipherKey');
            let generatedCipherUrl = '';

            document.querySelectorAll('[data-share-type="cipher"]').forEach((input) => {
                if (input.value && !input.value.includes('#')) {
                    input.value = appendKeyToUrl(input.value, cipherKey);
                    generatedCipherUrl = input.value;
                }
            });

            document.querySelectorAll('[data-copy-url]').forEach((button) => {
                const url = button.dataset.copyUrl;
                if (url && url.includes('/decrypt/') && !url.includes('#')) {
                    button.dataset.copyUrl = appendKeyToUrl(url, cipherKey);
                }
            });

            if (generatedCipherUrl) generateQRCode('cipher-qr-container', generatedCipherUrl);
            
            const cipherSuccessKeyless = document.getElementById('cipher-success-keyless');
            const cipherSuccessWithKey = document.getElementById('cipher-success-with-key');
            if (cipherSuccessKeyless) cipherSuccessKeyless.classList.add('hidden');
            if (cipherSuccessWithKey) cipherSuccessWithKey.classList.remove('hidden');
        }
    }

    // --- Cipher Encryption ---
    async function encryptAndSubmitCipher() {
        const plainField = document.getElementById('cipher-plaintext');
        const button = document.getElementById('cipher-btn');
        if (!plainField || !button) return;

        const plaintext = plainField.value.trim();
        if (!plaintext || cipherInProgress) return;

        cipherInProgress = true;
        button.innerHTML = '<span class="material-symbols-outlined text-[20px] animate-gentle-pulse" aria-hidden="true">shield</span> Encrypting...';
        button.disabled = true;

        try {
            const key = await generateKey();
            const ciphertextB64 = await encryptText(plaintext, key);
            plainField.value = '';
            document.getElementById('encrypted-message-input').value = ciphertextB64;

            sessionStorage.setItem('cipherKey', await exportKey(key));
            document.getElementById('cipherForm').submit();
        } catch (_) {
            cipherInProgress = false;
            showToast('Encryption failed. Please try again.', 'error');
            button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">lock</span> Encrypt Message';
            button.disabled = false;
        }
    }

    function initCipherForm() {
        document.getElementById('cipher-btn')?.addEventListener('click', encryptAndSubmitCipher);
    }

    // --- File Download & Decrypt ---
    function showDownloadError(message) {
        const alert = document.getElementById('download-error');
        const text = document.getElementById('download-error-text');
        if (!alert || !text) return;

        text.textContent = message;
        alert.classList.remove('hidden');
    }

    async function decryptAndDownload(event) {
        event.preventDefault();
        const button = document.getElementById('download-btn');
        if (!button || button.disabled) return;

        const originalHtml = button.innerHTML;
        button.innerHTML = '<span class="material-symbols-outlined text-[20px] animate-gentle-pulse" aria-hidden="true">shield</span> Decrypting...';
        button.disabled = true;

        const filename = button.dataset.filename;
        const keyB64 = getKeyFromFragment();
        const mimeType = button.dataset.mimetype || 'application/octet-stream';

        if (!keyB64) {
            showDownloadError('The decryption key is missing from the URL. Make sure you have the complete link.');
            button.innerHTML = originalHtml;
            button.disabled = false;
            return;
        }

        try {
            const key = await importKey(keyB64);
            const response = await fetch(`/api/v2/get/${filename}`);

            if (!response.ok) {
                showDownloadError(response.status === 404 ? 'This file has expired or been removed.' : 'Unable to retrieve the file. Please try again.');
                button.innerHTML = originalHtml;
                button.disabled = false;
                return;
            }

            const encryptedBlob = await response.blob();
            const plainBlob = await decryptFileAuto(encryptedBlob, key, mimeType);
            const url = URL.createObjectURL(plainBlob);
            const anchor = document.createElement('a');
            anchor.href = url;
            anchor.download = button.dataset.displayName || filename;
            anchor.click();
            setTimeout(() => URL.revokeObjectURL(url), 60000);

            button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">check_circle</span> Download complete';
        } catch (e) {
            console.error(e);
            showDownloadError('Decryption failed. The link may be incomplete or the file may be corrupted.');
            button.innerHTML = originalHtml;
            button.disabled = false;
        }
    }

    function initDecryptDownload() {
        document.getElementById('download-btn')?.addEventListener('click', decryptAndDownload);
    }

    // --- Collection Recipient Decryption and ZIP Generation ---
    function showCollectionError(message) {
        const alert = document.getElementById('collection-error');
        const text = document.getElementById('collection-error-text');
        const retryBtn = document.getElementById('collection-retry-btn');
        if (!alert || !text) return;

        text.textContent = message;
        alert.classList.remove('hidden');
        if (retryBtn) retryBtn.classList.remove('hidden');
    }

    function hideCollectionError() {
        const alert = document.getElementById('collection-error');
        if (alert) alert.classList.add('hidden');
    }

    function sanitizeZipFilename(name) {
        let clean = (name || 'file').replace(/^[a-zA-Z]:[/\\]+/, '').replace(/^[/\\]+/, '');
        let parts = clean.split(/[/\\]+/).filter(p => p !== '' && p !== '.' && p !== '..');
        let base = parts.pop() || 'file';
        return base.replace(/[\x00-\x1f\x7f]/g, '').trim() || 'file';
    }

    function disambiguateFilename(name, existingSet) {
        if (!existingSet.has(name)) {
            existingSet.add(name);
            return name;
        }
        const dotIdx = name.lastIndexOf('.');
        const base = dotIdx !== -1 ? name.substring(0, dotIdx) : name;
        const ext = dotIdx !== -1 ? name.substring(dotIdx) : '';
        let count = 1;
        while (existingSet.has(`${base} (${count})${ext}`)) {
            count++;
        }
        const newName = `${base} (${count})${ext}`;
        existingSet.add(newName);
        return newName;
    }

    async function downloadAndDecryptCollection(event) {
        if (event) event.preventDefault();
        const button = document.getElementById('download-zip-btn');
        if (!button || button.disabled) return;

        hideCollectionError();
        const publicId = button.dataset.publicId;
        const originalHtml = button.innerHTML;

        const keyB64 = getKeyFromFragment();
        if (!keyB64) {
            showCollectionError('The decryption key is missing from the URL (#key=...). Make sure you have the complete link.');
            return;
        }

        button.disabled = true;
        button.innerHTML = '<span class="material-symbols-outlined text-[20px] animate-gentle-pulse" aria-hidden="true">shield</span> Processing Collection...';

        const progressPanel = document.getElementById('collection-progress');
        const progressLabel = document.getElementById('collection-progress-label');
        const progressPercent = document.getElementById('collection-progress-percent');
        const progressBar = document.getElementById('collection-progress-bar');
        const progressSub = document.getElementById('collection-progress-sub');

        if (progressPanel) progressPanel.classList.remove('hidden');

        function setColProgress(label, percent, sub = '') {
            if (progressLabel) progressLabel.textContent = label;
            if (progressPercent) progressPercent.textContent = `${Math.max(0, Math.min(100, percent))}%`;
            if (progressBar) progressBar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
            if (progressSub && sub) progressSub.textContent = sub;
        }

        try {
            setColProgress('Importing encryption key...', 5, 'Client-side Web Crypto API');
            const key = await importKey(keyB64);

            setColProgress('Fetching collection manifest...', 10, 'Retrieving package inventory');
            const manifestRes = await fetch(`/api/v2/collection/${publicId}/manifest`);
            if (!manifestRes.ok) {
                if (manifestRes.status === 410) {
                    throw new Error('This collection has expired or has been revoked by the sender.');
                }
                throw new Error('Unable to retrieve collection manifest.');
            }

            const manifest = await manifestRes.json();
            const files = manifest.files || [];
            const downloadToken = manifest.download_token;
            if (files.length === 0) {
                throw new Error('Collection contains no files.');
            }

            if (typeof JSZip === 'undefined') {
                throw new Error('ZIP archive library is not available.');
            }

            const zip = new JSZip();
            const usedNames = new Set();
            const totalFiles = files.length;

            for (let i = 0; i < totalFiles; i++) {
                const f = files[i];
                const pct = 10 + Math.round((i / totalFiles) * 70);

                setColProgress(
                    `Downloading & decrypting (${i + 1}/${totalFiles}): ${f.original_name}`,
                    pct,
                    'AES-256-GCM verification'
                );

                const fileRes = await fetch(`/api/v2/collection/${publicId}/file/${f.file_id}`);
                if (!fileRes.ok) {
                    throw new Error(`Failed to download file "${f.original_name}" (Status ${fileRes.status})`);
                }

                const encryptedBlob = await fileRes.blob();

                let plainBlob;
                try {
                    plainBlob = await decryptFileAuto(encryptedBlob, key, f.mime_type);
                } catch (decErr) {
                    throw new Error(`Integrity verification failed for "${f.original_name}". Authentication tag mismatch — key is invalid or data corrupted.`);
                }

                if (!plainBlob || plainBlob.size === 0) {
                    throw new Error(`Decrypted file "${f.original_name}" is empty or corrupted.`);
                }

                // Sanitize and disambiguate filename to prevent path traversal
                const safeName = sanitizeZipFilename(f.original_name);
                const uniqueName = disambiguateFilename(safeName, usedNames);

                const arrayBuffer = await plainBlob.arrayBuffer();
                zip.file(uniqueName, arrayBuffer);
            }

            setColProgress('Compressing verified files into ZIP...', 85, 'Deflate compression');

            const zipBlob = await zip.generateAsync({
                type: 'blob',
                compression: 'DEFLATE',
                compressionOptions: { level: 6 }
            }, (meta) => {
                const zipPct = 85 + Math.round(meta.percent * 0.14);
                setColProgress(`Building ZIP: ${Math.round(meta.percent)}%`, zipPct);
            });

            // Trigger browser download
            const blobUrl = URL.createObjectURL(zipBlob);
            const anchor = document.createElement('a');
            anchor.href = blobUrl;
            anchor.download = `collection_${publicId}.zip`;
            document.body.appendChild(anchor);
            anchor.click();
            document.body.removeChild(anchor);
            setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);

            // Record download count on server using single-use acknowledgement token
            if (downloadToken) {
                try {
                    await fetch(`/api/v2/collection/${publicId}/record_download`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: downloadToken })
                    });
                } catch (_) {}
            }

            setColProgress('Download complete!', 100, 'All files decrypted, verified, and packaged into ZIP');
            button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">check_circle</span> Download complete';

        } catch (err) {
            console.error(err);
            if (progressPanel) progressPanel.classList.add('hidden');
            showCollectionError(err.message || 'Failed to decrypt and generate ZIP archive.');
            button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">refresh</span> Retry Download';
            button.disabled = false;
        }
    }

    function initCollectionDownload() {
        const btn = document.getElementById('download-zip-btn');
        if (btn) btn.addEventListener('click', downloadAndDecryptCollection);
        const retryBtn = document.getElementById('collection-retry-btn');
        if (retryBtn) retryBtn.addEventListener('click', downloadAndDecryptCollection);
    }

    // --- Message Decrypt ---
    function showDecryptError(message) {
        const alert = document.getElementById('decrypt-error');
        const text = document.getElementById('decrypt-error-text');
        if (!alert || !text) return;

        text.textContent = message;
        alert.classList.remove('hidden');
    }

    async function decryptMessage() {
        const button = document.getElementById('decrypt-btn');
        if (!button || button.disabled) return;

        button.innerHTML = '<span class="material-symbols-outlined text-[20px] animate-gentle-pulse" aria-hidden="true">shield</span> Retrieving &amp; Decrypting...';
        button.disabled = true;

        const keyB64 = getKeyFromFragment();
        if (!keyB64) {
            showDecryptError('The decryption key is missing from the URL. Make sure you have the complete link.');
            button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">lock_open</span> Decrypt &amp; Read Message';
            button.disabled = false;
            return;
        }

        const publicId = document.getElementById('cipher-public-id')?.value || window.location.pathname.split('/').pop();
        const csrfToken = document.getElementById('cipher-csrf-token')?.value || getCSRFToken();

        try {
            // Recipient-initiated atomic consumption: claims message and retrieves ciphertext in a single atomic transaction
            const response = await fetch(`/api/cipher/consume/${publicId}`, {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': csrfToken,
                    'Content-Type': 'application/json'
                }
            });

            if (response.status === 410 || response.status === 409 || response.status === 404) {
                // Message already burned, expired, or unavailable
                document.getElementById('decrypt-prompt')?.classList.add('hidden');
                document.getElementById('decryption-expired-state')?.classList.remove('hidden');
                return;
            }

            if (!response.ok) {
                showDecryptError('Unable to retrieve message from the server. Please try again.');
                button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">lock_open</span> Decrypt &amp; Read Message';
                button.disabled = false;
                return;
            }

            const data = await response.json();
            const encryptedB64 = data.ciphertext;
            if (!encryptedB64) {
                document.getElementById('decrypt-prompt')?.classList.add('hidden');
                document.getElementById('decryption-expired-state')?.classList.remove('hidden');
                return;
            }

            const key = await importKey(keyB64);
            const plaintext = await decryptText(encryptedB64, key);

            document.getElementById('decrypt-prompt')?.classList.add('hidden');
            const content = document.getElementById('decrypted-content');
            if (content) {
                content.classList.remove('hidden');
                content.classList.add('animate-fade-in');
            }
            const messageField = document.getElementById('plaintext-message');
            if (messageField) messageField.textContent = plaintext;
        } catch (err) {
            console.error('Decryption error:', err);
            showDecryptError('Decryption failed. The key in your URL fragment may be incorrect or the payload corrupted.');
            button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">lock_open</span> Decrypt &amp; Read Message';
            button.disabled = false;
        }
    }

    function initCipherDecrypt() {
        document.getElementById('decrypt-btn')?.addEventListener('click', decryptMessage);
    }

    // --- Form Duplicate Submit Prevention ---
    function initFormProtection() {
        document.querySelectorAll('form[method="POST"]').forEach((form) => {
            let submitted = false;
            form.addEventListener('submit', (event) => {
                if (submitted) {
                    event.preventDefault();
                    return;
                }

                submitted = true;
                const submitButton = form.querySelector('button[type="submit"]');
                if (submitButton) submitButton.disabled = true;

                window.setTimeout(() => {
                    submitted = false;
                    if (submitButton) submitButton.disabled = false;
                }, 5000);
            });
        });
    }

    // --- Toast from body data attribute ---
    function initToastFromBody() {
        const entries = performance.getEntriesByType('navigation');
        const isReload = entries.length > 0 && entries[0].type === 'reload';
        if (isReload) {
            document.body.removeAttribute('data-toast-message');
            delete document.body.dataset.toastMessage;
            return;
        }

        const message = document.body.dataset.toastMessage;
        if (!message || message.trim() === 'None') return;

        showToast(message);
        document.body.removeAttribute('data-toast-message');
        delete document.body.dataset.toastMessage;
    }

    // --- Client-Side Reload Protection ---
    function initReloadProtection() {
        const entries = performance.getEntriesByType('navigation');
        const isReload = entries.length > 0 && entries[0].type === 'reload';
        if (!isReload) return;

        const successPanel = document.getElementById('success-panel');
        const awaitingPanel = document.getElementById('awaiting-panel');
        if (successPanel && awaitingPanel) {
            successPanel.classList.add('hidden');
            awaitingPanel.classList.remove('hidden');
        }

        const cipherSuccessPanel = document.getElementById('cipher-success-panel');
        const cipherLedger = document.getElementById('cipher-ledger');
        const cipherEmpty = document.getElementById('cipher-empty');
        if (cipherSuccessPanel) {
            cipherSuccessPanel.classList.add('hidden');
            if (cipherLedger?.dataset.hasCiphers === 'true') {
                cipherLedger.classList.remove('hidden');
            } else {
                cipherEmpty?.classList.remove('hidden');
            }
        }

        sessionStorage.removeItem('uploadKey');
        sessionStorage.removeItem('cipherKey');
    }

    // --- Landing hero parallax (lightweight, RAF-driven) ---
    function initLandingParallax() {
        const layer = document.querySelector('.landing-bg-layer');
        if (!layer) return;

        let lastScroll = window.scrollY || window.pageYOffset;
        let ticking = false;

        function onScroll() {
            lastScroll = window.scrollY || window.pageYOffset;
            if (ticking) return;

            window.requestAnimationFrame(() => {
                const maxTranslate = 40;
                const docHeight = document.documentElement.scrollHeight - window.innerHeight || 1;
                const pct = Math.min(1, lastScroll / docHeight);
                layer.style.transform = `translateY(${pct * maxTranslate}px) scale(1.02)`;
                ticking = false;
            });

            ticking = true;
        }

        layer.style.transform = 'translateY(0px) scale(1.02)';
        window.addEventListener('scroll', onScroll, { passive: true });
        window.addEventListener('resize', onScroll, { passive: true });
    }

    // --- Destructive Action Confirmations ---
    function initConfirmationDialogs() {
        const confirmDialog = document.getElementById('confirm-dialog');
        const confirmCancel = document.getElementById('confirm-dialog-cancel');
        const confirmOk = document.getElementById('confirm-dialog-confirm');
        if (!confirmDialog || !confirmCancel || !confirmOk) return;

        let currentPendingForm = null;
        let lastOpenerElement = null;

        document.querySelectorAll('form.confirm-destructive').forEach(form => {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                currentPendingForm = form;
                lastOpenerElement = document.activeElement;
                confirmDialog.showModal();
                // WCAG 3.3.4 & 2.4.7: Explicitly focus the safe Cancel action by default
                setTimeout(() => confirmCancel.focus(), 50);
            });
        });

        const closeAndRestore = () => {
            currentPendingForm = null;
            if (confirmDialog.open) confirmDialog.close();
            if (lastOpenerElement && typeof lastOpenerElement.focus === 'function') {
                lastOpenerElement.focus();
            }
        };

        confirmCancel.addEventListener('click', closeAndRestore);
        confirmDialog.addEventListener('cancel', closeAndRestore);

        confirmOk.addEventListener('click', () => {
            if (currentPendingForm) {
                currentPendingForm.submit();
            }
            if (confirmDialog.open) confirmDialog.close();
        });
    }

    // --- Password Visibility Toggles (Phase 23) ---
    function initPasswordToggles() {
        document.querySelectorAll('[data-toggle-password]').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetId = btn.getAttribute('data-toggle-password');
                const input = document.getElementById(targetId);
                if (!input) return;

                const isPassword = input.type === 'password';
                input.type = isPassword ? 'text' : 'password';

                const icon = btn.querySelector('.material-symbols-outlined');
                if (icon) {
                    icon.textContent = isPassword ? 'visibility_off' : 'visibility';
                }

                btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
            });
        });
    }

    // --- Authentication Dynamic Form Validation (Phase 23) ---
    function initAuthValidation() {
        const registerForm = document.getElementById('register-form');
        if (!registerForm) return;

        const usernameInput = document.getElementById('register-username');
        const passwordInput = document.getElementById('register-password');
        const confirmInput = document.getElementById('register-confirm-password');

        const userFeedback = document.getElementById('username-validation-feedback');
        const passFeedback = document.getElementById('password-validation-feedback');
        const confirmFeedback = document.getElementById('confirm-validation-feedback');

        const strengthLabel = document.getElementById('strength-label-text');
        const segments = [
            document.getElementById('strength-seg-1'),
            document.getElementById('strength-seg-2'),
            document.getElementById('strength-seg-3'),
            document.getElementById('strength-seg-4')
        ];

        function updateUsernameFeedback() {
            const val = usernameInput.value;
            if (!val) {
                userFeedback.className = 'validation-feedback hidden';
                userFeedback.innerHTML = '';
                return;
            }
            userFeedback.classList.remove('hidden');
            const regex = /^[A-Za-z0-9_]+$/;
            if (regex.test(val) && val.length <= 50) {
                userFeedback.className = 'validation-feedback valid';
                userFeedback.innerHTML = '<span class="feedback-icon">✓</span> Valid username';
            } else {
                userFeedback.className = 'validation-feedback invalid';
                userFeedback.innerHTML = '<span class="feedback-icon">✗</span> Letters, numbers and underscores only';
            }
        }

        function updatePasswordFeedback() {
            const val = passwordInput.value;
            if (!val) {
                passFeedback.className = 'validation-feedback hidden';
                passFeedback.innerHTML = '';
                updateStrengthMeter(0);
                return;
            }
            passFeedback.classList.remove('hidden');
            if (val.length >= 8) {
                passFeedback.className = 'validation-feedback valid';
                passFeedback.innerHTML = '<span class="feedback-icon">✓</span> Meets minimum requirements';
            } else {
                passFeedback.className = 'validation-feedback invalid';
                passFeedback.innerHTML = '<span class="feedback-icon">✗</span> Minimum 8 characters required';
            }

            let score = 0;
            if (val.length >= 8) {
                score = 1;
                if (/[A-Z]/.test(val)) score++;
                if (/[a-z]/.test(val)) score++;
                if (/[0-9]/.test(val)) score++;
                if (/[^A-Za-z0-9]/.test(val)) score++;
            }
            updateStrengthMeter(score);
            updateConfirmFeedback();
        }

        function updateStrengthMeter(score) {
            segments.forEach(seg => {
                if (seg) seg.className = 'strength-meter-segment';
            });
            if (strengthLabel) strengthLabel.className = '';

            let label = 'None';
            let className = '';
            let activeCount = 0;

            if (score > 0) {
                if (score <= 1) {
                    label = 'Weak';
                    className = 'weak';
                    activeCount = 1;
                } else if (score === 2) {
                    label = 'Fair';
                    className = 'fair';
                    activeCount = 2;
                } else if (score === 3) {
                    label = 'Good';
                    className = 'good';
                    activeCount = 3;
                } else {
                    label = 'Strong';
                    className = 'strong';
                    activeCount = 4;
                }
            }

            if (strengthLabel) {
                strengthLabel.textContent = label;
                if (className) strengthLabel.classList.add(className);
            }

            for (let i = 0; i < activeCount; i++) {
                if (segments[i]) segments[i].classList.add(className);
            }
        }

        function updateConfirmFeedback() {
            const val = confirmInput.value;
            const pval = passwordInput.value;
            if (!val) {
                confirmFeedback.className = 'validation-feedback hidden';
                confirmFeedback.innerHTML = '';
                return;
            }
            confirmFeedback.classList.remove('hidden');
            if (val === pval) {
                confirmFeedback.className = 'validation-feedback valid';
                confirmFeedback.innerHTML = '<span class="feedback-icon">✓</span> Passwords match';
            } else {
                confirmFeedback.className = 'validation-feedback invalid';
                confirmFeedback.innerHTML = '<span class="feedback-icon">✗</span> Passwords do not match';
            }
        }

        usernameInput.addEventListener('input', updateUsernameFeedback);
        passwordInput.addEventListener('input', updatePasswordFeedback);
        confirmInput.addEventListener('input', updateConfirmFeedback);

        registerForm.addEventListener('submit', (e) => {
            const val = usernameInput.value;
            const pval = passwordInput.value;
            const cval = confirmInput.value;
            const regex = /^[A-Za-z0-9_]+$/;

            if (!val || !pval || !cval) {
                e.preventDefault();
                showToast('Please fill out all fields', 'error');
                return;
            }

            if (!regex.test(val) || val.length > 50) {
                e.preventDefault();
                showToast('Use only letters, numbers, and underscores for username', 'error');
                return;
            }

            if (pval.length < 8) {
                e.preventDefault();
                showToast('Password must contain at least 8 characters', 'error');
                return;
            }

            if (pval !== cval) {
                e.preventDefault();
                showToast('Passwords do not match', 'error');
                return;
            }
        });
    }

    // --- Landing Page Interactive Demo (Phase 24) ---
    function initLandingDemoCopy() {
        const btn = document.getElementById('demo-copy-btn');
        const input = document.getElementById('demo-share-input');
        if (!btn || !input) return;

        btn.addEventListener('click', () => {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(input.value.trim()).then(() => {
                    showToast('Demo link copied. Create an account to generate real secure links!', 'info');
                    setCopiedButtonState(btn);
                }).catch(() => {
                    showToast('Demo link copied. Create an account to generate real secure links!', 'info');
                    setCopiedButtonState(btn);
                });
            } else {
                showToast('Demo link copied. Create an account to generate real secure links!', 'info');
                setCopiedButtonState(btn);
            }
        });
    }

    // --- Mobile Memory Warning ---
    function initMobileWarning() {
        const warning = document.getElementById('mobile-memory-warning');
        if (warning) {
            const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
            const isChromium = !!window.chrome;
            const hasFileSystemAccess = 'showSaveFilePicker' in window;
            if (isMobile || !hasFileSystemAccess || !isChromium) {
                warning.classList.remove('hidden');
            }
        }
    }

    // --- Init ---
    function initPage() {
        initToastFromBody();
        initReloadProtection();
        initMobileNavigation();
        initCopyButtons();
        initProtocolToggles();
        initAliasSave();
        initDropzone();
        initUploadFlow();
        initCipherForm();
        initDecryptDownload();
        initCollectionDownload();
        initCipherDecrypt();
        initFormProtection();
        initLandingParallax();
        loadFragmentKeys();
        initExpiryCountdowns();
        initConfirmationDialogs();
        initPasswordToggles();
        initAuthValidation();
        initLandingDemoCopy();
        initMobileWarning();
    }

    document.addEventListener('DOMContentLoaded', initPage);

    return { showToast, copyText };
})();
