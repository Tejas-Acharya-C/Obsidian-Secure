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
        const list = document.getElementById('active-shares-list');
        const panel = document.getElementById('active-shares-panel');
        const emptyState = document.getElementById('active-shares-empty');
        if (!list || !panel || !share || !share.public_url) return;

        emptyState?.classList.add('hidden');
        panel.classList.remove('hidden');

        const wrapper = document.createElement('div');
        wrapper.className = 'flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-archival-soft border border-archival-border rounded hover:border-sage/40 transition-colors gap-3 group';
        wrapper.innerHTML = `
            <div class="min-w-0 flex-1">
                <h4 class="text-xs font-semibold text-ink-primary mb-1 truncate group-hover:text-sage transition-colors">${escapeHtml(share.original_name || 'Shared file')}</h4>
                <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-ink-muted">
                    <span class="flex items-center gap-1.5 text-sage font-semibold">
                        <span class="w-1.5 h-1.5 bg-sage rounded-full"></span>
                        <span>Active</span>
                    </span>
                    <span class="w-1 h-1 rounded-full bg-archival-border hidden sm:block" aria-hidden="true"></span>
                    <span class="text-ink-secondary hidden sm:inline">Uploaded ${escapeHtml(formatUtcLabel(share.upload_time))} UTC</span>
                    <span class="w-1 h-1 rounded-full bg-archival-border hidden sm:block" aria-hidden="true"></span>
                    <span class="text-ink-secondary expiry-countdown" data-expiry-time="${escapeHtml(share.expiry_time || '')}"></span>
                    <span class="w-1 h-1 rounded-full bg-archival-border" aria-hidden="true"></span>
                    <span class="text-ink-secondary">0 opens</span>
                </div>
            </div>
            <div class="flex items-center gap-2 self-end sm:self-center shrink-0">
                <button type="button" data-copy-url="${escapeHtml(share.public_url)}" class="btn-secondary py-1 px-3 text-[11px] min-h-[44px] sm:min-h-[32px]" aria-label="Copy link for ${escapeHtml(share.original_name || 'shared file')}">
                    Copy link
                </button>
                <form action="/revoke" method="POST" class="inline">
                    <input type="hidden" name="csrf_token" value="${escapeHtml(getCSRFToken())}">
                    <input type="hidden" name="public_url" value="${escapeHtml(share.public_url)}">
                    <button type="submit" class="btn-destructive py-1 px-3 text-[11px] min-h-[44px] sm:min-h-[32px] hover:bg-destructive/10" aria-label="Revoke access to ${escapeHtml(share.original_name || 'shared file')}">
                        Revoke
                    </button>
                </form>
            </div>
        `;

        list.prepend(wrapper);
        bindCopyUrlButton(wrapper.querySelector('[data-copy-url]'));
        refreshExpiryCountdowns();
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
                const dataTransfer = new DataTransfer();
                filesArray.forEach((file) => dataTransfer.items.add(file));
                fileInput.files = dataTransfer.files;
                fileInput.dispatchEvent(new Event('change'));
            }
        });
    }

    // --- Upload Flow ---
    function initUploadFlow() {
        const uploadForm = document.getElementById('uploadForm');
        const fileInput = document.getElementById('file-upload');
        const progressPanel = document.getElementById('upload-progress');
        if (!uploadForm || !fileInput) return;

        fileInput.addEventListener('change', async () => {
            const files = fileInput.files;
            if (files.length === 0 || uploadInProgress) return;

            let totalSize = 0;
            for (let index = 0; index < files.length; index += 1) {
                totalSize += files[index].size;
            }

            const maxSize = 5 * 1024 * 1024 * 1024;
            if (totalSize > maxSize) {
                showToast(`Payload exceeds the maximum allowed limit of 5GB (Selected: ${(totalSize / (1024 * 1024 * 1024)).toFixed(2)}GB). Please share fewer or smaller files.`, 'error');
                fileInput.value = '';
                return;
            }

            uploadInProgress = true;

            const hasDirectory = Array.from(files).some((file) => file.zipPath && file.zipPath.includes('/'));
            const isMultiFile = files.length > 1 || hasDirectory;
            let fileToEncrypt;
            let displayFileName;

            if (isMultiFile) {
                let commonRoot = '';
                if (hasDirectory) {
                    const firstZipPath = files[0].zipPath || '';
                    const parts = firstZipPath.split('/');
                    if (parts.length > 1) {
                        const candidate = parts[0];
                        const sharedRoot = Array.from(files).every((file) => file.zipPath && file.zipPath.startsWith(`${candidate}/`));
                        if (sharedRoot) commonRoot = candidate;
                    }
                }

                if (commonRoot) {
                    displayFileName = `${commonRoot}.zip`;
                } else {
                    const stamp = new Date().toISOString().slice(0, 19).replace(/[-T]/g, '_').replace(/:/g, '');
                    displayFileName = `Shared_Archive_${stamp}.zip`;
                }
            } else {
                displayFileName = files[0].name;
            }

            setDropzoneBusyState(isMultiFile ? `${files.length} files selected` : displayFileName);
            progressPanel?.classList.remove('hidden');
            resetUploadProgressUI();
            updateUploadStage('Preparing upload', 5);

            setUploadStep('select');
            await sleep(300);

            try {
                setUploadStep('encrypt');

                if (isMultiFile) {
                    if (typeof JSZip === 'undefined') {
                        throw new Error('ZIP module not loaded yet.');
                    }

                    const zip = new JSZip();
                    for (let index = 0; index < files.length; index += 1) {
                        const pathInZip = files[index].zipPath || files[index].name;
                        zip.file(pathInZip, files[index]);
                    }

                    const zipBlob = await zip.generateAsync({ type: 'blob' });
                    fileToEncrypt = new File([zipBlob], displayFileName, { type: 'application/zip' });
                } else {
                    fileToEncrypt = files[0];
                }

                const key = await generateKey();
                const exportedKey = await exportKey(key);

                const onEncryptProgress = (progress) => {
                    const percent = Math.round((progress.bytesProcessed / progress.totalBytes) * 100) || 0;
                    updateProgressText('encrypt-percent', percent);
                    updateLinearProgress('encrypt-progress-bar', percent);
                    updateUploadStage('Encrypting locally...', percent);
                };

                const csrfToken = getCSRFToken();
                const originalNameB64 = btoa(unescape(encodeURIComponent(displayFileName)));
                const encryptedStream = encryptFileToStream(fileToEncrypt, key, onEncryptProgress);
                const reader = encryptedStream.getReader();

                setUploadStep('upload');
                updateUploadStage('Uploading encrypted file...', 0);

                const uploadId = Array.from(crypto.getRandomValues(new Uint8Array(8))).map((byte) => byte.toString(16).padStart(2, '0')).join('');
                const totalFrames = 1 + Math.max(1, Math.ceil(fileToEncrypt.size / (1024 * 1024)));
                let frameIndex = 0;

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    const response = await fetch('/upload/stream', {
                        method: 'POST',
                        body: value,
                        headers: {
                            'Content-Type': 'application/octet-stream',
                            'X-CSRF-Token': csrfToken,
                            'X-Original-Name': originalNameB64,
                            'X-Upload-ID': uploadId,
                            'X-Chunk-Index': frameIndex.toString(),
                            'X-Total-Chunks': totalFrames.toString()
                        }
                    });

                    if (!response.ok) {
                        if (response.status === 413) {
                            throw new Error('File exceeds the maximum server upload limit.');
                        }
                        throw new Error(`Upload failed with status ${response.status}`);
                    }

                    const uploadPercent = Math.round(((frameIndex + 1) / totalFrames) * 100);
                    updateProgressText('upload-percent', uploadPercent);
                    updateLinearProgress('upload-progress-bar', uploadPercent);
                    updateUploadStage('Uploading encrypted file...', uploadPercent);

                    if (frameIndex === totalFrames - 1) {
                        const payload = await response.json();
                        if (payload.status !== 'success') {
                            throw new Error(payload.error || 'Upload failed');
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
                        fileInput.value = '';
                        restoreDropzoneState();
                        uploadInProgress = false;
                    }

                    frameIndex += 1;
                }
            } catch (error) {
                uploadInProgress = false;
                restoreDropzoneState();
                console.error(error);
                showToast(error.message || 'Encryption failed. Please try again.', 'error');
            }
        });
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

        if (!keyB64) {
            showDownloadError('The decryption key is missing from the URL. Make sure you have the complete link.');
            button.innerHTML = originalHtml;
            button.disabled = false;
            return;
        }

        try {
            const key = await importKey(keyB64);
            const response = await fetch(`/get/${filename}`);

            if (!response.ok) {
                showDownloadError(response.status === 404 ? 'This file has expired or been removed.' : 'Unable to retrieve the file. Please try again.');
                button.innerHTML = originalHtml;
                button.disabled = false;
                return;
            }

            async function runBlobFallback() {
                const encryptedBlob = await response.blob();
                const plainBlob = await decryptFileAuto(encryptedBlob, key);
                const url = URL.createObjectURL(plainBlob);
                const anchor = document.createElement('a');
                anchor.href = url;
                anchor.download = button.dataset.displayName || filename;
                anchor.click();
                setTimeout(() => URL.revokeObjectURL(url), 60000);
            }

            let useFallback = true;
            if ('showSaveFilePicker' in window) {
                const saveName = button.dataset.displayName || filename;
                let fileHandle;
                try {
                    fileHandle = await window.showSaveFilePicker({ suggestedName: saveName });
                    useFallback = false;
                } catch (error) {
                    if (error.name === 'AbortError') {
                        button.innerHTML = originalHtml;
                        button.disabled = false;
                        return;
                    }
                    console.warn('showSaveFilePicker failed, falling back to Blob download:', error);
                }

                if (!useFallback) {
                    try {
                        const writable = await fileHandle.createWritable();
                        await decryptStreamToStream(response.body, writable, key);
                    } catch (error) {
                        console.warn('Writing stream failed, falling back to Blob download:', error);
                        useFallback = true;
                    }
                }
            }

            if (useFallback) {
                await runBlobFallback();
            }

            button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">check_circle</span> Download complete';
        } catch (_) {
            showDownloadError('Decryption failed. The link may be incomplete or the file may be corrupted.');
            button.innerHTML = originalHtml;
            button.disabled = false;
        }
    }

    function initDecryptDownload() {
        document.getElementById('download-btn')?.addEventListener('click', decryptAndDownload);
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

        button.innerHTML = '<span class="material-symbols-outlined text-[20px] animate-gentle-pulse" aria-hidden="true">shield</span> Decrypting...';
        button.disabled = true;

        const keyB64 = getKeyFromFragment();
        if (!keyB64) {
            showDecryptError('The decryption key is missing from the URL. Make sure you have the complete link.');
            button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">lock_open</span> Decrypt Message';
            button.disabled = false;
            return;
        }

        const encryptedB64 = document.getElementById('cipher-content')?.value;
        if (!encryptedB64) {
            showDecryptError('No encrypted content found on this page.');
            button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">lock_open</span> Decrypt Message';
            button.disabled = false;
            return;
        }

        try {
            const key = await importKey(keyB64);
            const plaintext = await decryptText(encryptedB64, key);

            // Mark as read on server after successful decryption
            const publicId = window.location.pathname.split('/').pop();
            try {
                await fetch(`/api/cipher/confirm_read/${publicId}`, { method: 'POST' });
            } catch (e) { console.error('Confirmation failed', e); }

            document.getElementById('decrypt-prompt')?.classList.add('hidden');
            const content = document.getElementById('decrypted-content');
            if (content) {
                content.classList.remove('hidden');
                content.classList.add('animate-fade-in');
            }
            const messageField = document.getElementById('plaintext-message');
            if (messageField) messageField.textContent = plaintext;
        } catch (_) {
            showDecryptError('Decryption failed. The link may be incomplete or the message may be corrupted.');
            button.innerHTML = '<span class="material-symbols-outlined text-[20px]" aria-hidden="true">lock_open</span> Decrypt Message';
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

        document.querySelectorAll('form.confirm-destructive').forEach(form => {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                currentPendingForm = form;
                confirmDialog.showModal();
            });
        });

        confirmCancel.addEventListener('click', () => {
            currentPendingForm = null;
            confirmDialog.close();
        });

        confirmOk.addEventListener('click', () => {
            if (currentPendingForm) {
                currentPendingForm.submit();
            }
            confirmDialog.close();
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
        initCipherDecrypt();
        initFormProtection();
        initLandingParallax();
        loadFragmentKeys();
        initExpiryCountdowns();
        initConfirmationDialogs();
        initPasswordToggles();
        initAuthValidation();
        initLandingDemoCopy();
    }

    document.addEventListener('DOMContentLoaded', initPage);

    return { showToast, copyText };
})();
