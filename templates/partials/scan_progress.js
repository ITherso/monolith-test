/* Read-only dashboard updates. No scanner, listener or command dispatch. */
(() => {
    'use strict';
    const connection = document.getElementById('panel-connection');
    const message = document.getElementById('scan-connection-message');
    const login = document.getElementById('scan-connection-login');
    const missing = new Set();
    let busy = false;
    let stopped = false;
    let timer = null;
    let controller = null;
    let failures = 0;

    function connectionState(state, text) {
        if (connection) {
            connection.dataset.state = state;
            connection.textContent = text;
        }
        if (message) message.textContent = text;
        if (login) login.hidden = state !== 'login_required';
    }

    function rowError(row, text) {
        row.dataset.connection = 'stale';
        const error = row.querySelector('.scan-status-error');
        if (error) {
            error.textContent = text;
            error.hidden = false;
        }
    }

    function updateRow(row, data) {
        if (!data || data.scan_id !== Number(row.dataset.scanId) ||
            typeof data.status !== 'string' || !data.status.trim() || data.status.length > 256) {
            throw new Error('invalid_response');
        }
        const knownProgress = data.progress_available === true &&
            typeof data.progress === 'number' && Number.isFinite(data.progress) &&
            data.progress >= 0 && data.progress <= 100;
        const knownEta = data.eta_available === true &&
            typeof data.eta_seconds === 'number' && Number.isFinite(data.eta_seconds) && data.eta_seconds >= 0;
        const status = row.querySelector('.scan-status');
        const bar = row.querySelector('.scan-progress');
        const value = row.querySelector('.scan-progress-value');
        const eta = row.querySelector('.scan-eta');
        const vulnerabilityCount = row.querySelector('.scan-vulnerability-count');
        const error = row.querySelector('.scan-status-error');
        if (status) status.textContent = data.status;
        if (bar) {
            bar.style.width = knownProgress ? `${data.progress}%` : '0%';
            if (knownProgress) {
                bar.setAttribute('aria-valuenow', String(data.progress));
                bar.setAttribute('aria-valuetext', `${data.progress}%`);
            } else {
                bar.removeAttribute('aria-valuenow');
                bar.setAttribute('aria-valuetext', 'İlerleme bilinmiyor');
            }
        }
        if (value) value.textContent = knownProgress ? `${data.progress}%` : 'İlerleme bilinmiyor';
        if (eta) eta.textContent = knownEta ? `ETA: ${data.eta_seconds} s` : 'ETA: bilinmiyor';
        if (vulnerabilityCount && Number.isSafeInteger(data.vuln_count) && data.vuln_count >= 0) {
            vulnerabilityCount.textContent = String(data.vuln_count);
        }
        if (error) {
            error.textContent = '';
            error.hidden = true;
        }
        row.dataset.connection = 'current';
    }

    async function readRow(row, signal) {
        try {
            if (!/^[1-9][0-9]*$/.test(row.dataset.scanId || '') || !row.dataset.statusUrl) {
                throw new Error('invalid_address');
            }
            const url = new URL(row.dataset.statusUrl, document.baseURI);
            if (url.origin !== window.location.origin) throw new Error('invalid_address');
            const response = await fetch(url.href, {
                method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
                headers: {'Accept': 'application/json'}, signal,
            });
            if (response.status === 401) {
                rowError(row, 'Oturum sona erdi; son kayıt gösteriliyor.');
                return 'login_required';
            }
            if (response.status === 403) {
                rowError(row, 'Bu kaydın durumunu görüntüleme yetkin yok.');
                return 'forbidden';
            }
            if (response.status === 404) {
                if ((response.headers.get('content-type') || '').toLowerCase().includes('application/json')) {
                    const error = await response.json();
                    if (error && error.error === 'not_found') {
                        missing.add(row.dataset.scanId);
                        rowError(row, 'Tarama kaydı bulunamadı. Sayfayı yenile.');
                        return 'missing';
                    }
                }
                throw new Error('invalid_response');
            }
            if (!response.ok) throw new Error('service_unavailable');
            if (!(response.headers.get('content-type') || '').toLowerCase().includes('application/json')) {
                throw new Error('invalid_response');
            }
            updateRow(row, await response.json());
            return 'current';
        } catch (error) {
            const text = signal.aborted ? 'Durum isteği zaman aşımına uğradı; son kayıt gösteriliyor.' :
                error.message === 'invalid_address' ? 'Durum bağlantısının adresi geçersiz.' :
                'Durum alınamadı; son kayıt gösteriliyor.';
            rowError(row, text);
            return 'unavailable';
        }
    }

    function cancelTimer() {
        if (timer !== null) clearTimeout(timer);
        timer = null;
    }

    async function refresh() {
        if (stopped || busy || document.hidden) return;
        cancelTimer();
        const allRows = Array.from(document.querySelectorAll('tr[data-scan-id]')).slice(0, 20);
        const rows = allRows.filter(row => !missing.has(row.dataset.scanId));
        if (!rows.length) {
            if (message && message.dataset.sourceAvailable === 'false') {
                connectionState('unavailable', 'Tarama kayıtları şu anda okunamıyor. Sayfayı yenile.');
                return;
            }
            connectionState('idle', allRows.length ? 'Kayıtlar bulunamadı. Sayfayı yenile.' : 'Panel yüklendi; gösterilecek tarama yok.');
            return;
        }
        busy = true;
        controller = new AbortController();
        const active = controller;
        const timeout = setTimeout(() => active.abort(), 8000);
        try {
            const results = await Promise.all(rows.map(row => readRow(row, active.signal)));
            if (stopped) return;
            if (results.includes('login_required')) {
                stopped = true;
                connectionState('login_required', 'Oturum sona erdi. Durumları yenilemek için yeniden giriş yap.');
            } else if (results.includes('forbidden')) {
                stopped = true;
                connectionState('forbidden', 'Tarama durumlarını görüntüleme yetkin yok.');
            } else if (results.every(result => result === 'current')) {
                failures = 0;
                connectionState(missing.size ? 'partial' : 'current', missing.size ?
                    'Bazı kayıtlar bulunamadı; diğer tarama durumları güncel.' : 'Tarama durumları güncel.');
            } else {
                failures += 1;
                connectionState('stale', 'Bazı tarama durumları alınamadı; son kayıtlar gösteriliyor. Yeniden denenecek.');
            }
        } finally {
            clearTimeout(timeout);
            controller = null;
            busy = false;
            if (!stopped && !document.hidden) {
                timer = setTimeout(refresh, failures ? Math.min(30000, failures * 15000) : 5000);
            }
        }
    }

    document.addEventListener('visibilitychange', () => {
        cancelTimer();
        if (!document.hidden) refresh();
    });
    window.addEventListener('pagehide', () => {
        stopped = true;
        cancelTimer();
        if (controller) controller.abort();
    });
    window.addEventListener('pageshow', event => {
        if (event.persisted) {
            stopped = false;
            refresh();
        }
    });
    refresh();
})();
