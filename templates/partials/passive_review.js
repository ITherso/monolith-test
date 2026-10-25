(() => {
    'use strict';
    const client = document.getElementById('passive-review-client');
    const form = document.getElementById('passive-review-form');
    const fileInput = document.getElementById('event-file');
    const textInput = document.getElementById('event-text');
    const output = document.getElementById('passive-review-output');
    const maximum = Number(client.dataset.maxBytes);

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        output.textContent = 'İnceleniyor…';
        try {
            let payload;
            const file = fileInput.files[0];
            if (file) {
                if (file.size > maximum) throw new Error('too_large');
                payload = await file.arrayBuffer();
            } else {
                payload = new TextEncoder().encode(textInput.value);
                if (payload.byteLength > maximum) throw new Error('too_large');
            }
            if (payload.byteLength === 0) throw new Error('empty');
            const reviewUrl = new URL(client.dataset.reviewUrl, document.baseURI);
            if (reviewUrl.origin !== window.location.origin) throw new Error('invalid_address');
            const response = await fetch(reviewUrl.href, {
                method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
                headers: {'Content-Type': 'application/x-ndjson', 'Accept': 'application/json'}, body: payload,
            });
            if (!response.ok || !(response.headers.get('content-type') || '').toLowerCase().includes('application/json')) {
                throw new Error('invalid_response');
            }
            const result = await response.json();
            output.textContent = JSON.stringify(result, null, 2);
        } catch (error) {
            output.textContent = error.message === 'too_large' ?
                'JSONL verisi boyut sınırını aşıyor.' :
                error.message === 'empty' ? 'JSONL verisi boş.' :
                'İnceleme tamamlanamadı. Oturumunu ve JSONL biçimini kontrol et.';
        }
    });
})();
