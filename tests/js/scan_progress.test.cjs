'use strict';

// This suite evaluates only the read-only polling client against inert DOM and
// fetch fixtures. It never starts Flask, opens a socket, or contacts a target.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../templates/partials/scan_progress.js'), 'utf8');

function node(text = '') {
  const attributes = new Map();
  return {
    textContent: text,
    dataset: {},
    hidden: true,
    style: {width: '40%'},
    setAttribute(name, value) { attributes.set(name, String(value)); },
    removeAttribute(name) { attributes.delete(name); },
    getAttribute(name) { return attributes.get(name) ?? null; },
    set innerHTML(_value) { throw new Error('response data must not become HTML'); },
  };
}

function row(id = 7, url = `/mounted/api/management/scans/${id}/status`) {
  const children = new Map([
    ['.scan-status', node('OLD STATUS')],
    ['.scan-progress', node()],
    ['.scan-progress-value', node('40%')],
    ['.scan-eta', node('OLD ETA 99')],
    ['.scan-vulnerability-count', node('2')],
    ['.scan-status-error', node()],
  ]);
  return {
    dataset: {scanId: String(id), statusUrl: url},
    querySelector(selector) { return children.get(selector) ?? null; },
  };
}

function payload(id = 7, values = {}) {
  return {
    scan_id: id, status: 'RUNNING', progress: 50, progress_available: true,
    eta_seconds: 12, eta_available: true, vuln_count: 3, ...values,
  };
}

function response(status = 200, body = payload(), contentType = 'application/json') {
  return {
    status, ok: status >= 200 && status < 300,
    headers: {get(name) { return name.toLowerCase() === 'content-type' ? contentType : null; }},
    async json() { return body; },
  };
}

async function settle() {
  await new Promise(resolve => setImmediate(resolve));
}

function harness({rows = [row()], fetch = async () => response(), hidden = false, sourceAvailable} = {}) {
  const ids = new Map([
    ['panel-connection', node('Checking')],
    ['scan-connection-message', node('Checking')],
    ['scan-connection-login', node()],
  ]);
  if (sourceAvailable !== undefined) {
    ids.get('scan-connection-message').dataset.sourceAvailable = String(sourceAvailable);
  }
  const timers = new Map();
  const documentEvents = new Map();
  const windowEvents = new Map();
  const calls = [];
  let timerId = 0;
  const document = {
    hidden,
    baseURI: 'https://panel.example/mounted/dashboard',
    getElementById(id) { return ids.get(id) ?? null; },
    querySelectorAll(selector) {
      assert.equal(selector, 'tr[data-scan-id]');
      return rows;
    },
    addEventListener(event, callback) { documentEvents.set(event, callback); },
  };
  const window = {
    location: {origin: 'https://panel.example'},
    addEventListener(event, callback) { windowEvents.set(event, callback); },
  };
  const context = vm.createContext({
    document, window, URL, AbortController,
    fetch(url, options) { calls.push({url, options}); return fetch(url, options); },
    setTimeout(callback, delay) {
      timers.set(++timerId, {callback, delay});
      return timerId;
    },
    clearTimeout(id) { timers.delete(id); },
  });
  vm.runInContext(source, context, {filename: 'read-only-scan-progress.js'});
  return {
    rows, calls, document, timers,
    element(id) { return ids.get(id); },
    async documentEvent(event) { documentEvents.get(event)?.(); await settle(); },
    async windowEvent(event, value = {}) { windowEvents.get(event)?.(value); await settle(); },
    async fire(delay) {
      const match = [...timers].find(([, timer]) => timer.delay === delay);
      assert.ok(match, `expected scheduled timer with delay ${delay}`);
      timers.delete(match[0]);
      match[1].callback();
      await settle();
    },
    delays() { return [...timers.values()].map(timer => timer.delay); },
  };
}

function assertStale(h, currentRow = h.rows[0]) {
  assert.equal(currentRow.dataset.connection, 'stale');
  assert.equal(currentRow.querySelector('.scan-status-error').hidden, false);
  assert.notEqual(currentRow.querySelector('.scan-status-error').textContent, '');
  assert.equal(currentRow.querySelector('.scan-status').textContent, 'OLD STATUS');
  assert.equal(currentRow.querySelector('.scan-progress').style.width, '40%');
  assert.equal(currentRow.querySelector('.scan-eta').textContent, 'OLD ETA 99');
}

test('updates read-only state with same-origin JSON options and mounted URL', async () => {
  const h = harness();
  await settle();
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].url, 'https://panel.example/mounted/api/management/scans/7/status');
  const options = h.calls[0].options;
  assert.equal(options.method, 'GET');
  assert.equal(options.credentials, 'same-origin');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.redirect, 'error');
  assert.equal(options.headers.Accept, 'application/json');
  assert.ok(options.signal instanceof AbortSignal);
  assert.equal(h.rows[0].querySelector('.scan-status').textContent, 'RUNNING');
  assert.equal(h.rows[0].querySelector('.scan-progress').style.width, '50%');
  assert.equal(h.rows[0].querySelector('.scan-progress').getAttribute('aria-valuenow'), '50');
  assert.equal(h.rows[0].querySelector('.scan-progress').getAttribute('aria-valuetext'), '50%');
  assert.equal(h.rows[0].querySelector('.scan-vulnerability-count').textContent, '3');
  assert.equal(h.rows[0].dataset.connection, 'current');
  assert.equal(h.element('panel-connection').dataset.state, 'current');
  assert.equal(h.element('scan-connection-login').hidden, true);
  assert.deepEqual(h.delays(), [5000]);
});

for (const vulnCount of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, '4', true, null]) {
  test(`invalid vulnerability count ${String(vulnCount)} preserves the stored value`, async () => {
    const h = harness({fetch: async () => response(200, payload(7, {vuln_count: vulnCount}))});
    await settle();
    assert.equal(h.rows[0].querySelector('.scan-vulnerability-count').textContent, '2');
  });
}

test('zero progress and ETA are retained, then missing ETA clears old value', async () => {
  let data = payload(7, {progress: 0, eta_seconds: 0});
  const h = harness({fetch: async () => response(200, data)});
  await settle();
  assert.equal(h.rows[0].querySelector('.scan-progress').style.width, '0%');
  assert.equal(h.rows[0].querySelector('.scan-progress-value').textContent, '0%');
  assert.equal(h.rows[0].querySelector('.scan-eta').textContent, 'ETA: 0 s');
  data = payload(7, {status: 'COMPLETE', progress: 100, eta_available: false, eta_seconds: null});
  await h.fire(5000);
  assert.equal(h.rows[0].querySelector('.scan-status').textContent, 'COMPLETE');
  assert.equal(h.rows[0].querySelector('.scan-progress').style.width, '100%');
  assert.notEqual(h.rows[0].querySelector('.scan-eta').textContent, 'ETA: 0 s');
  assert.ok(!h.rows[0].querySelector('.scan-eta').textContent.includes('null'));
});

for (const progress of [-1, 101, Infinity, NaN, '55', true, null]) {
  test(`invalid progress ${String(progress)} never becomes a CSS percentage`, async () => {
    const h = harness({fetch: async () => response(200, payload(7, {progress}))});
    await settle();
    assert.equal(h.rows[0].querySelector('.scan-progress').style.width, '0%');
    assert.equal(h.rows[0].querySelector('.scan-progress').getAttribute('aria-valuenow'), null);
    assert.equal(h.rows[0].querySelector('.scan-progress').getAttribute('aria-valuetext'), 'İlerleme bilinmiyor');
    assert.notEqual(h.rows[0].querySelector('.scan-progress-value').textContent, `${progress}%`);
  });
}

test('record status is text, including hostile markup', async () => {
  const status = '<img src=x onerror="throw 1">';
  const h = harness({fetch: async () => response(200, payload(7, {status}))});
  await settle();
  assert.equal(h.rows[0].querySelector('.scan-status').textContent, status);
  assert.equal(h.rows[0].dataset.connection, 'current');
});

for (const status of [401, 403]) {
  test(`HTTP ${status} is visible and stops automatic retries`, async () => {
    const h = harness({fetch: async () => response(status, {error: 'denied'})});
    await settle();
    assertStale(h);
    assert.equal(h.element('panel-connection').dataset.state, status === 401 ? 'login_required' : 'forbidden');
    assert.equal(h.element('scan-connection-login').hidden, status !== 401);
    assert.deepEqual(h.delays(), []);
    await h.documentEvent('visibilitychange');
    assert.equal(h.calls.length, 1);
  });
}

test('mixed success and 404 keep good row current and do not retry removed record', async () => {
  const h = harness({rows: [row(7), row(8)], fetch: async url => {
    return url.includes('/8/') ? response(404, {error: 'not_found'}) : response();
  }});
  await settle();
  assert.equal(h.rows[0].dataset.connection, 'current');
  assertStale(h, h.rows[1]);
  assert.equal(h.element('panel-connection').dataset.state, 'stale');
  await h.fire(15000);
  assert.equal(h.calls.filter(call => call.url.includes('/8/')).length, 1);
  assert.equal(h.calls.filter(call => call.url.includes('/7/')).length, 2);
  assert.equal(h.element('panel-connection').dataset.state, 'partial');
});

for (const [label, reply] of [
  ['service error', () => response(503, {error: 'private details must not be displayed'})],
  ['HTML instead of JSON', () => response(200, '<html>login</html>', 'text/html')],
  ['malformed JSON', () => ({...response(), json: async () => { throw new SyntaxError('bad JSON'); }})],
  ['wrong record', () => response(200, payload(99))],
  ['invalid status', () => response(200, payload(7, {status: null}))],
]) {
  test(`${label} preserves last values and exposes unavailable state`, async () => {
    const h = harness({fetch: async () => reply()});
    await settle();
    assertStale(h);
    assert.equal(h.element('panel-connection').dataset.state, 'stale');
    assert.deepEqual(h.delays(), [15000]);
    assert.ok(!h.element('scan-connection-message').textContent.includes('private details'));
  });
}

for (const [label, reply] of [
  ['HTML 404 from proxy', () => response(404, '<html>route missing</html>', 'text/html')],
  ['unknown JSON 404', () => response(404, {error: 'route_not_found'})],
  ['malformed JSON 404', () => ({...response(404), json: async () => { throw new SyntaxError('bad JSON'); }})],
]) {
  test(`${label} cannot permanently mark a stored scan missing`, async () => {
    const h = harness({fetch: async () => reply()});
    await settle();
    assertStale(h);
    assert.equal(h.element('panel-connection').dataset.state, 'stale');
    await h.fire(15000);
    assert.equal(h.calls.length, 2, 'unrecognized endpoint failures must remain retryable');
  });
}

test('network failure backs off, then recovers and hides stale-row warning', async () => {
  let online = false;
  const h = harness({fetch: async () => {
    if (!online) throw new TypeError('network failed');
    return response();
  }});
  await settle();
  assertStale(h);
  await h.fire(15000);
  assert.deepEqual(h.delays(), [30000]);
  online = true;
  await h.fire(30000);
  assert.equal(h.rows[0].dataset.connection, 'current');
  assert.equal(h.rows[0].querySelector('.scan-status-error').hidden, true);
  assert.equal(h.element('panel-connection').dataset.state, 'current');
  assert.deepEqual(h.delays(), [5000]);
});

test('in-flight refreshes never overlap, and the 8-second timeout aborts them', async () => {
  const h = harness({fetch: (_url, {signal}) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), {once: true});
  })});
  assert.equal(h.calls.length, 1);
  assert.deepEqual(h.delays(), [8000]);
  await h.documentEvent('visibilitychange');
  await h.documentEvent('visibilitychange');
  assert.equal(h.calls.length, 1);
  await h.fire(8000);
  assert.equal(h.calls[0].options.signal.aborted, true);
  assertStale(h);
  assert.deepEqual(h.delays(), [15000]);
});

test('cross-origin URL and invalid record IDs never reach fetch', async () => {
  const h = harness({rows: [row(7, 'https://external.invalid/status'), row('0'), row('seven')]});
  await settle();
  assert.equal(h.calls.length, 0);
  h.rows.forEach(currentRow => assertStale(h, currentRow));
});

test('hidden tabs pause polling and pagehide cancels requests and timers', async () => {
  const h = harness({hidden: true});
  await settle();
  assert.equal(h.calls.length, 0);
  h.document.hidden = false;
  await h.documentEvent('visibilitychange');
  assert.equal(h.calls.length, 1);
  h.document.hidden = true;
  await h.documentEvent('visibilitychange');
  assert.deepEqual(h.delays(), []);
  await h.windowEvent('pagehide');
  h.document.hidden = false;
  await h.documentEvent('visibilitychange');
  assert.equal(h.calls.length, 1);
  await h.windowEvent('pageshow', {persisted: true});
  assert.equal(h.calls.length, 2);
});

test('pagehide aborts pending request and leaves no retry scheduled', async () => {
  const h = harness({fetch: (_url, {signal}) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), {once: true});
  })});
  await h.windowEvent('pagehide');
  assert.equal(h.calls[0].options.signal.aborted, true);
  assert.deepEqual(h.delays(), []);
});

test('empty panel is idle without requests, and a populated panel is bounded to 20', async () => {
  const empty = harness({rows: []});
  await settle();
  assert.equal(empty.calls.length, 0);
  assert.equal(empty.element('panel-connection').dataset.state, 'idle');
  assert.deepEqual(empty.delays(), []);
  const many = harness({rows: Array.from({length: 25}, (_, index) => row(index + 1)), fetch: async url => {
    const id = Number(url.match(/scans\/(\d+)/)[1]);
    return response(200, payload(id));
  }});
  await settle();
  assert.equal(many.calls.length, 20);
  assert.equal(many.element('panel-connection').dataset.state, 'current');
});

test('unavailable initial database data is not reported as a clean empty panel', async () => {
  const h = harness({rows: [], sourceAvailable: false});
  await settle();
  assert.equal(h.calls.length, 0);
  assert.equal(h.element('panel-connection').dataset.state, 'unavailable');
  assert.notEqual(h.element('scan-connection-message').textContent, '');
  assert.deepEqual(h.delays(), []);
});
