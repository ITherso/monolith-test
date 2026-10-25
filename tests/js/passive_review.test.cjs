'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(
  path.join(__dirname, '../../templates/partials/passive_review.js'), 'utf8',
);

async function settle() {
  await new Promise(resolve => setImmediate(resolve));
}

function harness({
  text = '{}\n', file = null, maximum = 1024, reply = {read_only: true},
  reviewUrl = '/panel/api/management/passive-events/review', status = 200,
  contentType = 'application/json',
} = {}) {
  const handlers = new Map();
  const calls = [];
  const client = {dataset: {reviewUrl, maxBytes: String(maximum)}};
  const form = {addEventListener(event, callback) { handlers.set(event, callback); }};
  const fileInput = {files: file ? [file] : []};
  const textInput = {value: text};
  const output = {
    textContent: 'initial',
    set innerHTML(_value) { throw new Error('response must never become HTML'); },
  };
  const elements = new Map([
    ['passive-review-client', client],
    ['passive-review-form', form],
    ['event-file', fileInput],
    ['event-text', textInput],
    ['passive-review-output', output],
  ]);
  const document = {
    baseURI: 'https://panel.example/panel/passive-review',
    getElementById(id) { return elements.get(id); },
  };
  const window = {location: {origin: 'https://panel.example'}};
  const context = vm.createContext({
    document, window, URL, TextEncoder,
    async fetch(url, options) {
      calls.push({url, options});
      return {
        status, ok: status >= 200 && status < 300,
        headers: {get(name) { return name.toLowerCase() === 'content-type' ? contentType : null; }},
        async json() { return reply; },
      };
    },
  });
  vm.runInContext(source, context, {filename: 'passive-review.js'});
  return {
    calls, output,
    async submit() {
      handlers.get('submit')({preventDefault() {}});
      await settle();
    },
  };
}

test('submits bounded text as same-origin NDJSON and renders JSON as text', async () => {
  const h = harness({
    text: '{"action":"persistence_created"}\n',
    reply: {findings: [{summary: '<img src=x onerror=alert(1)>'}]},
  });
  await h.submit();
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].url, 'https://panel.example/panel/api/management/passive-events/review');
  assert.equal(h.calls[0].options.method, 'POST');
  assert.equal(h.calls[0].options.credentials, 'same-origin');
  assert.equal(h.calls[0].options.cache, 'no-store');
  assert.equal(h.calls[0].options.redirect, 'error');
  assert.equal(h.calls[0].options.headers['Content-Type'], 'application/x-ndjson');
  assert.equal(h.calls[0].options.headers.Accept, 'application/json');
  assert.equal(new TextDecoder().decode(h.calls[0].options.body), '{"action":"persistence_created"}\n');
  assert.match(h.output.textContent, /<img src=x/);
});

test('rejects oversized pasted text before fetch', async () => {
  const h = harness({text: 'x'.repeat(20), maximum: 10});
  await h.submit();
  assert.equal(h.calls.length, 0);
  assert.match(h.output.textContent, /boyut sınırını/);
});

test('rejects empty input and cross-origin endpoint before fetch', async () => {
  const empty = harness({text: ''});
  await empty.submit();
  assert.equal(empty.calls.length, 0);
  assert.match(empty.output.textContent, /boş/);

  const crossOrigin = harness({reviewUrl: 'https://outside.invalid/review'});
  await crossOrigin.submit();
  assert.equal(crossOrigin.calls.length, 0);
  assert.match(crossOrigin.output.textContent, /tamamlanamadı/);
});

for (const [label, options] of [
  ['HTTP error', {status: 403}],
  ['HTML response', {contentType: 'text/html'}],
]) {
  test(`${label} is not rendered as a successful review`, async () => {
    const h = harness(options);
    await h.submit();
    assert.equal(h.calls.length, 1);
    assert.match(h.output.textContent, /tamamlanamadı/);
  });
}

test('rejects oversized file before reading or fetch', async () => {
  let read = false;
  const file = {
    size: 11,
    async arrayBuffer() { read = true; return new ArrayBuffer(0); },
  };
  const h = harness({file, maximum: 10});
  await h.submit();
  assert.equal(read, false);
  assert.equal(h.calls.length, 0);
  assert.match(h.output.textContent, /boyut sınırını/);
});
