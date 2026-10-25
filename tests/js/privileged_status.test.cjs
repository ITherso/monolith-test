'use strict';

// Run only the three metadata clients with a fake DOM, clock and fetch. No tool,
// native library, browser, server, kernel probe or external request is started.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const ebpf = {
  implementation: 'not_implemented', available: false, runtime_available: false,
  executed: false, compiled: false, loaded: false, attached: false,
  initialized: false, kernel_version: null, support_verified: false,
  host_probe_performed: false, host_state: 'not_inspected', verified_effects_only: true,
  loaded_programs: 0, total_programs: 0, hidden_processes: 0, hidden_files: 0,
  hidden_connections: 0, captured_packets: 0, packet_rules: 0, programs: {}, requested_records: {},
};
const panels = [
  {
    name: 'BYOVD', file: 'byovd.html', url: '/panel/byovd/api/status', output: 'terminalOutput',
    descriptor: {
      module: 'byovd', status: 'unavailable', success: false, available: false,
      executed: false, host_probe_performed: false, driver_loaded: false,
      kernel_access: false, edr_terminated: false, reason: 'byovd_backend_unavailable',
    },
    contradict(data) { data.driver_loaded = true; },
  },
  {
    name: 'eBPF', file: 'ebpf_rootkit.html', url: '/panel/ebpf-rootkit/api/status', output: 'ebpf-operation-state',
    descriptor: {success: false, descriptor_retrieved: true, available: false, executed: false, status: ebpf},
    contradict(data) { data.status.loaded = true; },
  },
  {
    name: 'Docker', file: 'docker_escape.html', url: '/panel/docker-escape/api/status', output: 'docker-module-status',
    descriptor: {
      success: false, available: false, initialized: false, execution_available: false,
      executed: false, host_probe_performed: false,
      status: {implementation: 'unavailable', initialized: false, inspection_performed: false,
        host_probe_performed: false, container_detected: null, container_info: null,
        escape_vectors: null, available_escapes: null, escape_attempts: null, successful_escapes: null},
    },
    contradict(data) { data.executed = true; },
  },
];

function scriptFor(panel) {
  const template = fs.readFileSync(path.join(__dirname, '../../templates', panel.file), 'utf8');
  const scripts = [...template.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 1, `${panel.name} must have only its metadata client`);
  const script = scripts[0][1].replace(/{{\s*url_for\([^)]*\)\s*\|\s*tojson\s*}}/g, JSON.stringify(panel.url));
  assert.ok(!script.includes('{{'), 'fixture must bind every template URL');
  return script;
}

function response(status, data, contentType = 'application/json') {
  return {
    status, ok: status >= 200 && status < 300,
    headers: {get: () => contentType},
    json: async () => data,
  };
}

function harness(panel, fetcher) {
  const nodes = new Map();
  const calls = [];
  const timers = new Map();
  let timerId = 0;
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, {
      textContent: '', disabled: false, dataset: {statusUrl: panel.url},
      addEventListener() {},
      set innerHTML(_value) { throw new Error('metadata must be rendered as text'); },
    });
    return nodes.get(id);
  }
  const context = vm.createContext({
    document: {getElementById: node, baseURI: 'https://panel.example/panel/'},
    window: {location: {origin: 'https://panel.example'}},
    URL, AbortController,
    fetch(url, options) { calls.push({url, options}); return fetcher(url, options); },
    setTimeout(callback, delay) { timers.set(++timerId, {callback, delay}); return timerId; },
    clearTimeout(id) { timers.delete(id); },
  });
  vm.runInContext(scriptFor(panel), context, {filename: `inert-${panel.file}`});
  return {calls, timers, text: () => node(panel.output).textContent};
}

async function settle() { await new Promise(resolve => setImmediate(resolve)); }

for (const panel of panels) {
  test(`${panel.name}: opening panel reads metadata only with mounted session URL`, async () => {
    const h = harness(panel, async () => response(200, structuredClone(panel.descriptor)));
    await settle();
    assert.equal(h.calls.length, 1);
    assert.equal(new URL(h.calls[0].url, 'https://panel.example').pathname, panel.url);
    const options = h.calls[0].options;
    assert.equal(options.method, 'GET');
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Accept, 'application/json');
    assert.equal(options.body, undefined);
    assert.ok(options.signal instanceof AbortSignal);
    assert.ok(h.text());
    assert.equal(h.timers.size, 0);
  });

  for (const status of [401, 403, 501, 503]) {
    test(`${panel.name}: HTTP ${status} cannot become descriptor confirmation`, async () => {
      const valid = harness(panel, async () => response(200, structuredClone(panel.descriptor)));
      await settle();
      const h = harness(panel, async () => response(status, structuredClone(panel.descriptor)));
      await settle();
      assert.ok(h.text());
      assert.notEqual(h.text(), valid.text());
      assert.equal(h.calls.length, 1);
      assert.equal(h.timers.size, 0);
    });
  }

  for (const kind of ['HTML', 'malformed JSON', 'contradictory flags']) {
    test(`${panel.name}: ${kind} stays unavailable`, async () => {
      const valid = harness(panel, async () => response(200, structuredClone(panel.descriptor)));
      await settle();
      const data = structuredClone(panel.descriptor);
      panel.contradict(data);
      const h = harness(panel, async () => {
        if (kind === 'HTML') return response(200, structuredClone(panel.descriptor), 'text/html');
        if (kind === 'malformed JSON') return {...response(200, {}), json: async () => { throw new SyntaxError('PRIVATE-FIXTURE'); }};
        return response(200, data);
      });
      await settle();
      assert.ok(h.text());
      assert.notEqual(h.text(), valid.text());
      assert.ok(!h.text().includes('PRIVATE-FIXTURE'));
      assert.equal(h.calls.length, 1);
      assert.equal(h.timers.size, 0);
    });
  }

  test(`${panel.name}: timeout cancels metadata request without operational retry`, async () => {
    const h = harness(panel, (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new Error('inert abort')));
    }));
    await settle();
    assert.equal(h.calls.length, 1);
    const timeout = [...h.timers.values()].find(timer => timer.delay === 8000);
    assert.ok(timeout);
    timeout.callback();
    await settle();
    assert.equal(h.calls[0].options.signal.aborted, true);
    assert.ok(h.text());
    assert.equal(h.calls.length, 1);
    assert.equal(h.timers.size, 0);
  });
}
