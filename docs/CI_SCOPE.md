# Management Safety CI scope

The default push/PR workflow is explicitly named **Management Safety CI**. Its
success means the reviewed management and host-protection contracts pass; it does
not mean that the offensive framework, all legacy tests, or runtime integrations
have been validated.

## Why the workflow changed

The previous workflow started `cyber.py` before collecting the complete legacy
suite. That imports operational modules and can reach code with local process or
network side effects. This conflicts with the local-host protection requirement.
It also failed during Python 3.11 collection before any test ran:

- `tests/test_evasion_atomic.py` imported `cybermodules/lateral_evasion.py`, whose
  nested f-string uses syntax not accepted by Python 3.11.
- The same run logged swallowed import errors in payload generation and DLL
  sideload modules.
- Static inventory separately found legacy parse defects in
  `cybermodules/event_driven_c2.py` and `cybermodules/kernel_callbacks_bypass.py`.

These operational modules were not repaired or re-enabled. `pytest.ini` and the
remaining legacy tests are retained; bare `pytest` still selects that old suite and
is not claimed to be green or safe to run on a personal computer. No test failure
is converted to success with `continue-on-error`, `|| true`, or xfail.

## What is checked

- The reviewed test files are listed explicitly in `pytest-management.ini` and
  the stdlib-only `scripts/check_management_safety.py` manifest. No automatic
  discovery of operational tests occurs.
- The suite checks host-entrypoint import stops, disabled local command execution,
  login/session behavior, credential persistence, escaped audit rendering,
  absent vulnerable management routes, schema upgrades/data preservation, honest
  simulation output, badge handling, and the CI boundary itself. It also covers
  real PDF-fixture encryption and failure propagation, mocked release metadata,
  bounded passive JSONL ingestion/preview routes, read-only feature status, and
  admin-only dispatch before inert HTTP/socket handlers. Authorization tests
  verify denied handlers do not run; they never execute an operational action.
- PDF rendering now exercises a real offline ReportLab path, including Turkish
  text, long content, tables, pagination, and encryption/publication together.
  Renderer failures remain mocked for deterministic failure checks. No external
  converter is executed. Dashboard malformed-data recovery and escaped scan
  detail rendering are also tested using isolated data/templates.
- Release HTTP is mocked. Passive monitoring reads only temporary supplied files, not OS events
  or captured packets. FIFO rejection is skipped on Windows because FIFOs are
  unavailable there; it is exercised on Ubuntu. See
  [repaired behavior and remaining limits](SAFE_FEATURE_REPAIRS.md).
- Offline vulnerability review now tests category completeness, observed-product
  recognition, contextual header hints, uncalibrated risk ordering, immutable
  deduplication, unknown/empty data, admin API dispatch, and real SQLite snapshot
  roundtrips. Migration checks include `0007_ai_vulnerability_reports`. AI-only
  worker tests extract the reviewed functions with inert dependencies; the actual
  worker and its operational imports are not loaded. See
  [analysis semantics and limits](AI_VULNERABILITY_ANALYSIS.md).
- Reviewed helpers/tests receive in-memory syntax compilation, Ruff lint, and
  formatting checks. Compilation catches invalid return, loop and scope contexts
  that AST parsing alone accepts. It never executes source, resolves imports, or
  writes bytecode files; contextual-error and no-execution regressions cover this.
  The two standalone safety/credential helpers also receive Mypy checks without
  importing operational dependencies.
- Listener failure regressions extract only the reviewed definitions into inert
  test namespaces. They check that placeholder starts cannot report success,
  missing Web C2 operations return explicit HTTP 501 without backend dispatch,
  and the advanced start route does not construct a server. C2 modules and the
  application are never imported or started; this is not listener validation.
- Dashboard status checks directly load the reviewed monitoring route with a
  temporary SQLite database and inert package dependencies. Canonical/legacy
  contracts, prefix-aware URLs, JSON session failures, bounded progress/ETA,
  generic database failures, and read-only behavior are covered. The legacy
  status handler is extracted into an inert namespace; scan-list tests load
  `scans.py` behind stubbed dependencies without starting operational features.
- The separate management-only factory is exercised against a migrated temporary
  SQLite database. It loads login, stored-record review, status, audit and offline
  analysis routes without importing the operational application or feature
  packages. Its CLI accepts loopback addresses only; tests use Flask's in-process
  client and never start a listening server.
- Node 24 dashboard tests evaluate only `templates/partials/scan_progress.js` against a fake
  DOM, clock, and fetch implementation. They cover safe read requests, errors,
  recovery, cancellation, stale display and zero/unknown values without starting
  a browser, server, scanner, or listener. Other dashboard scripts are not run.
- BYOVD status tests load the management-only route with inert package boundaries.
  eBPF and Docker tests extract only reviewed definitions into inert namespaces;
  their operational tool modules are not imported. Tests check unavailable API
  responses, admin access, false execution/access claims and safe panel rendering.
  They do not load drivers, compile or attach eBPF, contact a daemon, execute a
  payload, or validate host escape. See [the repaired status contracts](PRIVILEGED_MODULE_STATUS.md).
  Additional Node fixtures evaluate only the three pages' metadata clients and
  their response/timeout handling, with fake DOM and fetch implementations.
- The matrix covers Windows and Ubuntu with Python 3.11 and 3.12.
- CI installs `requirements_ci.txt`, not the operational dependency set. Pytest
  plugin auto-loading is disabled.
- The separate container job builds the image but never starts the application.

A separate source-only inventory on 2026-10-25 used Python 3.12.14: 433 tracked
Python files compiled in memory; the two legacy errors listed above remained.
Four locally missing sources were excluded without restoration.
This inventory did not execute source or validate Python 3.11 compatibility; the
curated CI matrix remains the evidence for its reviewed files on those versions.

Example local validation, without launching the application:

```text
python -m pip install -r requirements_ci.txt
python scripts/check_management_safety.py --syntax-check
python -m pytest -c pytest-management.ini
node --test tests/js/scan_progress.test.cjs tests/js/privileged_status.test.cjs
python scripts/check_management_safety.py --lint
python scripts/check_management_safety.py --format-check
python -m mypy --follow-imports=skip cyberapp/host_safety.py cyberapp/security.py
```

## Coverage-target workflow

The former badge workflow was invalid because `on: []` defines no event. It now
has a valid manual `workflow_dispatch` trigger. Its stdlib script reads a real
configured `--cov-fail-under` target, not a commented README example. If no target
exists, it makes no coverage claim and removes any stale target badge. A target
badge describes a configured threshold, not measured test coverage.
