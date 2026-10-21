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
  simulation output, badge handling, and the CI boundary itself.
- Reviewed helpers/tests receive AST syntax, Ruff lint, and formatting checks.
  The two standalone safety/credential helpers also receive Mypy checks without
  importing operational dependencies.
- The matrix covers Windows and Ubuntu with Python 3.11 and 3.12.
- CI installs `requirements_ci.txt`, not the operational dependency set. Pytest
  plugin auto-loading is disabled.
- The separate container job builds the image but never starts the application.

Example local validation, without launching the application:

```text
python -m pip install -r requirements_ci.txt
python scripts/check_management_safety.py --syntax-check
python -m pytest -c pytest-management.ini
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
