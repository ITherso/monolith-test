# Contributing to MONOLITH

Thank you for your interest in improving MONOLITH. This document explains how to set up the development environment, run tests, and submit changes.

## Code of Conduct

- Only test systems you own or have explicit written authorization to test.
- Do not commit credentials, keys, or offensive payloads intended for unauthorized use.
- Be respectful and constructive in issues and pull requests.

## Development Setup

```bash
git clone https://github.com/ITherso/monolith-test.git
cd monolith-test
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements_extra.txt
python3 cyber.py --db-upgrade
```

## Project Structure

- `cyberapp/` — Flask application, routes, models, services, workers
- `cybermodules/` — Core attack modules
- `evasion/` — Evasion engine and C2 profiles
- `tools/` — Standalone tools including cloud redirectors, mappers, report generators
- `c2/` — C2 listener and team server
- `tests/` — Pytest suite
- `docs/` — Documentation and images

## Testing and Lint

```bash
make test
make lint
make typecheck
make format
```

## Commit Conventions

Use clear, scoped commit messages:

- `feat(evasion): add adaptive timing module`
- `fix(c2): handle reconnect backoff on socket drop`
- `docs: update Quick Start screenshots`
- `refactor(cloud): split redirector into provider modules`

## Pull Requests

1. Open an issue describing the problem or feature.
2. Keep changes focused and minimal.
3. Ensure tests and lint pass.
4. Update README or docs when user-facing behavior changes.

## Reporting Bugs

Use GitHub Issues with:
- MONOLITH version
- OS / Python version
- Steps to reproduce
- Logs or traceback
