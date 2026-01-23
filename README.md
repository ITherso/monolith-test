## Production Başlatma (Senior Seviye)

Uygulamayı production-ready şekilde başlatmak için:

```bash
make run-prod
```

veya doğrudan:

```bash
PYTHONPATH=. .venv/bin/gunicorn -w 4 -b 0.0.0.0:8080 wsgi:app
```

Bu şekilde uygulama, 4 worker ile 8080 portunda production-ready olarak çalışır.
# Monolith Pentest Framework

![Coverage Target](https://img.shields.io/badge/coverage%20target-50%25-yellow)

Modular Flask-based pentest platform with services, routes, templates, and worker queue support.

## Structure

- `cyber.py` - app entrypoint and core bootstrap
- `cyberapp/routes/` - Flask blueprints
- `cyberapp/services/` - business logic and helpers
- `cyberapp/models/` - data access layer
- `templates/` - HTML templates
- `cybermodules/` - legacy modules and engines
- `tests/` - unit tests

## Run (dev)

```
python3 cyber.py
```

## Docker

```
docker build -t monolith .
docker run --rm -p 5000:5000 monolith
```

## Docker Compose

```
docker compose up --build
```

## Environment

Copy `.env.example` to `.env` and adjust secrets.

```
ADMIN_PASS=change_me
ANALYST_PASS=change_me
MONOLITH_HOST=127.0.0.1
MONOLITH_PORT=5000
MONOLITH_LOG_LEVEL=INFO
MONOLITH_QUEUE=local
REDIS_URL=redis://localhost:6379/0
```

## Queue

- Default: in-process queue
- Optional: RQ backend

```
export MONOLITH_QUEUE=rq
./run_rq_worker.sh
```

## Migrations

Database schema is managed via Alembic migrations.

Common commands:
- `python3 cyber.py --db-upgrade`
- `python3 cyber.py --db-current`
- `python3 cyber.py --db-revision "add feature"`

Coverage policy (incremental):
- Current gate: 50% for core app layers (`cyberapp/routes`, `cyberapp/services`, `cyberapp/models`)
- Target: increase to 60%, then 70% as tests expand
- Update badge: `python3 scripts/update_coverage_badge.py`
- Optional git hook: `python3 scripts/install_git_hooks.py`

```
alembic revision -m "add new table"
alembic upgrade head
```

## Tests

```
python3 -m unittest discover -s tests
```
