# Changelog

## [Unreleased]

### Added

## [2.6.0] - 2026-07-12 — "The Ghost Protocol"

### Added
- **Thread-Ghosting injection** (`evasion/process_injection.py`): `THREAD_GHOSTING`
  technique that detours a legitimately-loaded module export to an in-module
  shellcode trampoline; export-RVA resolver + in-module region allocation;
  registered in the fallback chain.
- **C2 Traffic Entropy obfuscation** (`evasion/c2_traffic_entropy.py`):
  embeds AES-encrypted C2 into benign carriers (PNG LSB stego or HTML decoy
  page) to defeat entropy / ML traffic analysis; wired into
  `WinHTTPNetworkStack` via `enable_traffic_entropy`.
- **Kernel Callback Unhooking / Snitch-Killer** (`tools/byovd_module.py`):
  `KernelCallbackUnhooker` enumerates EDR callbacks in
  `PspCreateProcessNotifyRoutine` / thread / load-image / `CmRegisterCallback`
  and neutralises them (nop / null / redirect); exposed via
  `BYOVDModule.unhook_kernel_callbacks()`.
- **API Sequence Spoofing** (`evasion/api_sequence_spoofing.py`):
  `APISequenceSpoofer` interleaves beacon API calls with benign svchost /
  explorer "heartbeat" chaff to break behavioural injection n-grams; wired
  into `BehavioralMimicryEngine.plan_api_sequence()` / `score_api_sequence()`.
- **Anti-Forensics Rotation** (`evasion/anti_forensics_rotation.py`):
  `AntiForensicsRotator` rotates beacon ID + all in-memory keys every 24h,
  securely wipes old key material, and emits a signed HMAC re-enrollment
  envelope; keys held in mutable `bytearray`s in `TransientNetworkCrypto` /
  `TaskCrypto` for in-place wipe.
- **Fileless WebShell** (`evasion/fileless_webshell.py`): `FastCGIInjection`
  performs an in-memory PHP-FPM webshell over FastCGI by setting
  `auto_prepend_file = php://input` + `allow_url_include = On`; the request
  body is executed in memory with no on-disk artifact. `generate_ghost_shell()`
  returns a self-decrypting (AES-256-GCM) payload delivered as the POST body.
- **In-Request Data Exfiltration** (`evasion/in_request_exfil.py`):
  `ProtocolExfil` smuggles loot inside benign WebSocket frames (with ping/pong
  heartbeat chaff) or across HTTP/2 streams hidden in `x-trace` trailers,
  defeating "Outbound Data Anomaly" detection. Lossless exfiltrate/recover
  round-trips plus raw frame encode/decode for the socket layer.

### Changed
- Bumped version to 2.6.0 ("The Ghost Protocol") in README and CHANGELOG.

- Cloud Redirector + High-Reputation Egress module (`tools/cloud/redirector.py`) with AWS CloudFront, Azure Front Door, and Cloudflare Worker IaC templates
- Adaptive Timing module (`evasion/adaptive_timing.py`) with Gaussian, Fibonacci, and SIEM-aware profiles
- Volume Obfuscation module (`evasion/volume_obfuscation.py`) for exfiltration shaping and channel rate limiting
- BYOVD + Kernel-level persistence research module (`evasion/byovd_kernel_persistence.py`) with RTCore64.sys IOCTL interface and EDR killer
- Automated ATT&CK Mapping (`tools/attack_mapper.py`) with technique coverage and heatmap data
- Report Generator (`tools/report_generator.py`) with HTML and PDF stub output
- Multi-operator Team Server (`c2/team_server.py`) for SocketIO-based collaboration
- GitHub Actions CI/CD activation (test, lint, typecheck, docker build)
- MIT License
- Repository description and topics
- CONTRIBUTING.md and CHANGELOG.md
- Native Rust agent scaffold (`agents/native/`) with stageless reflective loader, beacon, and Windows syscall stubs
- Ekko/Gargoyle-style ROP sleepmask (`evasion/sleep_masking.py`) with gadget finder, ROP chain builder, and NtProtectVirtualMemory via ROP
- Halo's Gate / Tartarus Gate syscall resolution (no disk I/O, no plaintext strings)
- Indirect syscall trampoline via clean ntdll `syscall; ret` gadgets
- Variadic stack-aware syscall support (4-8 arguments)
- WinHTTP transport with Edge User-Agent and forced TLS 1.2/1.3
- PE morphing engine: opcode-boundary aware metamorphic mutations (size-preserving)
- Reflective loader with PPID spoofing and BlockDLLs mitigation bypass
- Dynamic ntoskrnl base resolution via LSTAR MSR backward scan
- Steganographic LSB PNG exfiltration pipeline (`tools/stego_exfil.py`)
- JA4 fingerprint validation for C2 traffic (`tools/ja4_validator.py`)
- Purple Team control panel with JA4 verification (`cyberapp/routes/purple_team.py`)

### Changed
- Strengthened README with badges, overview, feature table, Quick Start demo, and detailed C2/Evasion sections
- Trimmed duplicate ELITE_*, PRO_*, WMI_*, PHISHING_* markdown files from repo root
- Updated `pyproject.toml` with description, keywords, classifiers, license, and authors

### Fixed
- Cleaned stray root files (`2`, `3`, `ss`, `List[Dict]_`, `flask_test_app.py`, `sitecustomize.py`)
- Fixed IRP preemption to use kernel-mode no-op stubs (SMEP/SMAP safe)
- Fixed syscall6 stack spill for correct shadow space alignment
- Fixed Ekko APC wake path to use alertable NtDelayExecution
- Fixed PE morphing to use 1-byte alignment-safe instruction swaps
- Fixed reflective loader to eliminate RWX page leaks
- Fixed PPID spoofing to resolve legitimate parent PID dynamically

## [2.5.0] - 2026-02-02

### Added
- Evasion engine expansion (AMSI/ETW bypass, indirect syscalls, process injection masterclass)
- C2 implant framework with blockchain (ETH/BTC) and IPFS channels
- Cloud pivot modules (Azure AD, AWS IMDS, GCP metadata)
- Behavioral mimicry and AI adversarial evasion
