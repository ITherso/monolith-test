# Changelog

## [Unreleased]

### Added
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
