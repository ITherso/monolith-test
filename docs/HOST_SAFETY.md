# Local-host safety stop

This update prioritizes protecting the operator's Windows computer. The application
is intentionally unavailable through its protected operational entry points on
Windows, WSL, Cygwin, and MSYS. There is no environment-variable or CLI override.

## Source findings

`tools/purple_team_validator.py` contains atomic-test command strings that launch
Calculator and can create Run-key, Startup, scheduled-task, or service persistence.
Its original real executor ran commands on the local machine. The campaign's
`target_environment` is descriptive metadata, not a remote execution boundary.

Normal construction used `safe_mode=True` and simulation, so the presence of these
strings does not establish that they ran. The supplied source alone cannot identify
the exact trigger for a previously observed Calculator launch.

The atomic tests define cleanup-command strings but do not execute them. They
therefore do not provide an automatic rollback guarantee if real execution occurs.
Do not run the project's cleanup routines as a generic removal tool: other cleanup
paths contain broad operations that can affect unrelated data.

The calculator-named helpers in `agents/memory_dll_injector.py` and
`cybermodules/memory_dll_loader.py` largely construct simulated results or script
text. The `/home/kali/Desktop` strings examined in demos modify Python's import
search path; they do not themselves copy files to the Windows Desktop. These
distinctions do not invalidate a reported real Calculator process; they limit what
can be attributed to the inspected code.

## Protective changes

- `cyberapp.host_safety.enforce_host_safety()` rejects Windows and Windows-hosted
  WSL/Cygwin/MSYS before operational imports.
- The stop is applied to `cyber.py`, `wsgi.py`, app import, CLI execution, route and
  worker packages, and the `agents`, `c2`, `cybermodules`, `evasion`, `monolith`,
  `scripts`, and `tools` package imports.
- The Purple Team script has its own early stop. Its real execution method now
  unconditionally fails, including direct calls that try to disable safe mode.
- The previous removal of vulnerable management routes is retained.

These are source-level protective stops. They are not OS isolation, do not cover
every standalone file or native binary, and do not make a container with host
mounts safe. Do not execute individual scripts or generated payloads on the host.
They also do not remove pre-existing persistence or repair a compromised system.

## Verification and host observations

Guard tests use a restricted import hook which prevents feature modules from being
loaded even if guard ordering regresses. The local-command method is extracted
from its AST and tested independently; no operational module is imported and no
shell command is launched. The focused suite, including prior management fixes,
passes 140 tests and 3 subtests.

Read-only checks on the available Windows machine found no matching Calculator or
Python processes at inspection time, and no matching project/known test indicators
in checked Run/RunOnce keys, scheduled tasks, services, or WMI consumers. Checked
Startup folders contained only desktop.ini. The System32 Calculator file had a
valid Microsoft Windows signature. These are limited observations, not a clean-bill
of-health or a forensic reconstruction of a prior event.

Defender recorded successful actions against source files
`evasion/amsi_bypass.py`, `evasion/web_shell_persistence.py`, and
`tools/aws_lambda_persistence.py`. These were not restored or executed. Their local
removal is excluded from the patch. An antivirus finding on source is not proof
that the code executed or established persistence.
