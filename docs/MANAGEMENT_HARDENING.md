# Management safety and compatibility changes

This patch addresses management-panel vulnerabilities, misleading demonstration
results, and generic schema/container configuration defects. It does not add or
repair C2, payload, evasion, or real scanning functionality.

The later [host-safety stop](HOST_SAFETY.md) intentionally blocks operational
startup on Windows and WSL and disables real local atomic-test execution.

## Accounts and sessions

- Existing `ADMIN_PASS`, `ANALYST_PASS`, and `FLASK_SECRET_KEY` environment or
  project `.env` values take precedence. Other `.env` configuration continues to
  populate the process environment; explicit environment values win.
- Missing values are generated once in `instance/security.json`. Keep this private,
  persist it across deployments, and back it up securely. It is already excluded
  from Git by the `instance/` rule. On Windows, restrict its inherited filesystem
  permissions to the service account.
- There is no public default password or development signing-key fallback.
  A configured public development signing key is rejected with a clear error.
  Existing explicitly configured weak passwords are preserved for compatibility;
  replace them with strong passwords.
- Login still uses form fields `user` and `pass` and retains admin/analyst roles.
  The unsafe SQL fallback that promoted arbitrary database rows to admin is gone.
  Successful and failed login attempts clear the previous session.
- Existing sessions must log in again when the old public signing key is replaced.
  HTTP-only cookies and SameSite=Lax are enabled. For HTTPS, configure
  `SESSION_COOKIE_SECURE=true`.
- Passwords are no longer printed in the CLI startup banner. Inspect your private
  configuration or generated file locally when recovering initial credentials.

## Deliberate behavior changes

- The management app no longer imports or registers `vulnerable` and `api_vuln`
  training blueprints. Their URLs return 404. No shared-process opt-in is provided.
  The debug demonstration also redacts environment and filesystem information.
- Audit-log database values are escaped before rendering HTML.
- `--web-app-scan` remains an offline example-report command. Console and
  JSON/HTML/CSV outputs label simulations and report zero verified findings.
  No actual scan is performed by this command.
- Experimental quantum APIs and UI make no post-quantum security guarantee.
  The unimplemented signature verifier rejects all signatures, and `/quantum/verify`
  returns HTTP 501 with `valid=false` and `verification_supported=false`.
- `/health` and the existing orchestration health URL report HTTP 503 / `DEGRADED`
  when a blueprint fails to load/register. They do not certify production readiness
  or validate external integrations. The app is no longer marked production-ready.
- The CLI development debugger is disabled and startup/schema failures propagate.

## Schema and container compatibility

The Compose public port remains 5000; its internal mapping is now 8080, matching
the existing CLI listener and image healthcheck. This alignment was checked
statically; the container and complete application were not started.

Migration `0006_merge_schema_heads` merges the two existing revision branches.
The earlier extended migration no longer adds or drops `source_host`, which belongs
to revision 0003. Fresh schemas, upgrades from either branch, repeated upgrades,
and preservation of existing sample rows were checked in temporary SQLite files.
Migration failures are no longer silently treated as success.

No existing user database was supplied or changed. A database created directly by
`init_db.py` without Alembic version metadata may need a separately reviewed
baseline plan; do not blindly stamp a revision or run a downgrade against it.

## Focused verification

The isolated regression suite uses inert blueprint replacements, temporary
SQLite databases, and sample reports. It does not start the full application or
exercise operational attack modules:

```text
python -m pytest tests/test_host_safety.py tests/test_management_security.py tests/test_audit_security.py tests/test_installation_regressions.py tests/test_simulation_contract.py tests/test_vulnerable.py -q
```

The previous training-route tests are replaced by tests requiring those routes to
remain unavailable in the management app. The former positive assertion for the
demo signature verifier now expects safe rejection.

The complete legacy suite and Docker runtime were not validated. During local
inspection Windows Defender acted on several source files; none were restored,
and those antivirus removals are excluded from the patch. This prevents claiming
that every feature in the local checkout is operational.
