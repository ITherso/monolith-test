# Management-only mode

MONOLITH now has a separate local management entry point for reviewing existing
records, status, audit history, feature inventory and offline vulnerability
analysis. It does not import the operational application factory, C2 modules,
payload generators, evasion packages or privileged host tooling.

After installing the normal Python dependencies, start it from the repository:

```text
python -m cyberapp.management_cli
```

The listener is restricted to numeric loopback addresses `127.0.0.1` or `::1`. The default URL
is `http://127.0.0.1:8080`. On first start the command upgrades the selected
SQLite database and generates persistent management credentials when explicit
credentials are absent. Generated values are stored in ignored
`instance/security.json`; configured environment or `.env` values continue to
take precedence.

Use `MONOLITH_DATABASE` or `--database` to select an existing SQLite file. The
management application passes that path to both migrations and all request-time
database connections, so it does not silently read a different working-directory
database.

Analysts can read the dashboard, feature inventory and stored scan records.
Audit history and offline analysis remain admin-only. The status and record APIs
are GET-only and return `Cache-Control: no-store`. Stored text is escaped before
HTML rendering, query output is bounded, and database errors are reported without
returning paths or exception details.

This mode is a management surface, not an isolation boundary. It does not enable
or validate scanners, listeners, payload delivery, persistence, evasion, driver
access, eBPF loading or container escape.
