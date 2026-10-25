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
Audit history, offline analysis, PDF downloads and passive JSONL review remain
admin-only. The scan detail reports both returned and total row counts so its
100-row per-category bound cannot look complete. Audit history uses bounded,
ID-based pagination.

The passive review page accepts at most 1 MiB of supplied JSONL and reviews the
first 1000 records in memory. It does not collect operating-system events or
capture traffic. PDF downloads are generated in a temporary directory from the
first 20 stored rows per category and report both returned and total row counts;
admins may request an AES-256 password-protected copy and the password is not
stored. The operational report generator is not imported.
Status and record APIs return `Cache-Control: no-store`. Stored text is escaped,
wrong-typed database fields fail closed, and database errors omit paths and
exception details.

This mode is a management surface, not an isolation boundary. It does not enable
or validate scanners, listeners, payload delivery, persistence, evasion, driver
access, eBPF loading or container escape.
