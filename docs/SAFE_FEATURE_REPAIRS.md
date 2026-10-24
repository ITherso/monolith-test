# Safe feature repairs and remaining limits

These changes repair reporting, release metadata, passive log analysis, and the
management inventory. They do not validate the full application or operational
modules. The Windows/WSL host stops and disabled real atomic executor remain in
place; see [host safety](HOST_SAFETY.md) and [CI scope](CI_SCOPE.md).

## PDF password protection

`cyberapp/report_security.py` replaces the former encryption placeholder with
AES-256 through `pypdf[crypto]`. It stages encrypted output, verifies the requested
password, algorithm and page count, then replaces the destination atomically.
Normal encryption failures leave the original file unchanged.

`PDFGenerator` renders in a temporary directory and publishes only after requested
protection succeeds. A conversion or encryption failure returns failure and
removes staged files; an existing destination survives. `ReportGenerator` now
propagates that failure rather than claiming a PDF path and overall success.
When `encrypt_pdf=True`, an empty or non-string `pdf_password` fails before PDF
rendering. Explicit unencrypted PDF exports retain their existing contract.

The renderer still requires the existing Pandoc/PDF-engine dependencies. Tests use
real PDF fixtures for encryption and mock the external converter. They do not
confirm an installed renderer or end-to-end HTML-to-PDF conversion. Temporary
cleanup is not secure disk erasure or a guarantee against abrupt power loss.

Report summaries now disclose that they use deterministic templates and supplied
statistics. The legacy `AISummaryGenerator` and configuration names remain for
compatibility; this summary path does not call an AI model.

## Release metadata checking

`cyberapp/release_updates.py` reads only
`https://api.github.com/repos/ITherso/monolith-test/releases/latest` with a timeout
and response-size limit. Its current version is `0.1.0`, matching `pyproject.toml`.
Numeric version comparison avoids treating an older release as an upgrade. Draft,
prerelease, unpublished, unsupported-tag and malformed responses are handled
separately from network and HTTP failures.

The return contract keeps `update_available` and adds a `status`:

| Status | Meaning |
| --- | --- |
| `update_available` | Published stable version is newer. |
| `up_to_date` | Versions compare equal. |
| `current_newer` | The current version is newer. |
| `no_release` | The endpoint returned 404; no published release was found there. |
| `no_published_release` | Metadata describes a draft, prerelease, or unpublished item. |
| `unsupported_version` | A version is outside the supported stable numeric format. |
| `invalid_response` | Metadata is malformed or too large. |
| `http_error` / `unavailable` | The check failed; this is not an up-to-date result. |

Release and asset URLs are metadata only: this helper does not download or install
files. `AutoUpdater.check_for_updates()` delegates to it. The separate legacy
`update_payloads()` method is unchanged and outside the verified scope. Tests mock
HTTP responses and do not verify a live repository release.

## Passive JSONL event analysis

The old Threat Hunter sleep loop is replaced with analysis of an explicitly
supplied regular JSONL file. A separate trusted producer must provide events.
There is no OS-event collection, packet capture, process execution, automatic
removal, or system configuration change.

Set `MONOLITH_EVENT_LOG` to the supplied file for the existing wrapper or the
authenticated preview routes. The wrapper also accepts an explicit `event_log`.
Without a configured source it fails clearly instead of claiming activity. Its
legacy `interface` argument does not enable packet capture.

Example input, one JSON object per newline-terminated record:

```jsonl
{"timestamp":"2026-10-24T10:00:00Z","process_name":"calc.exe","network_destination":"example.invalid"}
{"timestamp":"2026-10-24T10:01:00Z","action":"persistence_created"}
{"timestamp":"2026-10-24T10:02:00Z","action":"security_configuration_changed","setting":"real_time_protection","enabled":false}
```

These recorded conditions produce findings for human review. Each finding carries
`evidence_type=supplied_log_event` and `compromise_confirmed=false`; a finding is
not proof of infection. Ordinary events do not produce findings.

The reader commits only newline-terminated records, skips malformed or deeply
nested JSON, and resumes after append, file replacement, or detected truncation.
It limits a record to 1 MiB and a poll to 4 MiB / 1000 records. Oversized records
remain in discard mode across polls until their newline. The wrapper retains at
most 1000 findings. UNC paths and nonregular files are rejected; these checks do
not prove that storage is local or provide a filesystem sandbox.

GET `/threathunter/events` returns a synchronous bounded preview from the beginning
of the configured file. The legacy `/threathunter/start` path is an alias. Neither
starts a daemon or returns the former nonexistent port-5001 dashboard. The JSON
includes `status=analyzed`, processed/invalid counts, findings, and `partial` when
unread bytes remain. A partial preview is not a complete log scan. Every request
starts again at the beginning; query parameters cannot select a file. Missing or
unreadable configuration returns an error without exposing the configured path.

## Feature inventory

Authenticated GET `/feature-status` and `/api/feature-status` provide the same
read-only source/test inventory. The dashboard links to the page. Statuses
distinguish verified isolated management contracts, simulations, host safety
stops, incomplete paths, external configuration needs, and unverified features.
This representative inventory performs no live probes and does not certify
production readiness or completeness.

## Validation

The dedicated management suite tests real PDF encryption, mocked release HTTP,
temporary event-file ingestion, authenticated isolated Flask routes, existing
host stops, and prior management contracts. It does not start the application,
invoke external converters, run operational modules, or establish that a personal
computer is free of pre-existing persistence. FIFO rejection is exercised only
where the operating system provides FIFOs.
