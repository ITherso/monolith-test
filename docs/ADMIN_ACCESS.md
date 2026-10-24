# Admin access policy

`cyberapp.authorization.install_admin_access_control()` installs a global Flask
request check before feature blueprints are registered. Every matched endpoint
requires an authenticated admin session unless it is an explicit public or
read-only management exception. New blueprints and direct application routes are
restricted by default; changing a URL prefix does not grant access.

This change restricts existing access. It does not activate C2, injection,
persistence, evasion, SocketIO, or other operational features. Windows/WSL and
local atomic execution stops remain independent and cannot be overridden by an
admin role. See [host safety](HOST_SAFETY.md).

## Identity and denial

The main login handler writes identity and role to the signed Flask session.
Authorization requires `logged_in` to be exactly `True`, a nonempty string user,
and role exactly `admin` for protected features. Request headers, query parameters,
form fields, and JSON fields cannot grant that role. Partial sessions are rejected.

An authenticated non-admin receives HTTP 403 before the protected handler or its
blueprint request callbacks run. JSON responses contain `admin_required`.
Unauthenticated API/action requests receive HTTP 401 with `login_required`;
unauthenticated browser page requests redirect to `/login`. Denial responses use
`Cache-Control: no-store`. Unmatched routes retain normal 404/405 behavior.

## Exceptions

Login, logout, application static files, and the existing health endpoint aliases
remain public. These exceptions do not authorize feature routes.

The following endpoints allow GET, HEAD, and OPTIONS for authenticated readers:

| Area | Reader endpoints |
| --- | --- |
| Dashboard | `dashboard.index` |
| Feature inventory | `feature_status.feature_status_page`, `feature_status.feature_status_api` |
| Passive log preview | `ops.start_threathunter` (both preview URL aliases) |
| Monitoring | `monitoring.scan_status`, `monitoring.metrics` |
| Existing scan results | `scans.scans_list`, `scans.scan_status`, `scans.details`, `scans.api_get_vulnerabilities`, `scans.api_get_scan_stats` |

Other methods on reader endpoints default to admin. All other matched handlers,
including C2 callbacks, payload generation, persistence/evasion routes, generic
tools, scan execution/deletion, report generation/download, and blockchain
publication, require admin. Download was not exempted because its existing path
can generate a missing report. Existing narrower checks such as admin-only audit
viewing still apply.

## Existing socket callbacks

The existing exploit shell event and browser collection connect/data/disconnect
callbacks are wrapped with `socket_admin_required`. It checks the current event
session before calling the original callback and returns `False` on denial.
No socket server or socket initialization was enabled by this change. Tests use
inert callbacks and inspect registration order without importing these modules.

The wrapper does not add server-side session revocation. If SocketIO is enabled
separately in future, its cookie-session snapshot may outlive an HTTP logout;
immediate cross-connection revocation is not guaranteed by this check.

## Validation and limits

Isolated Flask tests cover unauthorized dispatch, exact roles, malformed sessions,
spoofed request inputs, reviewed reader access, HTTP methods, new/direct routes,
and inert admin handlers. Socket tests cover current-context checks; AST checks
verify the factory ordering and four existing callback guards.

This is a request authorization boundary, not an OS sandbox. It does not isolate
existing module import-time behavior or standalone CLI/function calls. Existing
operational GET/CSRF behavior and session storage are not redesigned here. Green
management CI does not establish that operational features work or are safe to run.
