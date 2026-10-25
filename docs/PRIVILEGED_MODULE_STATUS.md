# BYOVD, eBPF and Docker status repairs

These changes repair misleading results and the management interface. They do
not implement driver loading, EDR bypass, rootkit compilation or loading, process
hiding, payload execution, or container escape.

## BYOVD

The management route no longer changes `sys.path` or imports the operational
driver module by its bare name. Its previous catalog fields and several called
methods did not exist in that backend; those calls are not mapped to native
driver operations. A status descriptor is available without constructing a
driver module. Unsupported catalog/job and operational requests return HTTP 501
with explicit unavailable/not-executed flags.

## eBPF

A SHA-256 digest is not eBPF bytecode. The placeholder compiler now fails
explicitly instead of returning a digest as a compiled program. The management
routes do not construct a global rootkit instance or probe the local kernel at
import time. Unavailable operations return HTTP 501 before processing requests
or invoking a generator. Descriptors and counters do not present requested
targets as evidence of loading, attachment, or hiding.

## Docker

The inspected escape method previously reported success and host/root access
while `payload_executed` was false. Unexecuted results now keep all execution and
access flags false. Status does not treat an inspection result outside a container
as a detected container or count historical unexecuted results as confirmed
escapes. Counts based on supplied result flags remain recorded assertions, not
independent evidence of host access. Management actions fail explicitly before local inspection or payload
generation; opening the panel does not start a local detection request.

## Interface and validation limits

Existing page and API URLs are retained. Controls for unavailable features remain
visible and disabled, with an explanation. Status requests read metadata only;
they do not submit credentials or start privileged actions. Error and status text
is rendered as text. The existing admin policy and host entry-point stops remain
in force.

Tests use isolated Flask handlers, supplied records, extracted definitions and
inert dependencies. Operational tools, native libraries, drivers, the Docker
daemon, eBPF loaders and generated scripts are never imported or executed. These
tests validate failure reporting, not the operational modules or a live install.
Standalone legacy entry points and unrelated native implementations remain
outside this scope. See [the CI scope](CI_SCOPE.md).
