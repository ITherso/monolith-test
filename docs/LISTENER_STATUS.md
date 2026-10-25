# Listener failure reporting

The inspected C2 startup implementations do not contain a network listener
runtime. Changing a database status or an in-memory flag is not proof that a
socket is listening. This repair makes their failure explicit; it does not
implement or activate a command channel.

- `C2Server.start_listener()` returns `False` and keeps an existing listener
  record stopped. A missing record returns `False` without a status write.
- `WebC2Listener.start()` keeps `running=False`, logs the unavailable runtime,
  and returns `False`. Statistics expose `runtime_available=False`.
- The advanced start route returns HTTP 501 with `success=False`,
  `available=False`, and `running=False`, without constructing a server.
- Eight Web C2 routes retain their URLs but return HTTP 501 and
  `web_c2_backend_incomplete`: session listing, command dispatch, beacon
  registration, check-in, termination, template listing, beacon generation,
  and configuration. They do not construct a listener, parse command input,
  call missing methods, or delegate to similarly named operational methods.
- The Web C2 panel identifies the unavailable runtime. Failed start,
  registration, command, and removal responses cannot produce success messages.

Global admin authorization and host startup protection remain in place. Other
legacy C2 routes, overlapping route registrations, payload paths, server imports,
and session storage have not been validated or activated by this change.
Existing historical database records are not globally rewritten; the direct
framework start path corrects only the requested existing record.

The reviewed tests extract individual function definitions from source into inert
namespaces. They do not import the C2 modules or application, start threads or
sockets, run commands, or connect to a target. Passing these tests validates the
failure behavior only. See [the CI scope](CI_SCOPE.md).
