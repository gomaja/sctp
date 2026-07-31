Stream Control Transmission Protocol (SCTP)
----

A Go binding for the Linux kernel's SCTP stack, forked from
[ishidawataru/sctp](https://github.com/ishidawataru/sctp).

This package does not implement SCTP. Chunk handling, association setup,
retransmission, congestion control, path management and checksums are all the
kernel's; what is here is the socket API around them — `net.Conn` and
`net.Listener` implementations, the `sctp_*` socket options, ancillary data, and
the notifications the kernel delivers on the data stream.

Installing
----

The module path still declares the upstream repository, so `go get` on this fork
does not resolve on its own. Until that changes, consumers need a `replace`:

```
require github.com/ishidawataru/sctp v0.0.0

replace github.com/ishidawataru/sctp => github.com/gomaja/sctp master-gomaja
```

Platforms
----

SCTP exists on `linux` only, and this package's implementation additionally
excludes `linux/386`, where the `syscall` package does not define the socket
option syscalls it needs. On every other target with a real `syscall` package —
the BSDs, darwin, windows, solaris, illumos, aix, android — the package still
compiles, and the entry points that need a socket return `ErrUnsupported`, which
wraps `errors.ErrUnsupported`:

```go
if errors.Is(err, errors.ErrUnsupported) {
        // no SCTP on this platform
}
```

Two qualifications, both measured rather than assumed.

`plan9`, `js/wasm` and `wasip1/wasm` do **not** compile: their `syscall`
packages have no `RawSockaddrInet4`, which address marshalling needs. They have
no sockets to speak of either, so this is a statement of scope rather than a
plan.

And not every entry point is socket-bound. `ResolveSCTPAddr` and the deadline
setters are pure Go, compile everywhere, and do their ordinary job — so the
`errors.Is` gate above never trips for them. It applies to the calls that would
have to reach the kernel.

`TestCrossCompiles` builds the package for each target this promise covers, so a
non-portable symbol in shared code fails a test rather than a consumer's build.

Examples
----

See `example/sctp.go`

```go
$ cd example
$ go build
$ # run example SCTP server
$ ./example -server -port 1000 -ip 10.10.0.1,10.20.0.1
$ # run example SCTP client
$ ./example -port 1000 -ip 10.10.0.1,10.20.0.1
```

Reading messages
----

SCTP is message-oriented, so a read returns either a whole message or part of
one, and `SCTPRead` gives no way to tell those apart — a message larger than the
buffer is split, and the remainder arrives looking like a fresh message. Use
either

- `ReadMsg`, which reassembles a whole message, or
- `SCTPReadFlags`, testing the returned flags for `MSG_EOR`.

`SCTPReadFlags` also reports `MSG_NOTIFICATION`, which distinguishes an event
from application data. `ReadMsg` skips notifications, since it returns messages.

Testing
----

The socket-backed tests need a real SCTP stack, so they run on Linux only. The
harness that sets one up — extra loopback addresses for the multi-homing tests,
`net.sctp.auth_enable` for the AUTH tests, a blackhole route for the
retransmission tests — is `testdata/run-tests.sh`, and it wants a privileged
container:

```
$ docker build -t sctp-test -f testdata/Dockerfile .
$ docker run --rm --privileged -v "$PWD:/src" -w /src sctp-test \
        bash testdata/run-tests.sh ./... -count=1
```

`testdata/README.md` records what each test is for and what was measured to
justify it.
