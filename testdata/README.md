# Local SCTP test harness

Docker-based harness for exercising this package against a real Linux SCTP
stack. It is for local testing only — nothing here is imported by the module.

macOS has no SCTP stack, so these tests cannot run on the host.

## Build

```sh
docker build -t sctp-test -f testdata/Dockerfile testdata/
```

## Run the test suite

`--privileged` is needed to load the `sctp` kernel module.

```sh
docker run --rm --privileged -v "$PWD":/src -w /src sctp-test \
    bash testdata/run-tests.sh -count=1
```

Run the suite one container at a time. Several at once contend for cores and
make the timing-sensitive tests look far worse than they are.

## Truncation reproducer

`repro/` sends length-prefixed frames of increasing size through a 1500-byte
read buffer, mimicking a framed protocol such as M3UA.

```sh
docker run --rm --privileged -v "$PWD":/src -w /src sctp-test bash -c '
  cd testdata/repro
  printf "module repro\ngo 1.21\nrequire github.com/ishidawataru/sctp v0.0.0\nreplace github.com/ishidawataru/sctp => /src\n" > go.mod
  go mod tidy >/dev/null 2>&1
  go run .          # plain SCTPRead: messages over the buffer are lost
  go run . -fixed   # ReadMsg: all messages arrive intact
  rm -f go.mod go.sum'
```

With plain `SCTPRead`, messages of 1600 bytes and up are silently dropped and
the stream desynchronises — a following read parses payload bytes as a length
prefix. With `ReadMsg` every message arrives whole.

## Wire-level verification

Captures loopback SCTP with tshark while the reproducer runs, to confirm the
sender transmits every byte and that the loss is entirely receive-side.

```sh
docker run --rm --privileged --net=host -v "$PWD":/src -w /src sctp-test \
    bash testdata/tshark-verify.sh
```

It totals the DATA chunk payloads on the wire and compares them against what
was sent; the totals match even in the runs where messages are lost at the
API.

## Close-path wire verification

Confirms what each teardown puts on the wire: `Close` completing a SHUTDOWN
handshake, `Abort` sending an ABORT chunk, and `Close` against an
unresponsive peer falling back to ABORT rather than blocking for the full
grace period.

```sh
docker run --rm --privileged --net=host -v "$PWD":/src -w /src sctp-test \
    bash testdata/tshark-close.sh
```

Each mode runs on its own port so the capture can be split per association.
`closeprobe/` is the driver it builds.

## Notification wire verification

Confirms that the notifications `ParseNotification` decodes describe the
association teardown that actually happened on the wire, which in-process
assertions cannot show on their own.

```sh
docker run --rm --privileged --net=host -v "$PWD":/src -w /src sctp-test \
    bash testdata/tshark-notify.sh
```

Three cases run. Subscribed with a graceful close: SHUTDOWN, SHUTDOWN_ACK and
SHUTDOWN_COMPLETE on the wire, and SCTP_SHUTDOWN_EVENT plus
ASSOC_CHANGE(SHUTDOWN_COMP) at the API. Subscribed with an abort: an ABORT
chunk on the wire and ASSOC_CHANGE(COMM_LOST) at the API. Unsubscribed: the
same teardown chunks on the wire and no notifications at all.

The unsubscribed case is the one that gives the other two their meaning. A
build that emitted notifications unconditionally would pass the first two and
fail only this one.

`notifyprobe/` is the driver it builds.

### Truncation

The kernel truncates a notification to the caller's read buffer and drops the
remainder rather than queueing it. Reading with a 16 byte buffer delivers a 16
byte SCTP_ASSOC_CHANGE, four bytes short of the 20 byte event:

```
read buffer = 16 bytes; real kernel notifications:
  [0] type=0x8005 len=12    SHUTDOWN
  [1] type=0x8001 len=16    ASSOC_CHANGE, truncated from 20
  [2] type=0x150e len=4     fragment
```

`TestKernelTruncatesNotificationToReadBuffer` covers this against a real
kernel. Removing the length check in ParseNotification makes it panic with
`slice bounds out of range [:20] with capacity 16` inside the read path.

## Event subscription wire verification

Confirms that `SubscribeEvent` (the RFC 6458 §6.2.2 `SCTP_EVENT` option) changes
what the kernel delivers, rather than only what the option struct contains.

```sh
docker run --rm --privileged -v "$PWD":/src -w /src/testdata/eventprobe sctp-test bash -c '
  printf "module eventprobe\ngo 1.21\nrequire github.com/ishidawataru/sctp v0.0.0\nreplace github.com/ishidawataru/sctp => /src\n" > go.mod
  go mod tidy >/dev/null 2>&1
  go run .
  rm -f go.mod go.sum'
```

Three cases run against a real association, identical except for the
subscription:

```
subscribed:   notification=true  want=true  type=0x8001  ok
unsubscribed: notification=false want=false type=0x0000  ok
bulk:         notification=true  want=true  type=0x8001  ok
```

The unsubscribed case is what gives the other two meaning — a build that
delivered notifications unconditionally would pass the first and third and fail
only that one. Making `SubscribeEvent` a no-op turns the first case into
`MISMATCH` and exits non-zero while the other two stay correct.

## RFC conformance notes

Verified against RFC 6458 (Sockets API) and RFC 9260 (base protocol, which
obsoleted RFC 4960), each claim cross-checked against `linux/sctp.h` and a C
probe on a live kernel.

**Struct layouts all match the kernel.** `sctp_status`, `sctp_paddrinfo`,
`sctp_rtoinfo`, `sctp_assocparams`, `sctp_initmsg`, `sctp_assoc_value` and
`sctp_sndrcvinfo` agree on size and every field offset. `TestStructLayoutsMatchKernel`
pins this; `layoutprobe/` is the C program the numbers came from. The test earns
its place on field *reorders*, which keep the struct size identical and are
otherwise silent — the same class as the `sctp_pdapi_event` bug recorded above.

Re-run the probe when targeting a new kernel, and update the test if the numbers
move:

```sh
docker run --rm --privileged -v "$PWD":/src -w /src sctp-test bash -c '
  apt-get update -qq && apt-get install -y -qq libsctp-dev >/dev/null 2>&1
  gcc -o /tmp/lp /src/testdata/layoutprobe/main.c -lsctp && /tmp/lp'
```

```
sctp_paddrinfo size=152 assoc@0 addr@4 state@132 cwnd@136 srtt@140 rto@144 mtu@148
sctp_status size=176 assoc@0 state@4 rwnd@8 unack@12 pend@14 in@16 out@18 frag@20 prim@24
sctp_rtoinfo size=16  sctp_assocparams size=20  sctp_initmsg size=8
sctp_assoc_value size=8  sctp_sndrcvinfo size=32  sctp_event_subscribe size=14
```

The test asserts the Go side against these; it cannot detect a kernel that
changes its own layout.

**Two RFC-deprecated APIs are still in use.** RFC 6458 §6.2.2 deprecates
`SCTP_EVENTS`, and §5.3.2 titles `SCTP_SNDRCV` "DEPRECATED", directing callers
to `SCTP_SNDINFO`/`SCTP_RCVINFO`. `SubscribeEvent` now provides the `SCTP_EVENT`
replacement; `SCTPRead`/`SCTPWrite` still use `SCTP_SNDRCV`, and
`SetRecvRcvInfo`/`SetRecvNxtInfo` enable the modern ancillary data for callers
driving `recvmsg` themselves. That the option changes delivery rather than only
the flag was checked with a C `recvmsg` probe walking the control messages:
enabled, an `SCTP_RCVINFO` cmsg is present; disabled, it is absent.

**`SCTP_EVENT` and `SCTP_EVENTS` are not one state once an association exists.**
Measured, and contrary to the obvious assumption: on an unconnected socket a
per-event subscription reads back through the bulk struct, but on a connected
one it does not, because `AssocID` 0 scopes to the association while the bulk
option reads endpoint defaults. Both cases are pinned by tests so the
distinction cannot quietly become false.

**`sctp_event_subscribe` is 10 bytes here against the kernel's 14.** Linux adds
four events RFC 6458 does not define, so they are unreachable through that
struct. The short option length is safe, which was measured rather than assumed:
`setsockopt` accepts and applies it, and `getsockopt` writes only the first 10
bytes and leaves the caller's remaining buffer untouched.

**`EALREADY`/`EISCONN` are not in either RFC.** Zero occurrences across RFC 9260
and RFC 6458 — they are Linux behaviour, so the residual `SCTPConnect`
`EALREADY` gap needs the kernel source, not the specification.

Options present in RFC 6458 §8 but not yet bound: `SCTP_FRAGMENT_INTERLEAVE`,
`SCTP_PARTIAL_DELIVERY_POINT`, `SCTP_MAX_BURST`, `SCTP_CONTEXT`,
`SCTP_REUSE_PORT`, `SCTP_DEFAULT_SNDINFO`, `SCTP_AUTO_ASCONF`,
`SCTP_DEFAULT_PRINFO`, and the RFC 4895 `SCTP_AUTH_*` family. The
`SCTP_GET_ASSOC_*` options apply to one-to-many sockets, which this package does
not create.

## Address decoding

`SCTP_GET_LOCAL_ADDRS`, `SCTP_GET_PEER_ADDRS` and `SCTP_PRIMARY_ADDR` return a
packed array of sockaddrs, each sized by its own family: 16 bytes for
`AF_INET`, 28 for `AF_INET6`. The decoder used to read the family from the
first entry and stride the whole array by it.

Linux does not currently expose that. A C probe against the running kernel,
binding both `::1` and `127.0.0.1` to one socket with `sctp_bindx`, showed the
reply normalised to a single family:

```
RESULT: kernel ACCEPTS a mixed-family binding
addr_num = 2
  entry 0: family=10 (AF_INET6), stride=28
  entry 1: family=10 (AF_INET6), stride=28
```

So the fixed stride was correct in practice, and no live defect was
demonstrated. The decoder now reads the family per entry regardless, because
nothing in the interface guarantees a uniform reply, and a wrong stride
produces a wrong address rather than an error: an IPv6 address after an IPv4
one decodes as `0.0.0.0` and is returned to the caller as though it were real.

Two things came out of this that were live. Decoded addresses aliased the
kernel buffer, which for `SCTPGetPrimaryPeerAddr` is a stack local that goes
out of scope on return; they are copied now. And the address count from the
kernel was trusted as a walk bound with no reference to the buffer size.

`TestResolveFromRawAddr*` covers the decode, `TestKernelAddrsRoundTrip` covers
what the running kernel actually returns, and `FuzzResolveFromRawAddr` covers
arbitrary bytes. Note what the fuzzer does *not* cover: removing the bounds
checks and fuzzing for 90 seconds survives 4.3M executions, because an
over-read still lands inside the same Go allocation. The bounds are covered by
the unit tests, each confirmed by removing the check it guards.

## Test flakiness

`TestSCTPConcurrentAccept` used to fail about one run in four with
`# of failed Dials: 1`. `SCTP_SOCKOPT_CONNECTX3` reports `EISCONN` once the
handshake has completed, which under load happens before the call returns, and
`SCTPConnect` reported that as a failure for a socket that was connected and
writable. Fixed.

`TestStreams` used to fail as part of the full suite while passing on its own.
Three causes, found in that order:

The listen backlog was `syscall.SOMAXCONN`, a Go constant of 128, against a
kernel allowing 4096. This test opens exactly 128 clients, so it sat on the
limit and any association still pending from an earlier test pushed it over.
The listener answered the excess with ABORT and the clients reported
`connection refused`.

The test also mismanaged its own connections: the type assertion ran before
the error check, `sconn.Close` was deferred inside the accept loop instead of
per connection, the listener was never closed, and the accept loop treated the
`EINVAL` from a shut-down socket as fatal.

The backlog defect masked the rest, which is why fixing either alone measured
as noise. Together they took twelve failures in fifteen runs down to one and
two in two fifteen-run measurements — but not to zero.

The residual had nothing to do with `TestStreams`. `TestSCTPListenerNameFromFd`
passed a live listener's descriptor to `os.NewFile`, which takes ownership of
what it is given and closes it from a finalizer once the `*os.File` becomes
unreachable. That scheduled a close of a socket still in use, at a point
decided by the garbage collector, after the kernel had reused the number for
an unrelated socket. The failure therefore appeared in whichever test held
that descriptor when the collector ran — `TestStreams` losing its listener
mid-run, or `TestListenerCloseUnblocksAccept` getting `EBADF` from `Close`.

`TestListenerSurvivesGCAfterFileListener` forces collection and then dials the
listener, making it deterministic. Suite over twenty consecutive runs after
the fix: twenty passes.

The method matters as much as the fixes.

The backlog defect was invisible in the test output and in a capture of the
whole suite, where 1012 INIT chunks and 892 INIT_ACKs across ninety tests said
nothing. Filtering the capture to the one listener port under test gave it
immediately:

```
INIT      = 128
INIT_ACK  =  15
ABORT     = 121
```

The finalizer defect yielded to descriptor tracing rather than packet capture:
logging every acquisition and release showed a listener's descriptor going
invalid with no release recorded between, which rules out every path the
library itself controls and points outside it.

Three habits did the work. Run one measurement at a time and pair comparisons
against a baseline rather than running separate batches — several plausible
theories here died that way, and two candidate fixes measured no better than
baseline. Filter captures to the port that matters. When a symptom moves
between tests depending on timing, suspect a shared resource being released by
something other than its owner, and trace the resource rather than the test.
