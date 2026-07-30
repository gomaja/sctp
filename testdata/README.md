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

**Three kernel behaviours differ from what RFC 6458 describes**, each measured
with a C probe before the option was bound:

| Option | RFC says | Linux does |
|---|---|---|
| `SCTP_FRAGMENT_INTERLEAVE` | levels other than 0/1/2 "return an error" | accepts level 3 silently — so `SetFragmentInterleave` validates in Go |
| `SCTP_FRAGMENT_INTERLEAVE` level 2 | applies to one-to-many sockets | accepted on one-to-one but reads back as level 1; the test asserts the cap |
| `SCTP_REUSE_PORT` | set it before bind | **EFAULT** on a bound or connected socket rather than being ignored |

`SCTP_MAX_BURST` defaults to 4, as §8.1.24 documents. Its `int` and
`sctp_assoc_value` forms are genuinely interchangeable on a one-to-one socket
(same readback, same reported length, `assoc_id` ignored), which is why a
mutation swapping them survives — recorded rather than papered over.

**The read path accepts both ancillary-data forms.** RFC 6458 §5.3.2 titles
`SCTP_SNDRCV` "DEPRECATED" in favour of `SCTP_SNDINFO`/`SCTP_RCVINFO`. Enabling
only `SCTP_RECVRCVINFO` used to lose the message's stream and PPID silently — the
kernel sent a cmsg type nothing recognised and `SCTPRead` returned a nil
`SndRcvInfo` with no error:

```
sndrcv   n=1 stream=3 ppid=7
rcvinfo  n=1 info=nil   <-- stream/ppid LOST
both     n=1 stream=3 ppid=7
```

`parseSndRcvInfo` now handles both, with `SCTP_SNDRCV` winning when both are
present so existing callers see unchanged bytes. `RcvInfo` orders its fields
differently from `SndRcvInfo` — `TSN` and `CumTSN` precede `Context` instead of
following it — so the conversion copies fields rather than reinterpreting memory,
and `TestRcvInfoAndSndRcvBothParsed` anchors `Context` against a known
`SetContext` value to catch a mapping slip that `Stream`/`PPID` alone would miss.

## Extension options: PR-SCTP, stream reconfiguration, SCTP-PF, AUTH

The sweep that closed out the RFC 6458 §8 list was done by diffing every
`#define SCTP_*` in `linux/sctp.h` against the constants referenced in the
package, rather than working from the RFC's own table — which is how the
RFC 7496, RFC 6525 and RFC 7829 families turned up at all. They are not in
RFC 6458.

`optprobe/` is the C program that measured each option before any Go was
written, and it earned its keep: **five of the results contradict what the
relevant RFC or the kernel header implies.**

```sh
docker run --rm --privileged -v "$PWD":/src -w /src sctp-test bash -c '
  modprobe sctp; gcc -O0 -o /tmp/optprobe testdata/optprobe/main.c && /tmp/optprobe
  gcc -O0 -o /tmp/shapes   testdata/optprobe/shapes.c   && /tmp/shapes
  gcc -O0 -o /tmp/reconfig testdata/optprobe/reconfig.c && /tmp/reconfig'
```

| Option | Expected from the spec/header | Linux does |
|---|---|---|
| `SCTP_PR_SUPPORTED` | on/off int (RFC 7496 §4.5) | **rejects a plain int with EINVAL**; needs `struct sctp_assoc_value`, which the header does not declare for it |
| `SCTP_RECONFIG_SUPPORTED` | on/off int (RFC 6525 §6.1) | same — `sctp_assoc_value` only |
| `SCTP_ENABLE_STREAM_RESET` | on/off mask (RFC 6525 §6.3) | same — `sctp_assoc_value` only |
| `SCTP_AUTO_ASCONF` | endpoint-level flag | **requires a bound socket**; EINVAL on a fresh one, the opposite of `SCTP_REUSE_PORT` |
| `SCTP_AUTH_*` | absent ⇒ unsupported | **EACCES**, not EOPNOTSUPP — the family is gated by `net.sctp.auth_enable`, which is `0` on a stock kernel |

**The two "supported" flags behave differently, and the reason is a sysctl.**
Both are negotiated in the INIT, but `net.sctp.prsctp_enable` defaults to `1`
while `net.sctp.reconf_enable` defaults to `0`. So:

```
=== SCTP_PR_SUPPORTED ===          === SCTP_RECONFIG_SUPPORTED ===
listener=0 client=0 : cli=1 srv=1  listener=0 client=0 : cli=0 srv=0
listener=0 client=1 : cli=1 srv=1  listener=0 client=1 : cli=0 srv=0
listener=1 client=0 : cli=1 srv=1  listener=1 client=0 : cli=0 srv=0
listener=1 client=1 : cli=1 srv=1  listener=1 client=1 : cli=1 srv=1
```

`PrSupported` therefore reports `true` on an association where *neither* end
touched the option — a caller must not read it as "the peer asked for partial
reliability". The one direction that does have an effect is the opt-out:
disabling on either end suppresses the extension for both, which is what
`TestPrSupportedFollowsSysctl` pins, and is the only observable difference
between a working `SetPrSupported` and one that ignores its argument.

`SCTP_RECONFIG_SUPPORTED` has the trap: a post-connect `set` **returns success
and changes nothing**, because the extension can only be negotiated in the INIT.
`reconfig.c` separates that from the alternative explanations by running all
three enable combinations; `ReconfigSupported`'s doc comment says so, and
`TestReconfigSupportedNegotiates` covers all three.

**`SCTP_PEER_AUTH_CHUNKS` reports EINVAL regardless of `auth_enable`**, while
every sibling option tracks the sysctl. The association check runs first:

```
--- auth_enable=0 ---                --- auth_enable=1 ---
PEER_AUTH_CHUNKS:  Invalid argument  PEER_AUTH_CHUNKS:  Invalid argument
LOCAL_AUTH_CHUNKS: Permission denied LOCAL_AUTH_CHUNKS: ok
HMAC_IDENT:        Permission denied HMAC_IDENT:        ok
```

So the errno from that one option cannot be used to tell whether AUTH is
available. `TestAuthEnabledRoundTrip` skips unless the sysctl is on rather than
setting it — a global change is not a test's business:

```sh
echo 1 > /proc/sys/net/sctp/auth_enable
```

**Two structs need explicit padding that C gets from alignment.**
`sctp_paddrthlds` and `sctp_assoc_stats` embed a `sockaddr_storage`, which
contains a `long` and so aligns to 8 — putting the address at offset **8, not
4**, and rounding `sctp_paddrthlds` up from 140 to 144. A Go struct declared
field-for-field is silently wrong on both counts: every field after the
association id shifts by four and the option length comes up short.

`sctp_paddrinfo` is the counterexample that makes this easy to get wrong — it is
declared `__attribute__((packed, aligned(4)))`, so *its* address really is at
offset 4. Same shape, different answer; the offsets have to be measured per
struct:

```
sctp_paddrthlds  size=144 assoc@0 address@8  pathmaxrxt@136 pathpfthld@138
sctp_assoc_stats size=256 assoc@0 obs_rto@8  maxrto@136     isacks@144
sctp_paddrinfo   size=152 assoc@0 address@4  state@132      cwnd@136
sctp_sndinfo     size=16  sid@0 flags@2 ppid@4 context@8 assoc@12
sctp_default_prinfo size=12  sctp_prstatus size=24  sctp_authkeyid size=8
```

`sctp_authkeyid` is 6 bytes as declared but the kernel wants 8; Go's own
alignment already produces 8, so the explicit pad there documents the C layout
rather than causing the size. Same for `sctp_default_prinfo`. That is why
mutations removing those two pads survive — verified by measuring `unsafe.Sizeof`
both ways, not assumed.

**Where the kernel validates and where it does not** is inconsistent enough that
each option had to be checked, since it decides whether a Go-side guard is
needed:

| Option | Bad input | Result |
|---|---|---|
| `SCTP_DEFAULT_PRINFO` | policy `0x40` | EINVAL — kernel validates, so no Go guard |
| `SCTP_DEFAULT_SNDINFO` | 12-byte option | EINVAL — so `SndInfo`'s size must be exact |
| `SCTP_ENABLE_STREAM_RESET` | undefined mask bit | silently masked away — **Go guard added** |
| `SCTP_FRAGMENT_INTERLEAVE` | level 3 | silently accepted — Go guard (above) |
| `SCTP_AUTH_KEY` | `keylength` past the buffer | EINVAL — no over-read |

**`SCTP_ADD_STREAMS` was nearly written off on a probe artefact.** The first run
reported `ENOPROTOOPT`, which reads as "option not supported", and the option was
about to be documented as unusable. The probe had set `SCTP_RECONFIG_SUPPORTED`
*after* connect, so the extension was never negotiated. Setting it on both ends
before connect, with `SCTPEnableChangeAssocReq` in the mask:

```
reconfig negotiated cli=1
stream reset mask cli=0x7
ADD_STREAMS: ok
streams in/out before 10/10, after 12/12
```

It works, and the widened count is readable straight after the call over
loopback — so `TestAddStreams` asserts the new stream count rather than only the
absence of an error, and covers the `ENOPROTOOPT` path too so the two cannot be
confused again.

Not bound, with reasons: `SCTP_GET_ASSOC_NUMBER` and `SCTP_GET_ASSOC_ID_LIST`
return EOPNOTSUPP on the one-to-one sockets this package creates;
`SCTP_RESET_STREAMS` takes a variable-length stream list and returned EINVAL for
every fixed-size form tried, so it needs its own investigation;
`SCTP_AUTH_KEY`/`SCTP_AUTH_CHUNK`/`SCTP_AUTH_DELETE_KEY`/
`SCTP_AUTH_DEACTIVATE_KEY` take variable-length keys and are set-only, so they
want an API design rather than an accessor pair.

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

`TestAbortReleasesFdZero` failed about four runs in twenty while passing fifteen
in fifteen on its own. The test was wrong, not the code: it asked whether fd 0
was open after `Abort` and called an open descriptor a leak. The kernel hands out
the lowest free descriptor and the test's own accept loop runs concurrently, so a
socket created in the instant after `Abort` takes fd 0 back.

A single-threaded C program doing the same accept-then-abort sequence shows it
without any concurrency at all:

```
after abort: fcntl(0,F_GETFD) = 0 (errno=0)
  fd 0 IS a socket bound to port 48556 -> re-claimed, not leaked
```

It now records the association's local port before `Abort` and compares
afterwards, so it asks whether *this* association survived rather than whether
the number is in use. The assertion got stronger, not weaker: removing the close
from `abortSctpSocket` fails it with `fd 0 is still the aborted association
(local port 42491); the descriptor leaked`.

The general lesson is the same one the finalizer bug taught — a descriptor number
identifies nothing once it has been released. Compare the resource, not the
number.

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

### Residual rate, measured against a baseline

`TestStreams` still fails occasionally as part of the full suite, and the rate is
low enough that small samples mislead. A twenty-run batch showed 19/20 on a
working tree against 20/20 on a clean baseline, which invites the conclusion that
the working tree caused it. Sixty runs of each, in parallel, say otherwise:

```
working tree  60 pass  0 fail
baseline      58 pass  2 fail   (TestStreams once,
                                 TestNotificationHandlerAssignmentOnDialing once)
```

So the residual is pre-existing, and at this rate twenty runs cannot separate one
tree from another — the earlier 19/20-versus-20/20 reading was sampling noise
pointing the wrong way. `TestStreams` alone passes 30/30, so it needs the rest of
the suite's concurrency to fail at all.

The rule this reinforces: never call a flake pre-existing or introduced without a
baseline measured at a sample size that could distinguish them. A single batch
that happens to favour one side is not evidence.

`TestNotificationHandlerAssignmentOnDialing` appearing here is new and has not
been investigated; it is recorded rather than left in a terminal scrollback.
