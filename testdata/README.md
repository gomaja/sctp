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
and RFC 6458 — they are Linux behaviour, so the `SCTPConnect` `EALREADY` gap
needed the kernel source rather than the specification. It is now closed; see
below.

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

## The variable-length options, and a third precondition mistake

`SCTP_RESET_STREAMS` and the `SCTP_AUTH_*` key setters were both recorded as
blocked. Both were usable. `optprobe/varlen.c` is what settled it, and in both
cases the earlier attempt had got a precondition wrong rather than found a
limitation — the third time in this package that a missing precondition was
mistaken for a missing feature.

`SCTP_RESET_STREAMS` had **two** things wrong with the earlier attempt:

```
=== extension NOT negotiated ===
  all streams, bare struct                len= 8 -> Protocol not available
=== extension negotiated on both ends ===
  all streams, bare struct                len= 8 -> ok
  one stream, struct + its list entry     len=10 -> ok
  one stream, length excludes the list    len= 8 -> Invalid argument   <--
  flags INCOMING only                            -> ok
  flags OUTGOING only                            -> ok
  flags no flags                                 -> Invalid argument
```

The option length has to **cover the stream list**, not just the fixed header —
that is the EINVAL that looked like a refusal. And at least one direction flag is
required. `ResetStreams` takes a slice and computes the length from it, which is
why it does not expose the raw struct.

The AUTH family is fully usable once `net.sctp.auth_enable` is 1:

```
  key 1, 8 bytes, exact length            len= 16 -> ok
  keylength 200 but only 8 bytes present  len= 16 -> Invalid argument
  zero-length key (deactivates?)          len=  8 -> Invalid argument
  largest accepted key length = 8192
  DEACTIVATE_KEY(1) -> ok
  DELETE_KEY(1) after deactivate -> ok
  HMAC_IDENT set [SHA1] -> ok
  HMAC_IDENT set [2, unassigned] -> Operation not supported
```

The kernel validates `sca_keylength` against the option size, so a mismatch
cannot make it read past the buffer — worth knowing, because that check is what
the Go binding relies on. A zero-length key is refused rather than treated as a
deletion, which is a plausible thing for a caller to assume, so `SetAuthKey`
rejects it with a message naming `DeleteAuthKey`. Unassigned HMAC identifier 2 is
refused by the kernel, so `SetHmacIdent` needs no Go-side guard.

The active key cannot be deleted, which forces the rollover order: select a new
active key, deactivate the old one, then delete it. `TestAuthKeyManagement` walks
that sequence rather than testing each call in isolation.

### Byte-level tests for the hand-built buffers

Three of these accessors assemble their option as bytes, because the C structs end
in flexible arrays and a Go struct with a slice field would not be contiguous.
That puts them outside what `TestStructLayoutsMatchKernel` can pin, and one
mutation showed why a behavioural test is not enough:

**Writing the `sctp_hmacalgo` count as a `uint16` instead of a `uint32` survives
every socket-level test on amd64.** The buffer is zeroed by `make`, so the two
following bytes are already 0 and the `uint32` reads back correctly on a
little-endian host. On big-endian the count lands in the wrong half. No test
running on this kernel can catch it through behaviour.

So `buildResetStreams`, `buildAuthKey` and `buildHmacAlgo` are separate functions
asserted byte by byte against the offsets `offsetof()` reports:

```
sctp_reset_streams  size=8  assoc@0 flags@4 nstreams@6 list@8
sctp_authkey        size=8  assoc@0 keynum@4 keylen@6   key@8
sctp_hmacalgo       size=4  num@0 (u32)     idents@4
```

The flags/count pair in `sctp_reset_streams` and the keynumber/keylength pair in
`sctp_authkey` are adjacent `uint16`s in both cases, so a transposition produces a
buffer the kernel may still accept while doing the wrong thing.

## The send path: SCTP_SNDINFO

`SCTPWriteInfo` is the send-side counterpart to the `SCTP_RCVINFO` support on the
read path, emitting the `SCTP_SNDINFO` that RFC 6458 §5.3.2 directs callers to
instead of the "DEPRECATED" `SCTP_SNDRCV`. It optionally attaches `SCTP_PRINFO`
(per-message partial reliability) and `SCTP_AUTHINFO` (per-message key).

`SCTPWrite` is deliberately **unchanged** and still emits `SCTP_SNDRCV`, because
switching it would change the bytes on every existing caller's socket. The two
interoperate freely — the kernel accepts either, and even both in one `sendmsg`:

```
  sendmsg with SCTP_SNDINFO    -> ok
  sendmsg with SNDINFO+PRINFO  -> ok
  sendmsg with SNDRCV+SNDINFO  -> ACCEPTED
```

`TestSCTPWriteInfoInteropWithSCTPWrite` sends both ways on one association so a
caller can migrate one call site at a time.

Two details that are easy to get wrong:

**`struct sctp_prinfo` is 8 bytes, not 6.** A `__u16` followed by a `__u32` puts
the value at offset 4. Unlike the pads in `DefaultPrInfo` and `AuthKeyID` — which
Go's alignment would produce anyway — this one is load-bearing: without it Go
places `Value` at offset 2 and the policy value is read from the wrong place.

**The inter-cmsg alignment padding is observable in exactly one case.**
`CmsgSpace` equals `CmsgLen` for a 16-byte `SndInfo` and an 8-byte `PrInfo`, so a
send using only those passes whether or not the padding is emitted:

```
SndInfo  data=16 CmsgLen=32 CmsgSpace=32 pad=0
PrInfo   data= 8 CmsgLen=24 CmsgSpace=24 pad=0
AuthInfo data= 2 CmsgLen=18 CmsgSpace=24 pad=6
```

Only `AuthInfo` needs padding, and padding is only ever read when another control
message follows. That is why `SCTPWriteInfo` emits `AUTHINFO` **first** rather
than last: ordering it last would leave the padding logic permanently untestable
through the public API. The kernel does not care about the order.
`TestCmsgPaddingIsObservable` fails loudly if a platform ever made every size
self-aligning, so the padding test cannot quietly become vacuous.

### The final sweep, and a fourth near-miss

Re-running the header diff after all the above left six options unreferenced. Two
of them were about to be dismissed as one-to-many-only, by analogy with
`SCTP_GET_ASSOC_NUMBER`. Probing them first — for the fourth time in this package
— showed the analogy was wrong:

```
PR_ASSOC_STATUS:     ok (unsent=0 sent=0 len=24)
PEER_ADDR_THLDS_V2:  ok maxrxt=5 pf=0 ps=65535 len=144
GET_ASSOC_NUMBER:    Operation not supported
GET_ASSOC_ID_LIST:   Operation not supported
```

`SCTP_PR_ASSOC_STATUS` (RFC 7496 §4.4) and `SCTP_PEER_ADDR_THLDS_V2` both work on
a one-to-one socket and are now bound. The v2 thresholds add `spt_pathcpthld`,
the RFC 7829 §5 Primary Path Switchover threshold — the consecutive-error count
on the primary path at which the stack makes the current active path primary
instead. Its default of `0xffff` disables switchover, and asserting that default
is what proves the field is read at the right offset.

It is not a probing control, which is what an earlier version of this note said.
The kernel stores it in `transport->ps_retrans` and reads it in exactly one
place, `sm_sideeffect.c`:

```c
if (transport->error_count > transport->ps_retrans &&
    asoc->peer.primary_path == transport &&
    asoc->peer.active_path != transport)
        sctp_assoc_set_primary(asoc, asoc->peer.active_path);
```

Nothing consults it when deciding whether to keep heartbeating a path.
Confirmed live as well: `PathCpThld` read back through the getter tracks
`net.sctp.ps_retrans` exactly (65535 → 1234 → 7) while `PathPfThld` tracks
`net.sctp.pf_retrans` independently.

Its layout does **not** simply match v1. Both put a `sockaddr_storage` after the
association id without being packed, so the address offset follows the word
size, and the two structs round to different totals on 32-bit:

| | linux/amd64 | linux/arm/v7 |
|---|---|---|
| `sctp_paddrthlds` | 144, addr@8 | 136, addr@4 |
| `sctp_paddrthlds_v2` | 144, addr@8 | 140, addr@4 |

Both are marshalled through derived offsets for that reason; see
`TestSockaddrStorageOptionLayouts`.

`SCTP_GET_ASSOC_NUMBER` and `SCTP_GET_ASSOC_ID_LIST` genuinely return EOPNOTSUPP
here. `SCTP_SOCKOPT_CONNECTX_OLD` and `SCTP_SOCKOPT_PEELOFF_FLAGS` are internal
options the library reaches by other means.

### Two options that behaviour cannot distinguish

`SCTP_PR_ASSOC_STATUS` and `SCTP_PR_STREAM_STATUS` return the same
`struct sctp_prstatus`, and both read zero on an association where nothing has
been abandoned. **Swapping their option numbers survives every round-trip test.**

Telling them apart needs a message genuinely abandoned under a partial reliability
policy. That was attempted — a 1 ms TTL as the socket default, then 200 × 64 KB
sends on one stream without a reader — and it does not work over loopback: the
send drains before the TTL expires, so both counters stay at zero.

```
after abandoning on stream 4:
  STREAM_STATUS sid=4 -> unsent=0 sent=0
  ASSOC_STATUS  sid=4 -> unsent=0 sent=0
```

So `TestOptionNumbersMatchHeader` asserts the numbers against `linux/sctp.h`
instead, covering all 22 option constants and the 9 positional `sctp_cmsg_type`
values. That is weaker than a behavioural test and is recorded as weaker rather
than presented as equivalent — it is the same technique that closed the
`SCTPPrPolicyRtx`/`Prio` transposition, which the kernel also echoes back without
complaint.

The cmsg values matter because the C enum is positional: an insertion shifts
every later one. A wrong `SCTP_CMSG_PRINFO` makes the kernel reject the send and
is caught behaviourally, but `SCTP_CMSG_DSTADDRV4`/`V6` are unreachable from
one-to-one sockets and would otherwise go unnoticed.

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

Both residuals are now fixed — the ephemeral-port collision and the `EALREADY`
conversion, each documented below. Sixty runs of the fixed tree, alternating
`net.sctp.auth_enable` between runs so both configurations are covered:

```
FIXED-TREE PASS=60 FAIL=0     (baseline at the time: 58 pass, 2 fail)
```

Sixty runs cannot prove a rare flake is gone, only that it is rarer than roughly
one in sixty. What makes the claim stronger than the count is that each cause was
reproduced deterministically first and the fix verified against that
reproduction, rather than inferred from a batch coming back green.

### `TestNotificationHandlerAssignmentOnDialing`: a fixed port inside the ephemeral range

Four tests in `sctp_linux_test.go` bound port **54321**. The kernel's ephemeral
range here is:

```
$ cat /proc/sys/net/ipv4/ip_local_port_range
32768	60999
```

54321 is inside it. Every `:0` bind elsewhere in the suite — and there are dozens
— could be handed that port first, after which all four tests failed with
`address already in use`. That is why it only ever failed as part of the full
suite: in isolation the group passed 60/60.

Holding the port from a separate process reproduces it every time:

```
=== with 54321 already held ===
--- FAIL: TestNotificationHandlerAssignmentOnDialing
    sctp_linux_test.go:39: address already in use
```

Fixed by letting the kernel assign the port and reading it back from
`ln.Addr()`. Verified against the same reproduction, and by mutation: restoring
the fixed port, or dialing the unbound address instead of the listener's, both
fail.

The general shape is the one `TestGetStatus` hit earlier — a hardcoded port is a
collision waiting for a busy enough suite. There is no port outside the ephemeral
range that is safe either, since the range is configurable; asking for 0 is the
only correct answer.

### `SCTPConnect` and `EALREADY`: settled from the kernel source

This was the long-standing residual, about two failures in ninety-five suite
runs. It resisted 1024 concurrent Go dials, a C `sctp_connectx` loop, and forty
instrumented runs, and the errno appears nowhere in RFC 9260 or RFC 6458 — so
neither measurement nor the specification could settle it.

`net/sctp/socket.c` did. `__sctp_connect` and `sctp_connect_add_peer` both have:

```c
asoc = sctp_endpoint_lookup_assoc(ep, daddr, &transport);
if (asoc)
        return asoc->state >= SCTP_STATE_ESTABLISHED ? -EISCONN
                                                     : -EALREADY;
```

**`EISCONN` and `EALREADY` are one branch at two association states.** Both mean
the endpoint already holds the association the caller asked for; `EISCONN` says
the handshake finished, `EALREADY` says it is still in `CLOSED`, `COOKIE_WAIT` or
`COOKIE_ECHOED`. The early return also skips the `sctp_wait_for_connect` that ends
the function on the normal path.

So on a **blocking** socket — which is what this package's dial path creates —
`EALREADY` is a transient race and the association goes on to establish;
reporting failure discards a working connection, exactly as the earlier `EISCONN`
fix established. On a **non-blocking** socket the kernel has not waited, so
`EALREADY` genuinely means not yet connected and must keep reaching the caller.
`SCTPConnect` now makes that distinction on `O_NONBLOCK`, failing safe to "error"
for a descriptor it cannot query.

Reproducing it needs a peer that neither answers nor refuses. TEST-NET-1
(192.0.2.1, RFC 5737) is routed in the test container, so the gateway returns an
ICMP unreachable and the connect fails immediately with `ECONNREFUSED`. Dropping
the packet instead is what holds the association in `COOKIE_WAIT`:

```sh
iptables -A OUTPUT -d 192.0.2.1 -j DROP
```

With that in place, a blocking socket reproduces it on demand — one thread blocked
in `connectx`, another finding the association it created:

```
blocking socket, two threads:
  thread B attempt 0 -> Operation already in progress   <-- EALREADY on a BLOCKING socket
  thread B attempt 1 -> Operation already in progress
  thread B attempt 2 -> Operation already in progress
```

`run-tests.sh` installs the rule, so the test runs rather than skips.

**The first version of the blocking test was worthless and mutation caught it.**
On loopback the handshake completes inside the first call, so the second connect
finds an `ESTABLISHED` association and gets `EISCONN` — never `EALREADY`.
Reverting the entire fix still passed it. Only the two-goroutine blackholed
version reaches the branch, and it kills that mutation.

## Performance

The package had no benchmarks, so there was no baseline against which to judge a
change. `sctp_bench_test.go` adds them for the per-message paths:

```sh
go test -run '^$' -bench . -benchmem
```

Watch `allocs/op` rather than `ns/op`. The syscall dominates wall time on the
socket benchmarks and loopback flow control moves their `ns/op` by hundreds of
nanoseconds between runs for reasons unrelated to this package. Allocation is what
the package controls, and per-message garbage is what a caller pushing throughput
feels as GC pressure.

### The send path allocated eight times per message

`SCTPWrite` built its control message with two `toBuf` calls and an `append`.
`toBuf` goes through `binary.Write`, which reflects over the struct and writes
into a `bytes.Buffer`. `buildSndRcvCmsg` writes the bytes directly instead, using
the layout `TestStructLayoutsMatchKernel` already pins:

```
BenchmarkBuildSndRcvCmsg/legacy-8     286 ns/op   296 B/op   8 allocs/op
BenchmarkBuildSndRcvCmsg/current-8     32 ns/op    48 B/op   1 allocs/op
```

Roughly nine times faster with an eighth of the allocations. End to end that
takes `SCTPWrite` from 9 allocations per message to 2.

The risk in hand-writing a wire layout is a silently different control message, so
`TestBuildSndRcvCmsgMatchesLegacy` keeps a copy of the old construction and
compares the bytes for every field at distinct values, at zero, and at maximum.
`TestBuildSndRcvCmsgOffsetsMatchStruct` pins the offset literals against the Go
struct, because the byte comparison alone cannot catch a wrong payload length —
both implementations derive it from the same struct, and a mutation setting it to
28 survived that comparison.

### The old construction was a data race

The previous version byte-swapped the caller's `PPID` in place and swapped it
back:

```go
oldPPID := info.PPID
info.PPID = htonl(info.PPID)
cmsgBuf := toBuf(info)
info.PPID = oldPPID
```

An `*SndRcvInfo` is otherwise read-only, so sharing one across senders is natural —
and two goroutines doing it could observe the swapped value or lose the restore.
`TestSCTPWriteConcurrentSharedInfo` reports `WARNING: DATA RACE` against the old
implementation under `-race` and passes against the new one, which does not touch
its argument.

### Three benchmark harnesses that measured the wrong thing

Worth recording, because each produced numbers that looked plausible:

1. **Treating `EAGAIN` as failure.** `SCTPWrite` passes `MSG_DONTWAIT`, so a full
   send buffer is reported rather than waited on. The first harness failed at the
   first full buffer with "resource temporarily unavailable".
2. **Busy-retrying inside the timed loop.** The second reported **34500 allocs
   and 2 ms per write** — the cost of the retry spin, not of a send. `sender` now
   counts retries, reports them as a metric, excludes the waits from the clock,
   and fails outright if flow control dominated.
3. **A draining reader that died silently.** `BenchmarkSCTPWriteInfo` measured 241
   retries per send as the third of three benchmarks in one process, and zero when
   run alone. The send paths were identical; the reader had exited and nothing
   noticed. `benchDrain` now reports whether its reader failed.

A fourth mistake was in the setup rather than the loop: `SetWriteBuffer(4 << 20)`
against `net.core.wmem_max` of 212992 is **silently clamped**, and `setsockopt`
reports no error. The harness believed it had twenty times the buffer it had.
`raiseBuffers` now reads the ceiling from the sysctl and verifies what was
granted — a caller cannot otherwise tell a clamp from a success.

### The read path aliased its buffer

Looking at the per-call `oob` allocation for pooling turned up a correctness bug
rather than a performance one. `parseSndRcvInfo` returned a pointer *into* the
control-message buffer and byte-swapped `PPID` in place:

```go
dst := (*SndRcvInfo)(unsafe.Pointer(&m.Data[0]))
dst.PPID = ntohl(dst.PPID)
return dst, nil
```

Parsing the same bytes twice therefore swapped twice:

```
first parse PPID=0x11223344, second parse PPID=0x44332211 (input was 0x11223344)
both parses returned the SAME pointer: the result aliases the input buffer
```

Reachable by any caller driving `recvmsg` itself through `SyscallConn`. It also
meant the returned struct outlived the buffer it pointed into, which held only
because `SCTPReadFlags` allocates a fresh buffer every call — so pooling that
buffer, the obvious optimisation, would have been a use-after-free.

Fixed by copying. `TestParseSndRcvInfoDoesNotAliasInput` overwrites the source
buffer after parsing and checks the result is unaffected;
`TestSCTPReadInfoSurvivesLaterReads` holds the info from four messages and checks
all four after the reads finish. Both fail against the old implementation.

The lesson is the one this package keeps teaching: the bug was found by reading
the code around a performance question, not by looking for bugs.

### Not measured

The benchmarks here are loopback on one host and one kernel; they compare
revisions of this package rather than characterising the stack.

Throughput under concurrency, multi-homed paths, path failover and large
messages crossing the fragmentation point were all on this list and are no
longer; each is covered below.

## One listener, many peers

The suite could not previously show that a server *serves* several peers.
`TestSCTPConcurrentAccept` dials a hundred times, but closes each connection the
instant it is accepted and never sends a byte, so it proves accept does not
crash under concurrency and nothing else. Data isolation between peers,
per-connection state, and notification attribution were all unexercised.

`sctp_multiclient_test.go` covers them, holding every association open for the
duration and asserting what each peer actually receives:

| Test | What would fail it |
|---|---|
| `TestManyClientsConcurrentEcho` | one peer's bytes reaching another (24 peers × 20 messages, each payload unique) |
| `TestManyClientsHeldOpenSimultaneously` | a server that serialises peers instead of holding 16 associations at once |
| `TestManyClientsDistinctAssociationIDs` | two peers reported under one association id |
| `TestManyClientsPerConnectionDeadlineIsolation` | one peer's expired deadline expiring another peer's read |
| `TestManyClientsStreamsStayPerAssociation` | a crossed stream across 8 peers × 4 streams |
| `TestManyClientsCloseDoesNotDisturbPeers` | a close releasing a descriptor another peer is using |
| `TestManyClientsNotificationsCarryAssociationID` | notifications a shared handler cannot attribute to a peer |

**The shared `NotificationHandler` is the one real sharp edge in the API.** One
func is handed to the listener and inherited by every connection accepted from
it, and it is called with the raw bytes only — no `*SCTPConn`, no association
handle — so a server receives every peer's notifications through one callback.
The signature cannot change without breaking callers. What makes it workable is
that the notification body carries the association id, and the test asserts that
rather than assuming it: six aborting peers must produce six *distinct* ids.

The ordering it depends on was established by probing the kernel, not guessed.
The server has to consume the data message **before** the peer aborts and then
read again; that second read is what dequeues `SCTP_COMM_LOST`. Aborting while
the server has not yet read leaves the notification unobserved and the handler
never fires — the first version of the test skipped for exactly that reason.

### Peer separation verified on the wire

In-process assertions only prove the struct was populated. A local tshark
harness (six peers, four streams each, PPID encoding the sender) confirms the
separation on the wire:

```
INIT count: 6   INIT_ACK count: 6   distinct initiate tags: 6
DATA chunks per PPID:   8 each for 1000..1005
DATA chunks per stream: 12 each for streams 0..3
payloads: 24 distinct, each appearing exactly 2x (request + echo)
```

Six initiate tags is six genuinely separate associations rather than one
multiplexed. Every payload appearing exactly twice is what rules out a peer's
bytes being dropped, duplicated, or delivered to the wrong association — a count
alone would not. The harness asserts the negative too: corrupting one byte of
the echo makes it exit non-zero, so it detects the defect rather than always
reporting success.

This harness is **kept outside the repository**, unlike the older tshark scripts
in this directory. It is a Go program that dials N peers on M streams each,
encoding the sender in the PPID and the peer and stream in the payload, plus a
script that captures loopback SCTP around it and checks the capture. The same
place holds the scale probe that found the `EINTR` and connect-path defects
below, with its own notes on running both:

```sh
docker run --rm --privileged -v "$PWD":/src -v <harness-dir>/wire:/wire \
    -w /src sctp-test bash /wire/tshark-multiclient.sh
```

The `/wire` mount name is load-bearing: the script writes its capture there.
Exit status is the result — 0 if every payload was sent once and echoed once.

The checks that matter are `sctp.chunk_type == 1` for the INIT count and
`sctp.init_initiate_tag | sort -u` for distinct associations, then `data.data`
decoded from hex and counted per payload. `data.data` is the field that carries
the DATA chunk payload; `sctp.chunk_payload` and `sctp.payload` are not fields
in tshark 4.0 and silently yield nothing, which reads as a clean zero.

### Scale, and where the ceiling actually is

1000 simultaneous peers, five messages each, repeated eight times: 8000 sessions,
zero errors, zero mismatches.

The ceiling on this host was then measured rather than left as "it OOMs
somewhere". 1200 peers establish concurrently with no error; 1500 is killed by
the OOM killer before finishing. What matters is *whose* limit that is, so it
was attributed rather than assumed:

```
1200 associations open, measured:
  ceiling process RSS       3 MB      <- the Go side, including this package
  SCTP kernel slab          3 MB
  system memory used     7361 MB      <- of 7650 MB total
  delta over baseline    6769 MB  ->  ~5.8 MB per association
```

Nearly six megabytes per association, against a Go-side cost of three megabytes
for all twelve hundred. The memory is kernel socket buffers: `wmem_default` and
`rmem_default` are 212992 bytes each and the kernel commits far more than the
nominal figure per association. **The ceiling belongs to the host, not to this
package** — every failure at 1500 is `Killed`, never an error returned by the
library.

Lowering it is not possible here: `/proc/sys/net/core/wmem_default` is `r--r--r--`
in the Docker Desktop VM and `sysctl -w` returns EINVAL even privileged.
`SetWriteBuffer`/`SetReadBuffer` after connect do not help either, since the
commitment is made at association setup. A host that allows the sysctl, or one
with more memory, would push the number up; nothing was found that this package
does per association to bound it.

## The read path's allocations

A memory profile settled where they actually were, which was not where the
earlier note assumed:

```
16384 66.66%  syscall.anyToSockaddr
 8194 33.34%  sctp.(*SCTPConn).SCTPReadFlags
```

Two thirds came from `syscall.Recvmsg` building a peer address that
`SCTPReadFlags` discards — it fills a `RawSockaddrAny`, which escapes, then
converts it with `anyToSockaddr`, which allocates. Only the remaining third was
the `oob` buffer that the earlier note singled out as "the obvious next
candidate".

Both are gone. A local `recvmsg` passes a nil `msg.Name`, which asks the kernel
not to report the source address at all — correct here, since the socket is
connected and the value was never read — and keeps the `Msghdr` and `Iovec` on
the stack. The `oob` buffer now comes from a `sync.Pool`, which is only safe
because `parseSndRcvInfo` copies: it used to return a pointer *into* that buffer
and byte-swap `PPID` in place, so pooling would have been a use-after-free. The
aliasing fix is what unlocked this.

Measured on the same host, 3000 iterations, three runs each:

```
                          before                    after
SCTPRead                  417 B/op  5 allocs/op     129 B/op  3 allocs/op
ConcurrentEcho peers=64   657 B/op  3 allocs/op      96 B/op  0 allocs/op
```

The echo round trip is allocation-free. **Time is unchanged** — ~680ns and
~13µs before and after — so this is a garbage-collection win under sustained
load, not a latency one, and it should not be read as a speedup.

`TestPooledOobDoesNotCrossAssociations` drives 24 peers through the pool at once
and checks the *ancillary data* rather than only the payload, since a pooling
defect surfaces as one association's stream and PPID appearing on another's
message while the bytes stay correct. `TestPooledOobSurvivesReuse` holds the
info from sixteen reads and checks all sixteen afterwards.

Both mutations were run. Restoring the aliasing `parseSndRcvInfo` fails both new
tests plus the two that already covered it; returning the buffer to the pool
before it is parsed fails the concurrency test 3 runs of 3, reporting the exact
cross-association leak:

```
peer 16 msg 1: got stream=4 ppid=0x100c, want stream=0 ppid=0x1010
```

## Multi-homing

Multi-homing is SCTP's defining feature over TCP — one association spans several
addresses on each side (RFC 9260 §6.4) — and this package exposes it through
`SCTPAddr.IPAddrs`, `SCTPBind` and the `SCTP_GET_LOCAL_ADDRS` /
`SCTP_GET_PEER_ADDRS` readbacks. **None of it had a test against a live kernel.**
The coverage that existed parses address strings and decodes a reply buffer built
by hand, which proves the encoding and never that an association forms across
several addresses or that the peer learns them.

`sctp_multihome_test.go` covers three directions:

| Test | What would fail it |
|---|---|
| `TestMultihomedAssociationExchangesAddresses` | a peer learning fewer addresses than were bound; all four readbacks are checked, and data must flow so a passing address check cannot come from an association that never formed |
| `TestMultihomedListenerServesManyPeers` | twelve multi-homed peers on one multi-homed listener — the multi-client isolation assertion carried onto multi-homed associations |
| `TestMultihomedBindRejectsAnUnusableAddress` | a bind that silently drops an address the host does not own, leaving an association that looks healthy and is missing a path |

Verified by mutating `ToRawSockAddrBuf` to encode only the first address. All
three fail with exact diagnostics, and so does `TestKernelAddrsRoundTrip`:

```
listener bound [127.0.0.1], want [127.0.0.1 127.0.0.2]
client peer addresses = [127.0.0.1], want [127.0.0.1 127.0.0.2]
listen on [127.0.0.1 192.0.2.1] succeeded and bound [127.0.0.1]
```

Observed on a live association, both sides seeing the other's full set:

```
listener bound 3 addrs: [127.0.0.1 127.0.0.2 127.0.0.3]
client local [127.0.0.1 127.0.0.4]   client peer [127.0.0.1 127.0.0.2 127.0.0.3]
server local [127.0.0.1 127.0.0.2 127.0.0.3]   server peer [127.0.0.1 127.0.0.4]
```

### Address advertisement verified on the wire

The readbacks above prove the struct was populated. A capture proves the
addresses were actually advertised, which is a different claim — the kernel
carries them as IPv4 Address parameters in the INIT and INIT-ACK chunks
(RFC 9260 3.3.2), and a bind that dropped one would still return a working
association over the primary path:

```
sctp.chunk_type  sctp.parameter_ipv4_address
1 (INIT)         127.0.0.3,127.0.0.4      <- the client's set
2 (INIT_ACK)     127.0.0.1,127.0.0.2      <- the server's set
```

Both sets are on the wire, each advertised by the side that bound it.

`run-tests.sh` adds 127.0.0.2 through 127.0.0.4. The tests skip rather than pass
vacuously below three usable addresses, since a single-address host exercises
none of this.

### Path failover

The Go tests prove the addresses are negotiated. They cannot prove failover,
because a loopback path cannot be taken down: traffic between two of a host's
own addresses is routed through `lo`, so an iptables DROP on one of them is not
a path failure and the kernel never marks the path unreachable.

Real failover needs two hosts on two networks with a firewall between them, so
it runs outside the container the rest of the suite uses. `failover.sh` builds
two containers, attaches each to two docker networks — giving every end a real
`eth0` and `eth1` on different subnets — establishes an association across both,
and cuts one path underneath it:

```sh
bash testdata/failover.sh
```

```
=== Multi-homed: two paths, primary cut ===
PEER-PATHS=[{172.30.0.10 } {172.31.0.10 }]
RESULT sent=115 ok=115 failed=0
packets dropped by the cut: 10
PASS: every round trip succeeded across the cut.

=== Single-homed control: one path, cut ===
PEER-PATHS=[{172.30.0.10 }]
RESULT sent=18 ok=15 failed=3
packets dropped by the cut: 16
PASS: traffic failed as expected with no second path.
```

Every round trip survived the cut on two paths; on one path the same cut broke
the association. **The control run is what gives the first its meaning** — a cut
that silently did nothing would look identical to successful failover — and the
script also refuses to pass a case where the DROP rules matched no packets,
which is the other way a cut can quietly do nothing.

Verified by mutation: binding the multi-homed case to a single address makes it
exit 1 with `the association did not fail over`.

`failoverprobe/` is the driver. It cannot be a Go test for the routing reason
above, so it is a script; it is committed rather than kept local because it
needs no capture and no tooling beyond docker.

## Throughput under concurrency

Previously unmeasured. `BenchmarkConcurrentEcho` reports ns/op per round trip so
peer counts are comparable:

```
peers=1    33419 ns/op   606 B/op   4 allocs/op
peers=4    15348 ns/op   665 B/op   4 allocs/op
peers=16   14041 ns/op   813 B/op   4 allocs/op
peers=64   13141 ns/op  1459 B/op   4 allocs/op
```

Per-round-trip cost *improves* with concurrency rather than degrading: the
single-peer case is latency-bound waiting for each echo, while concurrent peers
keep the kernel busy. Allocations per message stay flat at four; the growth in
bytes per op is the per-peer goroutine and buffer set, not per-message cost.

`BenchmarkDial` answers the question the `EALREADY` fix raised — whether
confirming the association made dialing more expensive — against the commit
before it, 500x and three runs each:

```
baseline  1974259 / 1477438 / 1396742 ns/op   320 B/op  12 allocs/op
fixed     1515316 / 1394870 / 1483919 ns/op   320 B/op  12 allocs/op
```

Identical allocations and overlapping ranges. The confirmation runs only on the
`EALREADY` branch, so the common path is unchanged — which is what the placement
was chosen for.

## `EINTR`: no blocking syscall was retried

The scale probe is what turned this up. At 1000 peers a handful of reads failed
per run with `interrupted system call`, on associations that were otherwise
healthy; at 150 peers it never happened. Nothing in the package handled `EINTR`
anywhere.

A Go program receives signals it never asked for: the runtime uses `SIGURG` to
preempt goroutines, and preemption becomes frequent exactly when many goroutines
are runnable — which is what a busy server looks like. Three call sites were
exposed, and they fail in increasing order of nastiness:

| Call site | Consequence of the unretried `EINTR` |
|---|---|
| `recvmsg` in `SCTPReadFlags` | a healthy read reported as failed; measured at 0.1–0.3% of reads under load |
| `accept4` in `AcceptSCTP` | a spurious accept failure; a caller treating it as fatal stops serving |
| `read` in `closeSctpSocket` | **a graceful close turned into an ABORT** |

The third is the one that corrupts a protocol outcome rather than returning an
error. That read is what distinguishes "the peer's shutdown completed" from "the
peer never answered": `EINTR` returns `(-1, EINTR)`, which is not the completed
case, so the code fell through to the `linger=0` path and emitted an ABORT on an
association that had shut down cleanly. The peer sees `ECONNRESET` instead of the
end of the stream, and **no error is reported on either side** — the close
"succeeds".

All three now retry. The read retry re-enters the existing loop, which reprograms
`SO_RCVTIMEO` from the absolute deadline, so an interrupted read cannot extend its
own budget; the accept retry re-reads the listener descriptor so a concurrent
`Close` ends it with `EBADF` rather than spinning on a closed socket.

`sctp_eintr_test.go` drives real signals at a thread blocked in each call.
Against the unfixed code `TestReadSurvivesSignals` fails on the first read with
`EINTR`, and the 1000-peer probe produced nine failures across eight runs; after
the fix, 8000 sessions produced none.

### The connect path returned sockets with no association

Chasing an `EPIPE` that survived the `EINTR` fix led to a second, worse defect —
found only because the failure was pursued instead of dismissed as flakiness.

`SCTPConnect` treated `EALREADY` on a blocking socket as success, on the
reasoning recorded above: `EISCONN` and `EALREADY` are one kernel branch, so the
endpoint holds the association and a blocking socket has already waited for the
handshake. The first half is right. The second is not — the `EALREADY` branch is
an **early return that skips `sctp_wait_for_connect`**, so when the connect is
interrupted the handshake may never finish. Measured under signal load:

```
EALREADY seen=2 -> established_later=1 DEAD_FOREVER=1
```

One of two never established. `DialSCTP` then returned a `*SCTPConn` with no
association behind it: `GetStatus` failed with `EINVAL`, and the caller's *first
write* failed with `EPIPE` — having been told the dial succeeded. Silently
handing back a dead connection is worse than a failed dial.

**Where the fix goes matters, and the first attempt put it in the wrong place.**
Verifying inside `SCTPConnect` also changed the exported behaviour that
`TestSCTPConnectEALREADYOnBlockingSocketMidHandshake` pins, because
`SCTP_STATUS` reports `EINVAL` identically for "still handshaking" and "no
association" — it cannot tell them apart. Worse, verifying on *every* dial put a
timeout on handshakes the kernel would have completed: three previously-passing
tests started failing with `ETIMEDOUT` under suite load.

So the confirmation lives in the dial path, and only on the branch that needs it.
`sctpConnect` reports whether it returned through `EALREADY`; only then does
`dialSCTPExtConfig` wait for the association. A normal connect costs nothing
extra, a raw-fd caller driving `SCTPConnect` keeps the old semantics, and the
blackholed mid-handshake test passes unchanged.

`TestDialNeverReturnsAnUnestablishedAssociation` dials 2000 times under signals
and requires every dial that reports success to carry a real association. The
detection rate is honest rather than absolute: against the unfixed code it fires
4 runs in 5 at 2000 dials, and only 1 in 8 at 200 — racing the kernel's connect
path is inherently probabilistic. The fixed code passed 5 of 5.

### What the harness now enables

`run-tests.sh` turns on `net.sctp.auth_enable` and adds `127.0.0.2` to loopback.
Both were previously missing, and nine tests skipped as a result — the whole AUTH
group, the `SCTP_AUTHINFO` send path, the cmsg padding test (a 2-byte `AuthInfo`
is the only cmsg whose padding bytes are non-zero, so nothing else can prove the
padding is written correctly), and the multi-address decoding test. A skip reads
as a clean run while leaving those paths entirely unexercised.

One skip remains and is correct: Linux rejects a zero-length SCTP write with
`EINVAL`, so `TestReadMsgZeroLengthMessage` documents unreachable behaviour
rather than hiding a gap.

### Suite state

194 pass, 0 fail, 3 skip under `-race`, and ten consecutive clean runs of the
full suite on an idle host.

Getting a trustworthy number took several attempts, and every wrong one failed
the same way. Eight runs gave 5 pass / 3 fail; a re-run failed
`TestSCTPConnectEALREADYOnBlockingSocketMidHandshake` after 340s against its
usual 0.00s; later, `TestDialNeverReturnsAnUnestablishedAssociation` failed
after 352s against its usual 17s. Each time `docker ps` showed a container left
running from earlier work. Each time the failing run produced no `--- FAIL` line
or an implausible duration — both signatures of host contention rather than a
defect.

Measured properly, on a host with no other containers, against the baseline this
branch started from:

```
baseline (3bf7b9c)   full suite  12 pass  0 fail
fixed tree           full suite  12 pass  0 fail
fixed tree           full suite  10 pass  0 fail   (after the item-3 work)
baseline   EALREADY test alone   40 pass  0 fail
fixed tree EALREADY test alone   40 pass  0 fail
```

The one lasting change this forced is in the suite rather than the code:
`TestDialNeverReturnsAnUnestablishedAssociation` dials two thousand times under
continuous signals, which is the most load-sensitive thing here, so it now has a
`-short` sample of two hundred. That detects less — against the mutation that
skips the association confirmation the full count fires 4 runs in 5 and the
short one 3 in 5 — so the full count stays the default.

The rule, re-learned the hard way more than once: **never call a failure
pre-existing or introduced without a baseline measured at a sample size that
could distinguish them**, and never measure timing against a real kernel on a
busy host.

The two skipped AUTH-off tests are the deliberate inverses of the AUTH-on ones
and skip precisely because the harness now enables the sysctl.

## Backpressure: `EAGAIN` with no supported way to wait

Reported by a library user building on the package. Three claims, all of which
checked out at `5591211`: `SCTPWrite` passes `MSG_DONTWAIT` and so reports
`EAGAIN` the moment the send buffer fills; `SCTPWriteInfo` does the same; and
`SyscallConn` hands back a `rawConn` whose `Read` and `Write` **panic** with
`"not implemented"`. `Control` works, so a caller can extract the descriptor and
poll it — which is every caller reimplementing readiness handling, in
platform-specific code, for a type `Accept` returns as a `net.Conn`.

Two things the report got wrong, and they matter because they decide how much to
change. `net.Conn.Write` has **no** documented blocking requirement — `net/net.go`
says only "Write can be made to time out and return an error after a fixed time
limit" — so returning `EAGAIN` is conformant, and this is a usability gap rather
than a contract violation. And "implement `Read`/`Write` against the runtime
poller" is not available here: reaching the poller means `O_NONBLOCK`, and the
read path maps a `recvmsg` `EAGAIN` onto `os.ErrDeadlineExceeded`, so every read
that found the socket empty would report a deadline that had not expired.

The real problem was narrower and worse. `MSG_DONTWAIT` arrived in `2cd8759` to
stop a send to a peer that has stopped reading parking for minutes with no way
to interrupt it — that is worth keeping. But it also left `SetWriteDeadline`
with **nothing to do**: `SO_SNDTIMEO` bounds a wait the socket never performs, so
a deadline in the future changed no behaviour at all, and `TestWriteDeadlineInThePast`
was the only coverage precisely because an elapsed deadline was the only
observable case. A caller asking for "carry on until this is accepted or until
the deadline" got neither half.

So the wait now happens in `sendmsg`, bounded by the deadline the caller set.
With no deadline the behaviour is byte-for-byte what it was. `SyscallConn` on a
connected association returns a `connRawConn` that waits with `ppoll`;
`SCTPListener` and the `SocketConfig` hook return `syscall.EINVAL`, which is
exactly what `net/rawconn.go` does for a listener and what
`TCPListener.SyscallConn` documents.

The wire is what settles it. Same probe, same burst of 2000 messages of 512
bytes against a peer draining at 2 ms per read, counting DATA chunks rather than
frames — loopback bundles many chunks into one packet, and counting frames
undercounts by an order of magnitude:

| Code | Write deadline | DATA chunks on the wire |
|---|---|---|
| `5591211` | 120 s | **348** — the deadline is ignored |
| fixed | 120 s | **2000** — sequences 0..1999, each once, in order |
| fixed | none | **348** — `2cd8759`'s behaviour, deliberately unchanged |

Two traps in building that harness, both of which read as success. `sctp port N`
as a BPF capture filter matches nothing; `ip proto 132` works. And the sequence
check was written with `strtonum`, a gawk extension — Debian ships mawk, so it
silently did nothing and reported the payloads verified.

The mutation harness caught a third, in the tests rather than the tooling.
`TestSyscallConnCloseUnblocksWait` was written to prove that a parked wait comes
up for air and notices a closed descriptor; stretching `rawWaitSlice` to ten
minutes left it green. The wakeup was coming from the kernel: `closeSctpSocket`
calls `shutdown(SHUT_RDWR)` first, which wakes anything parked on the descriptor.
`Abort` does not — it sets `SO_LINGER` to zero and closes outright — so
`TestSyscallConnAbortUnblocksWait` covers the path where the polling cadence is
genuinely the only thing that ends the wait, and the two tests now pin opposite
sides of that mutation.

Two limitations that survive, both documented at the code:

- `ppoll` is level-triggered where the runtime's poller is edge-triggered, and
  `syscall.RawConn` explicitly permits `f` to report "not done" on a descriptor
  that is ready. `POLLOUT` means the send buffer has room; `sendmsg` needs room
  for the whole message and will not split one. After `rawSpinTolerance` such
  rounds the wait stops polling and paces itself, because the kernel has no
  readiness event for "enough room for a message of my size". Measured at 159
  calls over 300 ms; unguarded it reaches six figures.
- The descriptor lifetime race is narrowed, not removed. Reading `c.fd()` afresh
  each round beats the old snapshot, but there is no equivalent of the reference
  count `internal/poll` uses, so a `Close` landing between the read and the use
  is still the caller's ordering problem — as it already is for `SCTPRead` and
  `SCTPWrite`.

## Closing out the rest of the backpressure review

Ten things were flagged during the review above and left unfixed. Six were real,
two were not, and two of the "fixes" proposed for them were wrong in ways only a
probe caught. What follows is what each turned out to be, because several of the
plausible-sounding answers were false.

**`Close` never waited for anything.** `closeSctpSocket` decided whether the
shutdown handshake had completed by reading from the socket.
`shutdown(SHUT_RDWR)` sets `RCV_SHUTDOWN` before the SCTP layer sees it, and
`sctp_skb_recv_datagram` tests that — returning end of stream — *before* both the
`EAGAIN` path and the `SO_RCVTIMEO` wait. So the read returned `(0, nil)` the
instant the receive queue was empty, whatever the peer had done. Three things
followed: "the peer completed the handshake" was true for every peer that had
gone silent, which is the one case the wait exists for; the `EAGAIN` outcome the
comment documented was unreachable; and `timeout` was inert —
`CloseWithTimeout(1ms)` and `CloseWithTimeout(1h)` were the same call. The cost
was silent: against a vanished peer, `Close` skipped the ABORT and left the
association and its port in the kernel for up to 5 × RTO.max, which is exactly
the `EADDRINUSE` window its own doc claims to prevent.

The fix polls `SCTP_STATUS` instead. Getting there took two rounds: the first
analysis rejected it, quoting `sctp_id2assoc` as `if (!sctp_sstate(sk,
ESTABLISHED)) return NULL;` and concluding the query dies at shutdown. The real
line is `if (!sctp_sstate(sk, ESTABLISHED) && !sctp_sstate(sk, CLOSING))`, and
`sctp_shutdown` sets exactly `SCTP_SS_CLOSING`. Measured: still answering
`SHUTDOWN_PENDING` 3 s after the shutdown for a stalled peer, `EINVAL` 1.9 µs
after it for one that answers. A truncated quote had nearly bought a
`getpeername` plus a 152-byte `sockaddr_storage` round-trip through
`SCTP_GET_PEER_ADDR_INFO` to solve a problem that did not exist.

**The listener `Shutdown` comment was wrong, and so was its replacement.** The
existing text said shutdown fails on a listening socket with `ENOTCONN`. The
proposed correction said it fails with `EOPNOTSUPP` and does not unblock a
parked `Accept`. Both are wrong: `sctp_disconnect` returns `EOPNOTSUPP` only for
UDP-style sockets, and this package creates `SOCK_STREAM` exclusively, so it sets
`RCV_SHUTDOWN` and returns 0 — and `RCV_SHUTDOWN` is one of the conditions
`sctp_wait_for_accept` breaks on. Probed directly: shutdown returns success, and
shutdown *alone*, with no close and no signal, ends a parked accept in 135 µs
with `EINVAL`. Only the errno clause needed correcting, and
`TestListenerCloseUnblocksAccept` is deterministic rather than the latent flake
it was nearly re-graded as.

**Two flags were not defects at all.** A send on an association still in
`COOKIE_WAIT` returns `EPROTO` or `EPIPE`, never `EAGAIN`, so the retry loop
cannot spin against a handshake in progress — no liveness guard needed. And the
level-triggered `POLLERR` concern does not reproduce: the state is transient, and
the wait terminates after exactly one call to `f` with the real errno. The guard
proposed for it was worse than unnecessary — it was dead code, since the pacing
branch returns before the poll the counter lived next to, so it could never
reach its own threshold.

**Concurrency was measured rather than argued.** `internal/poll` takes the same
locks for `RawRead`/`RawWrite` that `FD.Read`/`FD.Write` take; `connRawConn`
takes none. What that costs, over 300 messages of 8000 bytes read through a
2000-byte buffer: one reader splits 0 messages, two `SCTPRead` readers split 61,
`SCTPRead` plus a RawConn reader splits 64. No run lost, duplicated or corrupted
anything — the kernel holds `lock_sock` across the dequeue and the requeue. So a
RawConn reader is indistinguishable from a second `SCTPRead`, and a lock here
would not fix the case that actually bites. It is documented, not locked.

**Smaller ones.** `MSG_NOSIGNAL` is now set on both send paths: SCTP does raise
`SIGPIPE`, and the flag suppresses it leaving the errno unchanged — both halves
measured. `ErrUnsupported` now wraps `errors.ErrUnsupported`, so the portable
check works; the shared name had made the failure easy to miss.
`SCTPListener.SetDeadline` gives `Accept` a bound that does not require
destroying the listener, via `SO_RCVTIMEO`, which `sctp_accept` honours.

**Two things the tools were hiding.** `GOOS=linux GOARCH=arm go vet` had never
passed: `sctp_maxseg_test.go` passed the constant `1<<33` to a function taking
`int`, which does not compile where `int` is 32 bits — so the whole test package
was uncompilable on every 32-bit target. The bound being tested is `uint32`'s
ceiling, which cannot be represented there at all, so the case is now guarded and
the value built at run time. And `go test ./...` had never passed on macOS:
`sctp_test.go` and `sctp_streams_test.go` lacked the `linux && !386` tag every
other behavioural test file carries, so they ran on a platform with no SCTP stack
and failed. Both now pass.

Two test defects turned up in mutation, both mine. `TestSendDoesNotRaiseSIGPIPE`
stopped at the first failed write, which reports `ECONNRESET` — and `ECONNRESET`
does not raise `SIGPIPE`. It passed with and without the flag until it was made
to write on past the first error to the `EPIPE` state that actually raises the
signal. And the healthy-close mutation was caught by
`TestCloseAfterCompletedHandshakeGivesPeerEOF` rather than by the promptness test
aimed at it: `completed := false` takes the ABORT path, which is fast, so
promptness could never have detected it. 9 of 9 mutations are caught now, but
only after both were re-pointed.

## Cancelling a dial

Second request from the same library user, and a fair one: there was no way to
abandon an in-flight connect. `dialSCTPExtConfig` creates its socket blocking, so
`sctpConnect` does not return until the kernel either completes the handshake or
exhausts its own retransmission budget. A caller with its own deadline could stop
*waiting*; it could not stop the *attempt*.

The distinction is visible on the wire and nowhere else. Two containers, the
receiver dropping all SCTP on its INPUT chain, the sender capturing, caller
giving up after 2s:

| | `DialSCTPExt` | `DialSCTPContext` |
|---|---|---|
| chunks out | INIT 0.00s, **INIT 3.04s, INIT 9.25s** | INIT 0.00s, **ABORT 2.00s** |
| after the caller gave up | still retransmitting | nothing |
| associations left | **1**, still 1 twelve seconds later | **0** |

So an application that abandoned a dial after two seconds was still emitting an
INIT seven seconds later, from a socket it believed it had finished with. For
anything reconnecting in a loop that makes the retry cadence unpredictable and
leaves a descriptor per abandoned attempt.

`SCTP_INITMSG` cannot fix it from the outside, which is worth recording because
it is the obvious thing to try. `MaxAttempts` counts retransmissions rather than
attempts and zero selects the kernel default, so the smallest usable value still
puts a second INIT on the wire at `net.sctp.rto_initial`; `MaxInitTimeout` caps
each RTO without bounding the total. The bound has to come from the dial itself.

`DialSCTPContext` and `SocketConfig.DialContext` create the socket with
`SOCK_NONBLOCK`, which puts the wait under this package's control rather than the
kernel's, then abort on every path that does not establish. `DialSCTP`,
`DialSCTPExt` and `SocketConfig.Dial` are untouched.

Two details that are easy to get wrong, both now pinned by tests. The descriptor
has to go back to blocking before it is handed over — `SCTPRead` and the deadline
handling assume it, and on a non-blocking one an idle read returns EAGAIN, which
this package maps onto `os.ErrDeadlineExceeded`, so the caller sees a deadline
expire that never did. And a refusal cannot arrive through the connect, which has
already returned; it comes back through `SO_ERROR`, and without that check a dial
to a closed port sits out its whole context and reports a timeout instead of the
refusal.

The mutation that mattered most was the one the tests initially missed. Removing
the already-cancelled check at the top left `TestDialContextAlreadyCancelledOpensNoSocket`
green, because without it the socket is opened *and* released by the same call —
a descriptor count taken afterwards is back where it started. The witness had to
be the `Control` hook, which runs between the socket being created and the
connect: if it ran at all, a socket was created for a context that was already
done. 8 of 8 mutations are caught with that change.

The capture needed care in the way the report warned. An `iptables -j DROP` on
the *sender's* OUTPUT chain discards the packet before the capture point, so
tshark records nothing and the harness reads as a clean pass for correct and
broken code alike. The drop belongs on the receiver's INPUT, which is why this
needs two containers rather than loopback.

## The audit, and what it turned up

Everything above was written while fixing something specific. This section is the
other direction: a sweep over the whole package, asking what was still wrong.
Most of it was, and had been from the start.

### The package stopped building for Windows

Upstream builds for `windows/amd64`. This fork did not, and had not for several
commits.

Two helpers had gone into `sctp.go`, which carries no build tag and is therefore
compiled for every target: `isNonblocking`, which calls `syscall.SYS_FCNTL`, and
`applyTimeout`, which calls `syscall.SetsockoptTimeval`. Neither is portable —
`SYS_FCNTL` is not in the `syscall` package on Windows at all, and
`SetsockoptTimeval` takes a `syscall.Handle` there rather than an `int`.

This matters more than it looks. The whole point of `sctp_unsupported.go` is that
a program importing this package and built for a platform without SCTP gets
`ErrUnsupported` when it calls something, not a compiler error when it builds. A
build failure cannot be handled and it breaks consumers who never touch SCTP on
that platform.

The suite stayed green throughout, because it only ever runs on one platform at a
time. staticcheck did report the symptom — under `GOOS=darwin` it flags several
`sctp.go` functions as unused, since their only callers are in the linux-tagged
file — but it flags perfectly portable ones the same way, so the signal was
indistinguishable from the noise. Commit `62e7e51` had claimed "staticcheck and
golangci-lint now all report nothing", which was already false when it was
written: 10 and 22 findings at that commit. A claim like that has to name the
GOOS/GOARCH it covers or it cannot be checked.

The detector for "does it build on platform X" is building it for platform X.
`TestCrossCompiles` now does, for twelve targets picked one per axis — syscall
package, word size, byte order — rather than for every target Go supports, since
each one costs a full compile of the standard library and `linux/ppc64le` next to
`linux/amd64` tests nothing new. Against the previous commit it fails on exactly
the three Windows targets.

`js/wasm`, `wasip1/wasm` and `plan9` are deliberately not in the list. Their
`syscall` packages define neither `RawSockaddrInet4` nor `AF_INET`, which
`SCTPAddr`'s exported encoding needs, and no version of this package has ever
built for them.

### Error causes were byte-swapped, and nothing could have noticed

`AssocChange.Error`, `RemoteError.Error` and `SendFailed.Error` carry the RFC 9260
§3.3.10 error cause — the answer to "why did this association fail". All three
were decoded with `nativeEndian`. All three are network byte order.

Measured on a live association rather than argued from source: aborting one side
and reading the peer's `SCTP_ASSOC_CHANGE` reported cause **3072** where the
actual cause is `SCTP_ERROR_USER_ABORT`, 12. `0x000c` byte-swapped is `0x0c00`.

The kernel's own uapi header points the wrong way here. It says the field holds
an `sctp_sn_error_t` — `SCTP_FAILED_THRESHOLD` and friends, a small host-order
enum. That is true of `spc_error`, and `PeerAddrChange.Error` is correct as it
stands. It is not true of `sac_error`: every value that reaches it comes from
`SCTP_PERR()`, and every argument to that macro is an `enum sctp_error` member,
each declared `cpu_to_be16`. `sctp_cmd_assoc_failed` takes the cause straight off
the wire as a `__be16` and assigns it into a `__u16` without converting. Checked
against `net/sctp/sm_statefuns.c`, `net/sctp/sm_sideeffect.c` and
`include/linux/sctp.h` rather than inferred.

So the two `__u16` fields are read big-endian, because the bytes in the buffer are
the network representation on either kind of host. `ssf_error` needs a different
rule: it is a `__u32` holding the same `be16` constant, widened by an ordinary
integer promotion, and the promotion is host arithmetic — so on a little-endian
host the swapped value sits in the low half of the word rather than the bytes
being the network form. Reading it natively and then undoing the byte order is
correct on both.

The reason this survived is worth more than the fix. The existing unit test
asserted `0x2222`, which is identical under a byte swap and could not have failed
whichever way the field was read; the kernel-backed test only logged the value.
Every new assertion here uses a byte-asymmetric cause. There is now also a test
that fails if the correction is applied to `spc_error` too, since a blanket
"notification error fields are network order" fix breaks the one field that is
genuinely host order and nothing else would say so.

The causes have names now. A bare number in a log is what let this last: 3072 in
a log looks like a number, and `SCTP_ERROR_USER_ABORT` does not.

### Accepted associations were not close-on-exec

Every socket created in this package asks for `SOCK_CLOEXEC`. `accept4` asked for
nothing, and that is the descriptor it matters most for, because it is a live
association rather than an idle listener.

A child forked while the server is running inherits every connection open at that
moment. It can read and write them. And because it holds the descriptor, closing
this side neither frees the port — a re-listen fails `EADDRINUSE` — nor sends the
peer the reset it is owed: `Abort()` puts nothing on the wire while the child
still has the fd. With `SOCK_CLOEXEC` set, the same abort resets the peer in
2.9 ms.

### `Dial` and `Listen` mutated the caller's address

Both appended the wildcard address into `laddr.IPAddrs`, which is the caller's
value, not a copy. Two things follow.

It is a data race whenever one address is shared between goroutines, which is the
ordinary way to run a client and a server against a fixed endpoint; the race
detector fires on it. And it changes the value's meaning after the call returns:
a `*SCTPAddr` that came back from a `"sctp6"` listen carries `[::]`, so reusing it
for a `"sctp4"` dial fails with `EINVAL`.

The same reasoning had already been applied to `*SndRcvInfo` in this document —
"the old construction was a data race" — and simply had not been applied here.

Only the `AF_INET6` arm is load-bearing: `ToRawSockAddrBuf` already encodes an
empty address list as IPv4 zero, so the `AF_INET` arm produces the bytes it would
have produced anyway. It is kept, because relying on that coupling from the bind
path would be a trap for whoever edits either half next.

### `ReadMsg` returned notifications as application data

The guard was `recvflags&MSG_NOTIFICATION > 0 && c.notificationHandler != nil`, so
with a nil handler a notification fell through to the data branch. `ReadMsg`
discards the flags except for the `MSG_EOR` test, and the kernel sets `MSG_EOR` on
notifications — so a `struct sctp_shutdown_event` came back as a finished message
the peer appeared to have sent. 12 bytes of it, with `err == nil` and `info == nil`.

There is no exported `SetNotificationHandler`, so a caller who dials normally and
then calls `SubscribeEvents` cannot install one. And this document had been
recommending `ReadMsg` as the framing-safe API for exactly the protocol shape it
corrupts.

The first test written for this passed with and without the fix, which is the part
worth recording. It wrote a message and then generated an event: the message is
delivered first, so `ReadMsg` returns before it ever reaches the notification.
Aborting the association leaves the event alone at the head of the receive queue,
which is the case that actually exercises the branch.

### An unknown network string panicked

`favoriteAddrFamily` is vendored from the standard library and picks an address
family from the network name's last byte. The standard library only ever calls it
with a name its own caller has already validated. This package called it with
whatever arrived.

So `ListenSCTP("")` and `DialSCTP("")` panicked with `index out of range [-1]` —
the empty string has no last byte — and `ListenSCTP("tcp")` quietly created an
SCTP socket, because `p` is neither `4` nor `6` and the default arm is reached.
Both reproduced. One helper now validates the name and expands the empty one,
which leaves the vendored file byte-identical to upstream apart from a build tag.

### The read path reported deadlines that were never set

`EAGAIN` was mapped to `os.ErrDeadlineExceeded` unconditionally. On a descriptor
that is non-blocking for some other reason — one handed to `NewSCTPConn`, or one a
`SocketConfig.Control` hook set `O_NONBLOCK` on — an ordinary empty read then
reported a timeout nobody had asked for, and a caller treating that as "my
deadline fired, retry" spins. `AcceptSCTP` and the write path already drew the
distinction; the read path was the one that did not.

### `PeelOff` could not have worked

`sctp_peeloff_arg_t` is 8 bytes with `sd` at offset 4 — both members are 32 bits
in the kernel. The Go struct declared `sd` as `int`, which is 64 bits on every
target anyone runs this on, making the struct 16 bytes with `sd` at offset 8. The
kernel wrote the new descriptor at 4; `PeelOff` read 8, which nothing had
written. It returned an `SCTPConn` wrapping descriptor 0 — the process's standard
input — and leaked the real one.

Measured: kernel 8/`sd`@4 against Go 16/`sd`@8.

It is correct on 32-bit, where Go's `int` is 32 bits, and it had no test on either.

There is a second reason it could not have worked. `sctp_do_peeloff` refuses any
socket that is not one-to-many, and every socket this package creates is
one-to-one, so `PeelOff` returns `EINVAL` for every connection made through `Dial`
or `Accept` here — reproduced. The method is usable through `NewSCTPConn` on a
`SOCK_SEQPACKET` descriptor the caller made themselves, which is the case the ABI
fix is for. The refusal is now asserted, so the doc comment stays honest and a
kernel that started allowing it would be noticed.

### A whole block of socket options was invisible

Optnames 123 to 133 were not merely unwrapped; they were undeclared. The coverage
sweep recorded earlier in this document compared header `#define`s against
constants *referenced in the package* — and a declared constant counts as
referenced, so a declared-but-unwrapped option was structurally invisible to it,
and an undeclared one doubly so. Re-running that sweep against constants reached
by a wrapper is the check that finds this class mechanically.

Probed against a live socket with both sysctls at 0:

| option | | |
|---|---|---|
| `SCTP_STREAM_SCHEDULER` (123) | get ok | set ok |
| `SCTP_INTERLEAVING_SUPPORTED` (125) | get ok | `EPERM` until fragment interleave is non-zero |
| `SCTP_ASCONF_SUPPORTED` (128) | get ok | set ok |
| `SCTP_AUTH_SUPPORTED` (129) | get ok | set ok |
| `SCTP_ECN_SUPPORTED` (130) | get ok | set ok |
| `SCTP_EXPOSE_POTENTIALLY_FAILED_STATE` (131) | get ok | set ok |
| `SCTP_SENDMSG_CONNECT` (126) | `ENOPROTOOPT` | — genuinely absent here |

Two of those change what this package documents.

**AUTH does not need the sysctl.** The AUTH accessors are documented as requiring
`net.sctp.auth_enable`, which only root can set system-wide. `SCTP_AUTH_SUPPORTED`
turns AUTH on for one socket with the sysctl still at 0 — measured.

**`SetAutoAsconf` did nothing.** `net.sctp.addip_enable` defaults to 0, so the
endpoint never negotiates ASCONF and `SetAutoAsconf` succeeded while adding a
local address mid-association put zero ASCONF chunks on the wire. With
`SCTP_ASCONF_SUPPORTED` set before binding: two ASCONF and two ASCONF-ACK.

### The fragment interleave explanation was wrong

This document and the doc comments said the kernel does not police the level, and
that level 2 fails on one-to-one sockets because RFC 6458 §8.1.20 restricts it to
one-to-many. Neither is the mechanism.

Linux keeps a flag rather than a level. Setting 2 reads back as 1, and so does
setting 3 — which is what distinguishes the two explanations, because a
one-to-many restriction would not clamp 3. What §8.1.20 describes for level 2 is
reached instead by negotiating the I-DATA chunk of RFC 8260, which is
`SCTP_INTERLEAVING_SUPPORTED`, and that needs both `net.sctp.intl_enable` and a
non-zero fragment interleave.

### Two tests had never run

`TestAuthDisabledReportsEACCES` and `TestAuthOptionsWithoutSysctl` assert the
errno a caller gets on a stock kernel — `EACCES`, not `EOPNOTSUPP`, which is the
first surprise anyone using AUTH hits. They skip when `net.sctp.auth_enable` is
on, and `run-tests.sh` turns it on for the other seven AUTH tests. So in the
documented harness they had never run once, and the suite read green with that
contract entirely unexercised. Earlier text here said "one skip remains and is
correct" while reporting three; these were the unaccounted pair.

They get their own pass now, with the sysctl back at its default and restored
afterwards.

While looking at that script: its `go vet` step could not fail. `go vet ./... |
grep -v ... || true` takes the pipeline's status from `grep` and then discards
even that, so `set -e` never saw anything. It ran, and it was decorative.

### CI was decorative too

The workflow triggered only on pull requests to `master`. The work happens on
`master-gomaja`, so nothing on this branch had ever run it. Its single step was
`go test -race ./...` with none of the harness setup, no cross-compilation, and no
lint — which is why the Windows break went unnoticed for several commits.

Two corrections to what was assumed about running without the setup. The
multi-homing tests do **not** skip without the added loopback aliases:
`availableLoopbacks` probes by binding, and Linux's `local 127.0.0.0/8` route
makes 127.0.0.2-4 bindable unaided. And the blackhole-gated dial tests **fail**
rather than skip without the iptables rule, because `blackholeAvailable` returns
true on `EINPROGRESS`.

### What the lint sequence can and cannot say

staticcheck and golangci-lint are clean for `linux/amd64`, `arm64`, `arm` and
`s390x` — every target that carries an implementation.

They are not clean for `GOOS=darwin` or `linux/386`, and cannot be made so without
splitting shared structs per platform. `sctp_linux.go` is excluded there, so the
helpers only it calls are reported unused. Ten findings remain, three of them
struct fields that cannot move without moving the struct. `ipsock_linux.go` was
worse: constrained only by its filename, it compiled on `linux/386` as entirely
dead code after its sole consumer was excluded, which is twelve more. It now
carries the same build tag as the file that uses it.

The lesson from the Windows break stands: a "lint is clean" claim has to name the
platform, and the detector for portability is compilation, not `U1000`.

## Reviewing the fixes

The three commits above were then reviewed as adversarially as the code they
fixed. That found two wrong constants — one inherited, one introduced by the
review's own subject — and both had passing tests.

### `SCTP_EOF` selected a partial reliability policy

The per-message send flags were an `iota` block:

```go
SCTP_UNORDERED = 1 << iota
SCTP_ADDR_OVER
SCTP_ABORT
SCTP_SACK_IMMEDIATELY
SCTP_EOF
```

The kernel's sequence is not contiguous. Bits 4 and 5 are `SCTP_PR_SCTP_MASK`,
carrying the partial reliability policy, and `SCTP_EOF` is not an SCTP bit at all
— it is `MSG_FIN`, `0x200`, confirmed from `bits/socket.h`. As the fifth `iota`,
`SCTP_EOF` came out as `1<<4`, which is exactly `SCTP_PR_SCTP_TTL`.

So a caller ending an association by setting `SCTP_EOF` on their last message
selected a PR-SCTP policy instead. No graceful shutdown, no error, and a lifetime
applied to the message they most wanted delivered.

`SCTP_SENDALL` and `SCTP_PR_SCTP_ALL` were missing outright. The block is written
out now, with the policy bits called out as a hole rather than left to be
absorbed by the next value added.

### The PF exposure levels were off by one

This one was introduced two commits earlier, by the work that added the option.

The kernel's enum, from `include/net/sctp/constants.h`, is:

```c
SCTP_PF_EXPOSE_UNSET,    /* 0 */
SCTP_PF_EXPOSE_DISABLE,  /* 1 */
SCTP_PF_EXPOSE_ENABLE,   /* 2 */
```

Zero is not "off"; it means "nobody has said", and the socket follows
`net.sctp.pf_expose`. Read as the off/on/locked shape most of these options have
— which is what happened — "exposed" lands on 1, the value that *disables*
exposure. `SetExposePotentiallyFailed(SCTPPFStateExposed)` turned PF reporting
off, the opposite of the only reason to call it.

The round-trip test could not have caught it. It set a value and read the same
value back, which holds whatever the value means. Both constant blocks are now
pinned to their kernel numbers, which is the assertion a round trip cannot make.

### The same mistake, three commits after fixing it

Adding `SOCK_CLOEXEC` to `PeelOff` broke the darwin and Windows builds
immediately: `syscall.SOCK_CLOEXEC` is not defined there, and `PeelOff` was in
`sctp.go`, which has no build tag.

That is precisely the defect the first of these commits existed to fix, repeated
by the same hand, inside a function whose change was about close-on-exec. It was
caught in seconds by `go build` rather than by a consumer, which is the entire
argument for `TestCrossCompiles` and for keeping the platform partition honest.
`PeelOff` now lives in `sctp_linux.go` with a stub alongside the others.

### Big-endian, measured rather than argued

The cause byte-order work was verified on a little-endian host by aborting a live
association. The other half was reasoning: that reading the two `__u16` fields
big-endian is right on either kind of host, because the bytes in the buffer are
the network representation, while the `__u32` field needs a native read followed
by an `ntohs` because its promotion happened in host arithmetic.

That is now measured. `docker run --platform linux/s390x` gives a real big-endian
Go toolchain under emulation, and every pure decoder test passes there —
including the one asserting `spc_error` stays host order. The socket-backed tests
cannot run: the emulated environment has no SCTP, and `ListenSCTP` fails with
`EPROTONOSUPPORT`. Worth knowing as a standing capability: layout and byte-order
work can be checked on big-endian without hardware, protocol behaviour cannot.

### Two things left as they are, deliberately

`SendFailed.Info.PPID` and `SendFailedEvent.Info.PPID` hold network byte order,
while `SCTPRead` hands back the same struct with the field converted. The same
field means different things depending on where it came from.

That is documented rather than changed. `SndRcvInfo.PPID` has always said it
holds what the kernel delivered and that `SCTPRead` converts, so the notification
path is consistent with the type's contract even though the asymmetry is a trap.
A test pins it, so converging on `SCTPRead`'s convention later is a deliberate
change rather than a silent one under callers who already compensate.

`ParseNotification` does not compare the length in the header against the bytes
present. That is intentional and documented on the type: the kernel truncates a
notification to whatever buffer the caller passed, so the declared length
routinely exceeds what arrived, and treating the difference as an error would
reject every short read rather than the malformed ones. The bounds that matter
are on the buffer, and those are checked.

### Where the option surface actually stands

Re-running the header sweep the right way — against constants reached by a
wrapper rather than merely declared — leaves nothing bindable unbound. What
remains is one-to-many territory: `SCTP_GET_ASSOC_ID_LIST`, the
`SCTP_DSTADDRV4`/`V6` and `SCTP_INIT` ancillary types, and the
`CURRENT`/`FUTURE`/`ALL_ASSOC` identifiers, none of which applies to a
one-to-one socket. Plus `SCTP_SENDMSG_CONNECT`, which this kernel answers with
`ENOPROTOOPT`.

The last two that did apply are bound now: RFC 6951 UDP encapsulation, which is
what lets an association cross a middlebox that drops IP protocol 132, and
RFC 8899 PLPMTUD, which finds a path's MTU without trusting ICMP. Both round-trip
against a live association.

## Round five: the edges

A sixth review pass, run the same way as the last — independent finders across
new code, kernel ABI, concurrency, documentation truth, test holes and API
surface, each finding then handed to two agents whose job was to refute it. The
struct-layout and constant surface came back clean again. Everything below is at
an edge: descriptor lifecycle, zero-length buffers, word size, and prose.

### `Abort()` did nothing while a reader was parked

`abortSctpSocket` armed `SO_LINGER{1,0}` and closed the descriptor. That is
enough on an idle socket and not enough when another goroutine is blocked in
`recvmsg`: the blocked call holds a reference to the `struct file`, so `close()`
only unhooks the descriptor number and defers the final release. `sctp_close`
never runs, so the ABORT is never emitted.

Captured on loopback, before and after:

| | before | after |
|---|---|---|
| ABORT (chunk 6) | absent | frame 5 |
| SHUTDOWN (chunk 7) | frame 7 | absent |
| parked reader | still blocked at 4s | returned in 5ms |

The pre-fix capture also shows HEARTBEAT and HEARTBEAT_ACK: the association was
alive and being maintained throughout, and was eventually torn down *gracefully*
with SHUTDOWN/SHUTDOWN_ACK/SHUTDOWN_COMPLETE. So `Abort()` — which returned
`nil` in 29µs — did the exact opposite of what it promises, and the caller had
no way to know.

The fix is `shutdown(fd, SHUT_RD)` before the close. `SHUT_RD` specifically:
`SHUT_RDWR` and `SHUT_WR` also wake the reader, so they pass the waking test,
but they ask for a graceful teardown and the capture then shows SHUTDOWN and no
ABORT at all. That mutation is caught by `TestAbortReportsTheUserAbortCause`,
which asserts the peer sees `SCTP_COMM_LOST`.

### An accept deadline leaked into every connection

`sctp_copy_sock` copies `sk_rcvtimeo` onto the socket the kernel creates for a
new association, and the accept deadline is implemented by putting `SO_RCVTIMEO`
on the listener. So the polling accept loop — a short deadline so the server can
notice a shutdown flag between accepts — handed out connections already armed to
time out. The `SCTPConn` wrapping the descriptor records no deadline, so the read
path's corrective `applyTimeout` never runs.

Measured: a `Read` on a connection that never had a deadline of its own returned
after 309ms against a 300ms accept window, with `SO_RCVTIMEO` reading back
`0s300000us`. And because no deadline is recorded locally the errno is not
mapped, so the caller gets a bare `EAGAIN` for which
`errors.Is(err, os.ErrDeadlineExceeded)` is false — the failure cannot even be
classified.

### A zero-length read consumed a byte

`recvmsg` substitutes a one-byte scratch iovec when the data buffer is empty and
the control buffer is not, mirroring the stdlib. The control buffer on this path
is never empty, so a caller's empty slice became a one-byte read into a
package-local variable: the kernel dequeued a payload byte, `recvmsg` returned 1,
and `Read` returned `n=1` for a zero-length buffer. Eight bytes queued, `Read(nil)`
returned 1, the next read returned `"BCDEFGH"`.

It is not only `Read(nil)` that gets there. The ordinary framing loop reads into
`b[total:]`, which is empty the moment the buffer fills — so `total` grew past
`cap` and the caller's next line, `b[:total]`, panicked.

### Four option structs were wrong on 32-bit

Most SCTP option structs carrying an address are `packed, aligned(4)` and so are
identical everywhere. Four are not, and their `sockaddr_storage` keeps the
alignment of the `unsigned long` inside it — which follows the word size:

| | linux/amd64 | linux/arm/v7 |
|---|---|---|
| `sockaddr_storage` | align 8 | align 4 |
| `sctp_udpencaps` | 144, addr@8 | 136, addr@4 |
| `sctp_probeinterval` | 144, addr@8 | 136, addr@4 |
| `sctp_paddrthlds` | 144, addr@8 | 136, addr@4 |
| `sctp_paddrthlds_v2` | 144, addr@8 | 140, addr@4 |
| `sctp_paddrparams` (packed) | 156, addr@4 | 156, addr@4 |

The Go mirrors baked in the 64-bit answer, and `sctp_linux.go` is tagged
`linux && !386`, so `linux/arm` and `linux/mips` compile the real setsockopt
path. The setters demand an exact `optlen` and would be refused outright; the
getters only check the length is *at least* `sizeof`, so an oversized 144 is
accepted, the kernel reads the address from the wrong offset and writes back 136
bytes, leaving the trailing field holding whatever the caller passed in. That
one is silent.

`sctp_assoc_stats` is a case the review missed and the probe caught: it is 256
bytes with its counters at 136 on **both** word sizes, and only the
`sockaddr_storage` between them moves — 8 on 64-bit, 4 on 32-bit, the difference
absorbed by padding. No length check can see that at all.

All five are marshalled through derived offsets now. The mutation results are
the interesting part: pinning the alignment to 8, giving `sctp_paddrthlds_v2` the
same size as v1, and hard-coding the `sctp_assoc_stats` address offset all
**survive on amd64 and fail on arm** — so the layout assertions run under
`linux/arm/v7` in CI, and a formula test checks both alignments on any host.

### Tests that could not fail

- **Option numbers 32 to 133 were unpinned.** Their only coverage was set/get
  round trips through the same constant, which cannot fail whatever the number
  is. Swapping `SCTP_ASCONF_SUPPORTED` with `SCTP_AUTH_SUPPORTED` left the
  complete suite green while a live probe showed `SetAuthSupported(true)` reading
  back 1 through the wrong option, with AUTH still off and dynamic address
  reconfiguration switched on instead.
- **`NotificationMaxSize` was never compared against anything.** Shrinking it
  from 1024 to 128 survived the full suite — and 128 is below the 148 of
  `SCTP_PEER_ADDR_CHANGE`, so a caller sizing their buffer as documented would
  read the path-failure event in fragments and reject every one as truncated.
- **`sctp_unsupported.go` is executed by nothing.** `go build` for a cross
  target skips `_test.go` files, `go vet` type-checks without running, and every
  CI job was `ubuntu-latest`. Twenty-six of the thirty stubs could return `nil`
  with the suite green — and `ListenSCTP` returning `(nil, nil)` makes a caller
  who correctly checks `err` panic on the next line. There is a `macos-latest`
  job now, and the test covers all thirty.
- **`TestReadMsgZeroLengthMessage` had never run.** Its guard skipped when the
  zero-length write was refused, and the kernel always refuses one. Unlike the
  two AUTH skips, no second pass reached it. It now asserts the contract that
  exists: `SCTPWrite` of an empty buffer is `EINVAL`, `Conn.Write` is `(0, nil)`.
- **`TestSCTPReadRetriesEINTRUnderLoad` passes with the retry deleted.** It
  dials sixty peers and asserts no read returned `EINTR`, but the read path's own
  comment records that EINTR appears at a thousand peers and never at a hundred.
  Deleting the retry left it green in 0.13s. The replacement pins the reader to
  an OS thread and delivers SIGURG to that thread with `tgkill` while it is
  blocked in `recvmsg` — the read deadline is what makes the signal observable,
  since Go installs handlers with `SA_RESTART` and only a socket carrying
  `SO_RCVTIMEO` returns `EINTR` anyway.
- **No test ever created an AF_INET6 endpoint**, so `bindLocal`'s v6 wildcard
  could become `IPv4zero` undetected. The new test skips on an independent
  syscall-level probe rather than on `ListenSCTP`'s own error — the first version
  skipped instead of failing under exactly the mutation it existed to catch.
- **`blackholeAvailable` reported a false positive.** It inspected only the
  immediate return of one non-blocking connect, so a gateway that ICMPs a few
  milliseconds later still read as "blackholed" and the tests it guards failed on
  a surprising errno instead of skipping. It now polls `SO_ERROR`; in Docker the
  gateway answers `ENOPROTOOPT` (errno 92) and the tests skip cleanly.

### Documentation that was wrong

`PathCpThld` was documented as the count at which the stack stops probing a
Potentially Failed path. It is the RFC 7829 §5 Primary Path Switchover
threshold. The kernel stores it in `transport->ps_retrans` and reads it in
exactly one place:

```c
if (transport->error_count > transport->ps_retrans &&
    asoc->peer.primary_path == transport &&
    asoc->peer.active_path != transport)
        sctp_assoc_set_primary(asoc, asoc->peer.active_path);
```

Nothing consults it when deciding whether to keep heartbeating. Confirmed live:
the value read back through the getter tracks `net.sctp.ps_retrans` exactly
(65535 → 1234 → 7) while `PathPfThld` tracks `net.sctp.pf_retrans`
independently. So the `0xffff` default disables switchover; it does not mean
probing continues indefinitely.

`SCTPPFStateDisabled` was documented as making `GetPeerAddrInfo` report a
potentially-failed path as `SCTP_ACTIVE`. It makes it fail:

```c
if (transport->state == SCTP_PF &&
    transport->asoc->pf_expose == SCTP_PF_EXPOSE_DISABLE) {
        retval = -EACCES;
        goto out;
}
```

and the `SCTP_UNKNOWN → SCTP_ACTIVE` fixup happens after that check. The sysctl
default is `UNSET` (0), not `DISABLE`, and at `UNSET` the PF state *is* visible —
only the notification is withheld. So the comment told every default-socket user
they would not see states they will in fact see.

Also corrected: `SetAutoAsconf` needs a socket bound to the **wildcard**, not
merely a bound one (`!sctp_is_ep_boundall(sk) && *val` → `EINVAL`), which rules
out the listener-bound-to-named-addresses case the old advice pointed at;
`SCTP_PR_SCTP_ALL` is not a send flag at all, its only two kernel uses being in
the PR status getters; `SCTP_AUTH_FREE_KEY` is local and says nothing about the
peer; `SetAuthKey`'s documented 8192-byte bound does not exist, the kernel's is
`USHRT_MAX`; error causes 11 to 13 are attributed to RFC 9260 by IANA, not to the
Implementation Guide, and 14 is Unassigned; RFC 6951 is updated by RFC 8899, not
RFC 9899, which is a YANG ACL model. And roughly thirty RFC section numbers were
wrong — RFC 4895 has no §6.5 to §6.9 at all, RFC 6525 has no §6.5, and the AUTH
socket options are defined by RFC 6458 §8, not by RFC 4895. Each was checked
against the RFC text rather than corrected from the review's list.

The platform promise was overstated in two directions: `plan9`, `js/wasm` and
`wasip1/wasm` do not compile (`syscall.RawSockaddrInet4` is undefined there),
and `ResolveSCTPAddr` and the deadline setters work everywhere rather than
returning `ErrUnsupported`, so the `errors.Is` gate shown next to the claim never
trips for them.

## Round six: twenty mutations against the suite as a whole

Individual fixes here are mutation-tested as they are made. The suite as a whole
never had been. Twenty mutations were applied across `sctp.go` and
`sctp_linux.go` — one per run, the complete suite each time through
`run-tests.sh`, both source files restored from a pristine copy between every
one so a mutation that fails to apply cannot leak into the next.

```
13 caught   6 survived   1 failed to compile
```

The six survivors are the point of the exercise, and they do not mean six
missing tests. Two were, three cannot be observed on this platform at all, and
one is a branch the kernel never reaches.

### Two mutants that never ran are worth as much as the ones that did

The generator requires each target string to match **exactly once** in its file,
and aborts otherwise, on the reasoning that a zero- or multi-match is a defect in
the mutation rather than a finding about the code. It earned that immediately:

```
mutation htons-alwaysswap: '\tif nativeEndian == binary.LittleEndian {'
matches 2 times in sctp.go, want exactly 1
```

`htons` and `htonl` carry a byte-identical guard. Matching on the condition alone
would have silently mutated whichever came first, and the conclusion drawn would
have been about the wrong function.

The other is subtler. Deleting `SetInitMsg`'s upper bound did not compile:

```
./sctp.go:71:2: "math" imported and not used
```

`math.MaxUint16` at line 1592 is the only use of the `math` import in the whole
file, so removing the comparison orphans the import. **A mutant that does not
build tests nothing while looking like a result** — it would have been recorded
as a compile error and quietly counted as "the suite noticed". Retargeted to
`math.MaxInt32`, which keeps the import live, still rejects negatives, and lets
70000 through to truncate, it is caught by
`TestSetInitMsgRejectsOutOfRangeValues`. `math.MaxUint32` would not do: as an
untyped constant compared against an `int` it overflows on 32-bit targets.

### The control buffer was sized against one cmsg; the kernel sends three

Shrinking the pooled `oob` buffer from 254 bytes to **48** left the entire suite
green. 48 is not an arbitrary number — it is exactly
`CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))`.

The comment above `oobPool` explained the size by reasoning about one control
message at a time: `SCTP_SNDRCV` is 32 bytes of payload plus a 16-byte header,
and `SCTP_RCVINFO` and `SCTP_NXTINFO` are smaller again. Every part of that is
true and the conclusion does not follow, because they are not delivered one at a
time. Measured on 6.12 with every info option enabled and a message queued
behind the one being read:

```
read n=7 oobn=128 MSG_CTRUNC=false
  cmsg level=132 type=4 (SCTP_NXTINFO) len=32 space=32
  cmsg level=132 type=3 (SCTP_RCVINFO) len=44 space=48
  cmsg level=132 type=1 (SCTP_SNDRCV)  len=48 space=48
                                       total 128
```

**`SCTP_NXTINFO` comes first**, which is what makes an undersized buffer quiet.
`SCTP_SNDRCV` is written last, so the truncation takes the description of the
message in the caller's hand while still delivering the prediction of the next
one — and the read itself succeeds. The kernel says so only through
`MSG_CTRUNC`, which nothing in this package inspects.

That ordering is also why `TestSCTPReadNextInfoReportsTheQueuedMessage` passed at
48 bytes despite subscribing both. Its subscription needs 80:

```
DATA_IO+NXTINFO: oobn=80 MSG_CTRUNC=false
with a 48-byte control buffer: oobn=48 MSG_CTRUNC=true
```

Its first read wants `NxtInfo`, which survives the truncation; its second read
happens with nothing queued behind, so the kernel emits no `NXTINFO` at all and
the lone `SCTP_SNDRCV` fits in 48 exactly. Each assertion found the one cmsg it
was looking for, and the loss landed between them.

`TestPooledOobHoldsEveryInfoCmsgAtOnce` closes it from both ends: it requires
`MSG_CTRUNC` clear with both structs returned, and separately measures what one
read carries into an oversized buffer and requires the pool to be at least that
large — so it keeps holding if a kernel starts sending more.

### An accept could report a deadline the caller never set

`AcceptSCTP` converts `EAGAIN` to `os.ErrDeadlineExceeded` only when a deadline
was programmed through `SetDeadline`, and making that conversion unconditional
survived the suite. The two cases are identical at the syscall — `sctp_accept`
takes its wait budget from `SO_RCVTIMEO` and reports expiry as `EAGAIN`, the same
errno a non-blocking accept gives — so only the listener's own record
distinguishes them.

`SyscallConn` is what makes the untested case reachable. A caller who sets
`SO_RCVTIMEO` on the descriptor themselves leaves `rcvTimeoSet` at 0, so the
package neither clears the timeout nor knows it is there:

```
accept after 204.116ms with SO_RCVTIMEO set out-of-band and no package-level
deadline: err=resource temporarily unavailable EAGAIN=true
ErrDeadlineExceeded=false
```

Reporting a deadline there would invent one the caller never set, on a listener
they configured themselves. `TestAcceptReportsEAGAINRatherThanAPhantomDeadline`
covers it. The read path already drew the same distinction and already had a test
for it; only the accept path was uncovered.

### Three survivors that no test on this host can catch

Recorded rather than papered over, because each is a mutation that changes the
source and cannot change the behaviour here:

**`EAGAIN` alone no longer mapping to a deadline.** `toDeadlineErr` tests for
`EAGAIN || EWOULDBLOCK`; on Linux the two errnos are the same value, so dropping
either arm is a no-op. Expected to survive before the run started, and it did.

**`htons` swapping unconditionally.** The swap is guarded by
`nativeEndian == binary.LittleEndian`, so on amd64 the guard is always true and
the mutant is byte-for-byte equivalent. This one is not untestable, only
unrunnable — it needs a big-endian machine, and under
`docker run --platform linux/s390x` an assertion that already existed fails
immediately:

```
--- FAIL: TestToRawSockAddrBufEncodesEachFamily/empty_address_list_falls_back_to_IPv4_zero
    sctp_untested_test.go:244: port encoded as 0x3412, want 0x1234
```

The gap was the platform, not the assertion. The `layout-32bit` CI job is now
`cross-layout`, a matrix over `linux/arm/v7` and `linux/s390x` sharing one list
of socket-free tests, so word size and byte order are both covered by the same
job. Four tests are excluded because they open a socket and qemu-user does not
forward `SOL_SCTP`: `TestSackTimerLayoutAndRoundTrip`,
`TestResetStreamsWireLayout` and the two `TestSubscribedEvents*`.

**`hasEstablishedAssoc` returning a bare `true`.** The function returns false on
a `getsockopt` error and `status.State != 0` otherwise, and replacing the second
with `true` changes nothing, because the second never decides anything.
`SCTP_STATUS` was probed across every state a socket passes through before an
association exists:

```
one-to-one, fresh              errno=invalid argument
one-to-one, bound              errno=invalid argument
one-to-one, listening          errno=invalid argument
one-to-many, fresh             errno=invalid argument
one-to-many, bound             errno=invalid argument
one-to-many, listening         errno=invalid argument
one-to-one, COOKIE_WAIT        errno=invalid argument
one-to-one, ESTABLISHED        OK state=4 assoc=152471
one-to-one, after peer close   errno=invalid argument
one-to-one, after own shutdown errno=invalid argument
```

`EINVAL` in every case, and only an established association answers at all —
`sctp_id2assoc` declines to hand back an association on a one-to-one socket
unless the socket is itself `ESTABLISHED` or `CLOSING`. So the doc comment's
claim that `SCTP_STATUS` "reports state 0 when there is nothing to describe" was
never observed. The check stays as a guard; the comment now says it is one.

### And one branch the kernel does not reach

`dialSCTPExtConfigContext` tolerates `EALREADY` from its connect alongside
`EINPROGRESS`, and removing the tolerance survived. It is the first connect on a
socket the function just created, so the kernel has no earlier attempt to find:

```
first connect on a fresh non-blocking socket, 200 attempts: map[EINPROGRESS:200]
```

Zero `EALREADY` in two hundred. What keeps the tolerance is the `control` hook,
which is handed the descriptor before that point and could have connected it —
but the comment implied a live path and now says defensive.

### A test that raced against itself, found while validating the above

Running the suite under `-race` to check the two new tests turned up a failure in
one neither of them touches:

```
--- FAIL: TestSCTPConnectEALREADYOnBlockingSocketMidHandshake (340.34s)
    sctp_already_test.go:248: second SCTPConnect gave connection timed out,
                              want success once the association exists
```

**The first attempt to attribute it was a bad experiment.** HEAD ran first and
the working tree second in every round, so "which tree" and "which slot" were one
variable, and the result — HEAD 3 passes, working tree 2 failures — read as
though the change had caused it. Reversing the order broke the correlation.
Across both orders it is 3 failures in 12, split cleanly by neither variable,
which is far too small a sample to separate anything. The same trap this
document already records for `TestStreams`, walked into again.

What settled it was not the counting. Every changed line in `sctp.go` and
`sctp_linux.go` this round is a comment, and neither new test matches the `-run`
filter used, so both trees executed identical code.

The mechanism is a race between the test's own two goroutines. It starts one
that calls `SCTPConnect` to the blackholed address and then probes with a second
`SCTPConnect` on the same socket, expecting to find the association the first
created — but `close(started)` says only that the goroutine was scheduled, not
that its connect reached the kernel. When the probe arrives first, **it** becomes
the call that creates the association, and on a blocking socket to an address
that never answers it waits out the entire INIT retransmission schedule: a flat
342s, ending in `ETIMEDOUT`, reported as a failure of a branch it never reached.
Every failing run took 341.6s to 342.2s; every passing run took 1.3s.

The fix is a precondition rather than a sleep, and it exists because the test's
own comment was wrong about what could be observed:

> Without an observable state to poll — SCTP_STATUS reports EINVAL mid-handshake

`SCTP_STATUS` does answer `EINVAL` mid-handshake, confirmed by the probe above.
But `/proc/net/sctp/assocs` lists the association in `COOKIE_WAIT` within 50 ms
of the connect beginning, and the suite already reads that file for
`countAssocs`. `waitAssocExists` polls `getsockname` for the port the connect
autobinds, then waits for a row carrying it — reading the `LPORT` column index
out of the header rather than hard-coding it, since the row is positional.

Measured after the fix, on the same host, same conditions:

```
30 runs under -race:  PASS=30  FAIL=0     (before: 3 failures in 12)
```

And it keeps its teeth, which is the risk with any fix that makes a test wait
for something. Making `isEstablishedAssoc` return false for `EALREADY` on every
socket — the conversion this test exists to cover — still fails it, and now in
1.47s rather than 342s, because the test no longer has to exhaust a timeout to
discover the branch was never reached.

### What the exercise says about the suite

Two real holes in twenty mutations, both in code with tests either side of the
gap rather than in code nobody had covered. The `oob` buffer had two tests
already, for aliasing and for crosstalk, and neither touched its size; the
deadline conversion had a test on the read path and none on the accept path. The
useful signal was not "this function is untested" but "this function is tested
for the property somebody thought of".

The three equivalent mutants are worth as much as the two holes, in a different
way: each one had a comment above it asserting behaviour that was never measured,
and two of the three comments were wrong. So did the flaky test's own comment,
which is what had kept the race in place.

One process note. An early validation run reported a red suite that had never
executed a single test: `run-tests.sh` runs under `set -e`, and
`have=$(ip -4 addr show dev lo | grep -c ...)` fails the script outright on a
host without `iproute2`. The image reached for was stock `golang:1.24-bookworm`,
which carries neither `ip` nor `iptables`; only the `sctp-test` image built from
`testdata/Dockerfile` does. The tell was a failure with no `--- FAIL` line
anywhere in the log — the same signature as a suite killed by contention, and
worth recognising, because both look like "the tests failed" and neither is.
