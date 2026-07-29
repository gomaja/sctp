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

## Test flakiness

`TestSCTPConcurrentAccept` used to fail about one run in four with
`# of failed Dials: 1`. `SCTP_SOCKOPT_CONNECTX3` reports `EISCONN` once the
handshake has completed, which under load happens before the call returns, and
`SCTPConnect` reported that as a failure for a socket that was connected and
writable. Fixed.

`TestStreams` used to fail twelve runs in fifteen as part of the full suite,
while passing on its own. Two causes, and neither shows without the other:

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
as noise. Together: twelve failures in fifteen runs before, one and two in two
fifteen-run measurements after.

The method matters as much as the fix. The cause was invisible in the test
output and in a capture of the whole suite, where 1012 INIT chunks and 892
INIT_ACKs across ninety tests said nothing. Filtering the capture to the one
listener port under test gave it immediately:

```
INIT      = 128
INIT_ACK  =  15
ABORT     = 121
```

Run one measurement at a time, filter captures to the port that matters, and
pair comparisons against a baseline rather than running separate batches.
