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

`TestStreams` fails in this environment on an unmodified tree as well — it
opens 128 concurrent associations against one listener and is flaky under
container networking. Skip it to see the rest:

```sh
docker run --rm --privileged -v "$PWD":/src -w /src sctp-test \
    go test -count=1 -skip TestStreams ./...
```

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
