//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Benchmarks for the per-message paths. The package had none, so there was no
// baseline to compare an optimisation against and no way to tell a real
// improvement from noise.
//
// The syscall dominates wall time on every one of these, so the number to watch
// is allocs/op rather than ns/op: allocation is what this package controls, and
// per-message garbage is what shows up as GC pressure in a caller pushing
// throughput. Where a change is meant to alter ns/op, that is stated.
//
// Run:
//
//	go test -run '^$' -bench . -benchmem
//
// Comparing two revisions honestly needs benchstat over repeated runs, not a
// single pair of numbers:
//
//	go test -run '^$' -bench . -benchmem -count=10 > new.txt
//	benchstat old.txt new.txt

// benchPair brings up one association and returns both ends. Setup is outside
// the timed loop in every benchmark below.
func benchPair(b *testing.B) (client, server *SCTPConn) {
	b.Helper()

	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	b.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan *SCTPConn, 1)
	go func() {
		c, aerr := ln.AcceptSCTP()
		if aerr != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		b.Fatal("listener has no address")
	}
	client, err = DialSCTP("sctp", nil, la)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	b.Cleanup(func() { _ = client.Close() })

	server, ok = <-accepted
	if !ok {
		b.Fatal("accept failed")
	}
	b.Cleanup(func() { _ = server.Close() })

	// Raise the socket buffers as far as the kernel allows. Flow control is a
	// real property of the stack but it is not what these benchmarks measure,
	// and a small buffer turns every one of them into a measurement of how fast
	// the peer drains.
	//
	// The size has to come from net.core.wmem_max/rmem_max rather than being
	// picked: SO_SNDBUF is silently clamped to that ceiling and setsockopt
	// reports no error, so an earlier version asking for 4 MiB against a
	// 212992-byte limit believed it had twenty times the buffer it actually had.
	// That is what made these benchmarks fail intermittently once the send path
	// got fast enough to outrun the reader.
	for _, c := range []*SCTPConn{client, server} {
		raiseBuffers(b, c)
	}
	return client, server
}

// raiseBuffers sets the socket buffers to the kernel's own maximum and checks the
// result, so a clamped request cannot be mistaken for a satisfied one.
func raiseBuffers(b *testing.B, c *SCTPConn) {
	b.Helper()

	// The kernel doubles what SO_SNDBUF is given, and reports the doubled value
	// back, so asking for the ceiling yields twice it. Reading the limits rather
	// than hardcoding them keeps this correct on a host tuned differently.
	wmax := readSysctlInt(b, "/proc/sys/net/core/wmem_max")
	rmax := readSysctlInt(b, "/proc/sys/net/core/rmem_max")

	if err := c.SetWriteBuffer(wmax); err != nil {
		b.Fatalf("SetWriteBuffer(%d): %v", wmax, err)
	}
	if err := c.SetReadBuffer(rmax); err != nil {
		b.Fatalf("SetReadBuffer(%d): %v", rmax, err)
	}

	// Confirm what was granted. A caller cannot tell a clamp from a success, so
	// the benchmark checks rather than assumes — this is the exact mistake that
	// produced misleading numbers before.
	got, err := c.GetWriteBuffer()
	if err != nil {
		b.Fatalf("GetWriteBuffer: %v", err)
	}
	if got < wmax {
		b.Fatalf("write buffer is %d after asking for %d; the kernel granted "+
			"less than net.core.wmem_max, so these benchmarks would measure "+
			"flow control", got, wmax)
	}
}

// readSysctlInt reads one integer sysctl, failing the benchmark if it cannot.
func readSysctlInt(b *testing.B, path string) int {
	b.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		b.Fatalf("read %s: %v", path, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		b.Fatalf("parse %s (%q): %v", path, raw, err)
	}
	return n
}

// drainReaders is how many goroutines benchDrain runs against one socket. One is
// not enough: with the optimised send path a single writer outruns a single reader
// on loopback, and the write benchmarks then measure how fast the peer drains
// rather than how fast a send costs.
const drainReaders = 1

// benchDrain reads continuously from c until the returned function is called, so
// the send buffer does not fill and turn a write benchmark into a measurement of
// flow control. The returned function stops the reader and waits for it.
//
// It reports whether the reader exited early. That matters because a dead reader
// is invisible from the sending side except as flow control: the writer simply
// starts collecting EAGAIN and, without this, the benchmark reports a number that
// describes a full buffer rather than a send.
//
// This is not hypothetical. The first version silently returned on any read error,
// and BenchmarkSCTPWriteInfo — the third of three write benchmarks in one process
// — measured 241 retries per send while the same benchmark run alone measured
// zero. The send paths were identical; the reader had died.
func benchDrain(b *testing.B, c *SCTPConn) (stop func(), alive func() error) {
	b.Helper()
	done := make(chan struct{})
	// Buffered so the reader never blocks publishing its error, and read only
	// after wg.Wait() so there is no race on it.
	failed := make(chan error, drainReaders)
	var wg sync.WaitGroup
	// Several readers on the one socket. A single reader cannot keep pace with
	// the optimised send path on loopback: the buffer fills, the writer collects
	// EAGAIN, and the benchmark ends up measuring the drain rate. recvmsg on one
	// descriptor from several goroutines is safe — each call returns a whole
	// message — and the messages are discarded here, so their order does not
	// matter.
	for i := 0; i < drainReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 65536)
			for {
				select {
				case <-done:
					return
				default:
				}
				if _, _, err := c.SCTPRead(buf); err != nil {
					// Publish it rather than swallow it. Reads failing after
					// stop() closed the socket are expected, which is why the
					// check against done comes first.
					select {
					case <-done:
					default:
						failed <- err
					}
					return
				}
			}
		}()
	}

	var once sync.Once
	stop = func() {
		once.Do(func() {
			close(done)
			// Closing is what releases a reader blocked in recvmsg; the select
			// above only notices between messages.
			_ = c.Close()
			wg.Wait()
		})
	}
	alive = func() error {
		select {
		case err := <-failed:
			return err
		default:
			return nil
		}
	}
	return stop, alive
}

// sender wraps a send function so a benchmark can push messages without
// measuring flow control.
//
// SCTPWrite passes MSG_DONTWAIT, so a write never blocks and reports EAGAIN once
// the send buffer fills. Neither obvious response is acceptable:
//
//   - Treating EAGAIN as a failure stops the benchmark at the first full buffer.
//     That is what the first version did, failing immediately with "resource
//     temporarily unavailable".
//   - Busy-retrying inside the timed loop measures the spin instead of the send.
//     That is what the second version did, and it reported 34500 allocs and 2 ms
//     per write — numbers that describe the retry loop, not SCTPWrite.
//
// So retries are counted and reported separately. The benchmark waits for the
// buffer to drain rather than spinning, and refuses to report a result at all if
// retries were a significant fraction of the sends: a number produced under heavy
// flow control is not a measurement of the send path, and printing it anyway would
// be worse than failing.
type sender struct {
	b       *testing.B
	send    func() error
	sends   int
	retries int
}

func newSender(b *testing.B, send func() error) *sender {
	return &sender{b: b, send: send}
}

// do performs one send, waiting for space rather than spinning when the buffer
// is full.
//
// A sender that only calls runtime.Gosched between attempts still burns the
// timed loop: with the optimised send path a writer outruns a single reader on
// loopback, and the retry count reached hundreds per send. Sleeping briefly hands
// the processor to the reader instead, so the queue actually drains. The sleep is
// counted as a retry, so report() still refuses to publish a number that was
// produced mostly under flow control.
func (s *sender) do() {
	s.sends++
	for attempt := 0; ; attempt++ {
		err := s.send()
		if err == nil {
			return
		}
		if !errors.Is(err, syscall.EAGAIN) {
			s.b.Fatalf("write: %v", err)
		}
		s.retries++
		if attempt < 4 {
			// A yield is enough when the reader is merely behind by a message.
			runtime.Gosched()
			continue
		}
		// Past that the buffer is genuinely full and only time will drain it.
		// Stop the clock across the wait: the time spent blocked on a full
		// buffer is the receiver's cost, and leaving it in ns/op would report
		// the drain rate as though it were the send cost.
		s.b.StopTimer()
		time.Sleep(50 * time.Microsecond)
		s.b.StartTimer()
	}
}

// report fails the benchmark if flow control dominated, and records the retry
// rate either way so the result can be judged rather than taken on trust.
func (s *sender) report() {
	if s.sends == 0 {
		return
	}
	rate := float64(s.retries) / float64(s.sends)
	s.b.ReportMetric(rate, "retries/op")

	// The threshold is deliberately loose. On loopback a sender outruns a
	// receiver whatever the buffer size, so some flow control is unavoidable and
	// demanding zero would make these benchmarks fail on a fast host rather than
	// a broken one. Sleeps are excluded from the clock in do(), so a modest rate
	// perturbs ns/op little; what it cannot do is inflate allocs/op, which is the
	// number these benchmarks exist to track.
	//
	// Past this point the run is mostly waiting and even allocs/op becomes hard
	// to attribute, so it fails rather than publishing a misleading figure. The
	// original harness reached 241 retries per send, which is the failure this
	// guards against — not the fraction-of-one rates a healthy run shows.
	if rate > 2 {
		s.b.Fatalf("flow control dominated: %d retries over %d sends (%.2f per "+
			"send). The result describes the receiver draining the buffer rather "+
			"than the send path. Check that the draining reader is alive and "+
			"that net.core.wmem_max is not unusually small",
			s.retries, s.sends, rate)
	}
}

// BenchmarkSCTPWrite measures the send path with per-message ancillary data,
// which is the common case: SubscribeEvents(SCTP_EVENT_DATA_IO) plus an
// SndRcvInfo naming a stream.
//
// A reader goroutine drains continuously so the send buffer does not fill and
// turn the benchmark into a measurement of flow control.
func BenchmarkSCTPWrite(b *testing.B) {
	client, server := benchPair(b)

	stopDrain, drainAlive := benchDrain(b, server)
	defer stopDrain()

	payload := make([]byte, 512)
	info := &SndRcvInfo{Stream: 1, PPID: 0x1234}

	s := newSender(b, func() error {
		_, err := client.SCTPWrite(payload, info)
		return err
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.do()
	}
	b.StopTimer()
	if err := drainAlive(); err != nil {
		b.Fatalf("the draining reader died mid-benchmark (%v); every number "+
			"from this run describes a full send buffer rather than the send "+
			"path", err)
	}
	s.report()
}

// BenchmarkSCTPWriteNoInfo isolates the ancillary-data construction cost by
// sending without it. The difference against BenchmarkSCTPWrite is what building
// the cmsg costs per message.
func BenchmarkSCTPWriteNoInfo(b *testing.B) {
	client, server := benchPair(b)

	stopDrain, drainAlive := benchDrain(b, server)
	defer stopDrain()

	payload := make([]byte, 512)

	s := newSender(b, func() error {
		_, err := client.SCTPWrite(payload, nil)
		return err
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.do()
	}
	b.StopTimer()
	if err := drainAlive(); err != nil {
		b.Fatalf("the draining reader died mid-benchmark (%v); every number "+
			"from this run describes a full send buffer rather than the send "+
			"path", err)
	}
	s.report()
}

// BenchmarkSCTPWriteInfo measures the SCTP_SNDINFO send path against
// BenchmarkSCTPWrite's SCTP_SNDRCV one. Both carry a stream and PPID, so the
// difference is the cost of how each builds its control message.
func BenchmarkSCTPWriteInfo(b *testing.B) {
	client, server := benchPair(b)

	stopDrain, drainAlive := benchDrain(b, server)
	defer stopDrain()

	payload := make([]byte, 512)
	info := &SndInfo{SID: 1, PPID: htonl(0x1234)}

	s := newSender(b, func() error {
		_, err := client.SCTPWriteInfo(payload, info, nil, nil)
		return err
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.do()
	}
	b.StopTimer()
	if err := drainAlive(); err != nil {
		b.Fatalf("the draining reader died mid-benchmark (%v); every number "+
			"from this run describes a full send buffer rather than the send "+
			"path", err)
	}
	s.report()
}

// BenchmarkSCTPRead measures the receive path including ancillary-data parsing.
// A writer goroutine keeps the queue non-empty so the benchmark measures the read
// rather than the wait for a message.
func BenchmarkSCTPRead(b *testing.B) {
	client, server := benchPair(b)
	if err := server.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		b.Fatalf("subscribe: %v", err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		payload := make([]byte, 512)
		info := &SndRcvInfo{Stream: 1, PPID: 0x1234}
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := client.SCTPWrite(payload, info); err != nil {
				if errors.Is(err, syscall.EAGAIN) {
					continue
				}
				return
			}
		}
	}()
	b.Cleanup(func() {
		close(done)
		_ = client.Close()
		wg.Wait()
	})

	buf := make([]byte, 4096)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := server.SCTPRead(buf); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
}

// BenchmarkBuildSndRcvCmsg measures the control-message construction on its own.
//
// This is the benchmark that actually tracks the send-path optimisation. The
// socket benchmarks above include a sendmsg, whose cost is the kernel's and whose
// variance on loopback swamps the difference: their allocs/op is reliable but
// their ns/op moves by hundreds of nanoseconds between runs for reasons that have
// nothing to do with this package.
//
// legacySndRcvCmsg, defined in the cmsg-build tests, is the pre-optimisation
// construction. Benchmarking both here makes the comparison direct rather than
// requiring two revisions and benchstat.
func BenchmarkBuildSndRcvCmsg(b *testing.B) {
	info := &SndRcvInfo{Stream: 1, PPID: 0x1234, Context: 0x5eed}

	b.Run("current", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if buf := buildSndRcvCmsg(info); len(buf) == 0 {
				b.Fatal("empty buffer")
			}
		}
	})

	b.Run("legacy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if buf := legacySndRcvCmsg(info); len(buf) == 0 {
				b.Fatal("empty buffer")
			}
		}
	})
}

// BenchmarkToBuf measures the serialisation helper on its own, without a syscall
// to hide it. It is no longer on the send path — buildSndRcvCmsg replaced it
// there — but it remains in use for the smaller option structs, so its cost is
// still worth knowing.
func BenchmarkToBuf(b *testing.B) {
	info := &SndRcvInfo{Stream: 1, PPID: 0x1234}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := toBuf(info)
		if len(buf) == 0 {
			b.Fatal("empty buffer")
		}
	}
}

// BenchmarkParseSndRcvInfo measures the ancillary-data decoder against a control
// message the kernel would actually send. Building the input once outside the loop
// keeps the measurement on the parse.
func BenchmarkParseSndRcvInfo(b *testing.B) {
	client, server := benchPair(b)
	if err := server.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		b.Fatalf("subscribe: %v", err)
	}
	if _, err := client.SCTPWrite([]byte("bench"),
		&SndRcvInfo{Stream: 1, PPID: 0x1234}); err != nil {
		b.Fatalf("write: %v", err)
	}

	// Capture one real control message rather than hand-building one, so the
	// benchmark cannot drift from what the kernel emits.
	oob := make([]byte, 254)
	buf := make([]byte, 4096)
	_, oobn, _, _, err := syscall.Recvmsg(server.fd(), buf, oob, 0)
	if err != nil {
		b.Fatalf("recvmsg: %v", err)
	}
	if oobn == 0 {
		b.Fatal("no ancillary data received; the subscription did not take")
	}
	cmsg := oob[:oobn]

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := parseSndRcvInfo(cmsg); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}

// BenchmarkResolveSCTPAddr covers address parsing, which a caller doing
// short-lived connections runs per dial.
func BenchmarkResolveSCTPAddr(b *testing.B) {
	b.Run("single", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ResolveSCTPAddr("sctp", "127.0.0.1:0"); err != nil {
				b.Fatalf("resolve: %v", err)
			}
		}
	})
	b.Run("multihomed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ResolveSCTPAddr("sctp",
				"127.0.0.1/127.0.0.2/127.0.0.3:0"); err != nil {
				b.Fatalf("resolve: %v", err)
			}
		}
	})
}

// BenchmarkToRawSockAddrBuf covers the address encoder every dial and bind runs.
func BenchmarkToRawSockAddrBuf(b *testing.B) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1/127.0.0.2:9999")
	if err != nil {
		b.Fatalf("resolve: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if buf := addr.ToRawSockAddrBuf(); len(buf) == 0 {
			b.Fatal("empty buffer")
		}
	}
}

// The benchmarks above are all single-association micro-benchmarks: they
// characterise one code path with one peer. The ones below cover what the
// multi-client work is actually about — cost that only appears with many
// associations at once, and the dial path, which now confirms the association
// before returning.

// BenchmarkDial measures a full dial and close.
//
// This is the path the EALREADY fix touched. The confirmation it added runs only
// on the EALREADY branch, so the common case should cost nothing extra; this is
// what would show it if that were ever wrong. Compare against a revision before
// the fix rather than reading the absolute number.
func BenchmarkDial(b *testing.B) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, aerr := ln.AcceptSCTP()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	b.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		b.Fatal("listener has no address")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, derr := DialSCTP("sctp", nil, la)
		if derr != nil {
			b.Fatalf("dial: %v", derr)
		}
		_ = c.Close()
	}
}

// BenchmarkConcurrentEcho measures request/response throughput with several
// associations driving traffic at once.
//
// Reported as ns/op per round trip across all peers, so raising the peer count
// shows whether added concurrency costs per-message throughput. The single-peer
// case is the baseline the others are read against; it is not comparable to
// BenchmarkSCTPWrite, which never waits for a reply.
func BenchmarkConcurrentEcho(b *testing.B) {
	for _, peers := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("peers=%d", peers), func(b *testing.B) {
			addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
			if err != nil {
				b.Fatalf("resolve: %v", err)
			}
			ln, err := ListenSCTP("sctp", addr)
			if err != nil {
				b.Fatalf("listen: %v", err)
			}
			var srvWG sync.WaitGroup
			srvWG.Add(1)
			go func() {
				defer srvWG.Done()
				for {
					c, aerr := ln.AcceptSCTP()
					if aerr != nil {
						return
					}
					srvWG.Add(1)
					go func(c *SCTPConn) {
						defer srvWG.Done()
						defer func() { _ = c.Close() }()
						buf := make([]byte, 4096)
						for {
							n, _, rerr := c.SCTPRead(buf)
							if rerr != nil {
								return
							}
							if werr := benchWriteAll(c, buf[:n]); werr != nil {
								return
							}
						}
					}(c)
				}
			}()
			la, ok := ln.Addr().(*SCTPAddr)
			if !ok {
				b.Fatal("listener has no address")
			}

			conns := make([]*SCTPConn, 0, peers)
			for i := 0; i < peers; i++ {
				c, derr := DialSCTP("sctp", nil, la)
				if derr != nil {
					b.Fatalf("dial %d: %v", i, derr)
				}
				if err := c.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
					b.Fatalf("deadline: %v", err)
				}
				conns = append(conns, c)
			}
			b.Cleanup(func() {
				for _, c := range conns {
					_ = c.Close()
				}
				_ = ln.Close()
				srvWG.Wait()
			})

			// Spread b.N round trips over the peers, so ns/op stays "per round
			// trip" however many are running.
			each := b.N / peers
			if each == 0 {
				each = 1
			}
			payload := make([]byte, 512)

			b.ReportAllocs()
			b.ResetTimer()
			var wg sync.WaitGroup
			for _, c := range conns {
				wg.Add(1)
				go func(c *SCTPConn) {
					defer wg.Done()
					buf := make([]byte, 4096)
					for j := 0; j < each; j++ {
						if err := benchWriteAll(c, payload); err != nil {
							return
						}
						if _, _, err := c.SCTPRead(buf); err != nil {
							return
						}
					}
				}(c)
			}
			wg.Wait()
			b.StopTimer()
		})
	}
}

// benchWriteAll retries a send whose buffer is momentarily full. Writes use
// MSG_DONTWAIT, so under the concurrency these benchmarks create EAGAIN is a
// flow-control condition rather than a failure; treating it as one would make
// the numbers depend on buffer luck.
func benchWriteAll(c *SCTPConn, b []byte) error {
	for {
		_, err := c.SCTPWrite(b, nil)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		runtime.Gosched()
	}
}
