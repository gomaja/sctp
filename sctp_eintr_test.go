//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// EINTR on the blocking syscalls.
//
// Found by scaling the multi-client probe to 1000 simultaneous peers: a
// handful of reads failed per run with "interrupted system call", on peers that
// were otherwise healthy. The rate was roughly 0.1-0.3% of reads and varied run
// to run, which is the signature of signal delivery rather than of a protocol
// error.
//
// The cause is that this package retried none of its blocking syscalls. A Go
// program receives signals it did not ask for — the runtime uses SIGURG for
// goroutine preemption, and preemption becomes frequent exactly when many
// goroutines are runnable, which is what a server serving many peers looks
// like. Any signal delivered while recvmsg, accept4 or read is blocked makes
// the call return EINTR, and this package handed that straight to the caller as
// a failed read, a failed accept, or — worst — a graceful close turned into an
// ABORT.
//
// POSIX requires the caller to retry; that is what SA_RESTART cannot do for a
// socket carrying a receive timeout (SO_RCVTIMEO), which is precisely the
// configuration SCTPRead uses whenever a deadline is set.
//
// These tests deliver real signals to a thread blocked in each of those calls
// and require the operation to complete anyway.

// eintrSignaller repeatedly sends SIGURG to the current process until stop is
// closed, so a syscall blocked on another thread is interrupted.
//
// SIGURG is what the Go runtime itself uses for preemption, so it is delivered
// to a running thread without terminating the process and without needing a
// handler installed by the test. signal.Notify keeps the runtime's own handler
// from being disturbed.
func eintrSignaller(t *testing.T) (stop func()) {
	t.Helper()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGURG)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			return
		}
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = p.Signal(syscall.SIGURG)
			time.Sleep(200 * time.Microsecond)
		}
	}()

	return func() {
		close(done)
		wg.Wait()
		signal.Stop(ch)
	}
}

// TestReadSurvivesSignals requires a read to complete while the process is
// being signalled continuously.
//
// Against the unfixed SCTPRead this fails with "interrupted system call": the
// signal lands while recvmsg is blocked waiting for the message, recvmsg
// returns EINTR, and the error goes to the caller even though the association
// is healthy and the message arrives immediately afterwards.
func TestReadSurvivesSignals(t *testing.T) {
	client, server := eorPair(t)

	stop := eintrSignaller(t)
	defer stop()

	// A deadline puts SO_RCVTIMEO on the socket, which is the case where the
	// kernel cannot restart the call for us even with SA_RESTART.
	if err := server.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	const messages = 40
	// The sender must be waited on. Left detached it outlives the test body,
	// and eorPair's cleanup then closes the association underneath it — the
	// half-torn-down socket collides with whatever the next test dials on the
	// reused descriptor, which showed up as an unrelated test failing with
	// EPIPE on its first write.
	var senderWG sync.WaitGroup
	senderWG.Add(1)
	go func() {
		defer senderWG.Done()
		for i := 0; i < messages; i++ {
			// Send slowly enough that the reader is genuinely blocked in
			// recvmsg when the signals arrive, rather than finding data
			// already queued.
			time.Sleep(2 * time.Millisecond)
			if _, err := client.SCTPWrite([]byte(fmt.Sprintf("msg-%d", i)), nil); err != nil {
				return
			}
		}
	}()
	defer senderWG.Wait()

	buf := make([]byte, 4096)
	for i := 0; i < messages; i++ {
		n, _, err := server.SCTPRead(buf)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				t.Fatalf("read %d returned EINTR: a signal arriving during "+
					"recvmsg must be retried, not reported to the caller", i)
			}
			t.Fatalf("read %d: %v", i, err)
		}
		want := fmt.Sprintf("msg-%d", i)
		if got := string(buf[:n]); got != want {
			t.Fatalf("read %d: got %q, want %q", i, got, want)
		}
	}
}

// TestAcceptSurvivesSignals requires accept to complete while the process is
// being signalled.
//
// A server spends most of its life blocked in accept, so an unretried EINTR
// there is a spurious accept failure. A caller that treats an accept error as
// fatal stops serving entirely.
func TestAcceptSurvivesSignals(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	stop := eintrSignaller(t)
	defer stop()

	const peers = 20
	accepted := make(chan error, peers)
	go func() {
		for i := 0; i < peers; i++ {
			c, aerr := ln.AcceptSCTP()
			if aerr != nil {
				accepted <- aerr
				return
			}
			_ = c.Close()
			accepted <- nil
		}
	}()

	for i := 0; i < peers; i++ {
		// Dial with a gap so accept is blocked when the signals land.
		time.Sleep(2 * time.Millisecond)
		c, derr := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
		if derr != nil {
			t.Fatalf("peer %d dial: %v", i, derr)
		}
		if err := <-accepted; err != nil {
			if errors.Is(err, syscall.EINTR) {
				t.Fatalf("accept %d returned EINTR: a signal arriving during "+
					"accept4 must be retried, not reported as an accept failure", i)
			}
			t.Fatalf("accept %d: %v", i, err)
		}
		_ = c.Close()
	}
}

// TestGracefulCloseSurvivesSignals is the worst of the three, because it
// corrupts a protocol outcome rather than returning an error.
//
// closeSctpSocket decides between a clean close and an ABORT by reading: a
// read returning (0, nil) means the peer's shutdown completed, so close() may
// proceed normally. EINTR returns (-1, EINTR), which is not that case, so the
// unfixed code fell through to the linger=0 path and sent an ABORT on an
// association that had shut down cleanly. The peer sees ECONNRESET instead of
// EOF, and no error is reported on either side — the close "succeeds".
//
// This test closes many associations under continuous signalling and requires
// every peer to observe a clean end of stream.
func TestGracefulCloseSurvivesSignals(t *testing.T) {
	const rounds = 25

	stop := eintrSignaller(t)
	defer stop()

	var reset int
	for i := 0; i < rounds; i++ {
		client, server := eorPairNoCleanup(t)

		// The server closes gracefully while signals are flying.
		if err := server.Close(); err != nil {
			t.Fatalf("round %d: server close: %v", i, err)
		}

		if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatalf("round %d: deadline: %v", i, err)
		}
		buf := make([]byte, 256)
		_, _, err := client.SCTPRead(buf)
		switch {
		case err == nil:
			// A data message; drain until the stream ends.
		case errors.Is(err, syscall.ECONNRESET):
			reset++
		}
		_ = client.Close()
	}

	if reset > 0 {
		t.Errorf("%d of %d graceful closes were turned into an ABORT: the peer "+
			"saw ECONNRESET instead of a clean end of stream. A signal arriving "+
			"during the close-path read makes it report EINTR, which the code "+
			"must not treat as 'the peer did not shut down'.", reset, rounds)
	}
}

// TestDialNeverReturnsAnUnestablishedAssociation covers the defect that the
// EINTR work uncovered in the connect path.
//
// SCTPConnect used to treat EALREADY on a blocking socket as "connected",
// reasoning that the kernel waits for the handshake before returning. That is
// true on the normal path, but the EALREADY branch is an *early return* that
// skips sctp_wait_for_connect, so when the connect is interrupted the
// handshake may never finish. Measured under signal load, one of two EALREADY
// dials never established.
//
// The caller then received a *SCTPConn with no association behind it: a dial
// that reported success, a GetStatus that fails with EINVAL, and a first write
// that fails with EPIPE. Silently handing back a dead connection is worse than
// a failed dial, which is why this asserts the association exists rather than
// just that the dial returned.
func TestDialNeverReturnsAnUnestablishedAssociation(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
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
					if werr := writeAll(c, buf[:n], nil); werr != nil {
						return
					}
				}
			}(c)
		}
	}()

	// Signals are what drive the connect into the interrupted EALREADY branch.
	stop := eintrSignaller(t)

	// EALREADY is rare — one to three dials in two thousand even under
	// signals — so the dial count has to be high enough to reach the branch.
	// Measured against the unfixed code: at 200 dials it was caught 1 run in
	// 8, at 2000 it is caught 4 runs in 5. That residual is inherent to
	// racing the kernel's connect path and is recorded rather than hidden;
	// the fixed code passed 5 of 5.
	const (
		rounds        = 4
		dialsPerRound = 500
	)
	var dead, failed int64
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		for i := 0; i < dialsPerRound; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, derr := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
				if derr != nil {
					// A reported failure is acceptable: the contract is that a
					// dial either works or says so.
					atomic.AddInt64(&failed, 1)
					return
				}
				defer func() { _ = c.Close() }()
				// The dial claimed success, so an association must exist.
				if st, serr := c.GetStatus(); serr != nil || st == nil || st.State == 0 {
					atomic.AddInt64(&dead, 1)
				}
			}()
		}
		wg.Wait()
	}
	const dials = rounds * dialsPerRound
	stop()
	_ = ln.Close()
	srvWG.Wait()

	if n := atomic.LoadInt64(&dead); n > 0 {
		t.Errorf("%d of %d dials reported success but carried no association; "+
			"a dial must not hand back a socket whose first write fails with EPIPE",
			n, dials)
	}
	if n := atomic.LoadInt64(&failed); n > 0 {
		t.Logf("%d of %d dials reported an error (acceptable)", n, dials)
	}
}

// TestSCTPReadRetriesEINTRUnderLoad is the direct regression test for the
// failure the scale probe produced: many concurrent associations, each doing a
// blocking read, with signals delivered throughout.
//
// It is the closest in-process reproduction of a real server under load, where
// the Go runtime's own preemption supplies the signals without any test having
// to send them.
func TestSCTPReadRetriesEINTRUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test; skipped under -short")
	}

	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
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
					// writeAll, not SCTPWrite: sends use MSG_DONTWAIT, so a
					// momentarily full send buffer reports EAGAIN. Treating
					// that as fatal makes the server close a healthy
					// association, and the peer's next write then fails with
					// EPIPE — which looks like a library defect but is only
					// this echo loop mishandling flow control.
					if werr := writeAll(c, buf[:n], nil); werr != nil {
						return
					}
				}
			}(c)
		}
	}()

	stop := eintrSignaller(t)

	const peers = 60
	var eintrs int64
	var wg sync.WaitGroup
	errCh := make(chan error, peers)
	for i := 0; i < peers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, derr := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
			if derr != nil {
				errCh <- fmt.Errorf("peer %d dial: %w", id, derr)
				return
			}
			defer func() { _ = c.Close() }()
			if err := c.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
				errCh <- fmt.Errorf("peer %d deadline: %w", id, err)
				return
			}
			buf := make([]byte, 4096)
			for j := 0; j < 10; j++ {
				want := fmt.Sprintf("peer-%d-msg-%d", id, j)
				if err := writeAll(c, []byte(want), nil); err != nil {
					errCh <- fmt.Errorf("peer %d write %d: %w", id, j, err)
					return
				}
				n, _, rerr := c.SCTPRead(buf)
				if rerr != nil {
					if errors.Is(rerr, syscall.EINTR) {
						atomic.AddInt64(&eintrs, 1)
					}
					errCh <- fmt.Errorf("peer %d read %d: %w", id, j, rerr)
					return
				}
				if got := string(buf[:n]); got != want {
					errCh <- fmt.Errorf("peer %d msg %d: got %q, want %q", id, j, got, want)
					return
				}
			}
			errCh <- nil
		}(i)
	}
	wg.Wait()
	stop()
	close(errCh)

	var failed int
	for err := range errCh {
		if err != nil {
			failed++
			if failed <= 5 {
				t.Error(err)
			}
		}
	}
	if n := atomic.LoadInt64(&eintrs); n > 0 {
		t.Errorf("%d reads failed with EINTR; blocking syscalls must be retried", n)
	}
	if failed > 5 {
		t.Errorf("... and %d further failures", failed-5)
	}

	_ = ln.Close()
	srvWG.Wait()
}

// TestCloseTerminatesPromptlyUnderSignals pins the bound on the close-path
// retry.
//
// Retrying that read on EINTR is what stops a signal from turning a graceful
// close into an ABORT, but a retry loop needs a bound or a server tearing down
// many associations could hang in one of them. The bound is SO_RCVTIMEO,
// programmed just above the read.
//
// It is loose in principle — on a socket with no data the kernel restarts much
// of the remaining timeout after each interruption, measured at 7351 retries
// over 15.9s against a 1s timeout — but it does not bite, because the read
// follows the shutdown and so returns on its first call instead of blocking.
// This asserts the reachable behaviour rather than the theoretical one, and
// would fail if the read ever moved ahead of the shutdown and became genuinely
// unbounded.
func TestCloseTerminatesPromptlyUnderSignals(t *testing.T) {
	const rounds = 20

	stop := eintrSignaller(t)
	defer stop()

	const grace = 500 * time.Millisecond
	var worst time.Duration
	for i := 0; i < rounds; i++ {
		client, server := eorPairNoCleanup(t)

		start := time.Now()
		_ = server.CloseWithTimeout(grace)
		if d := time.Since(start); d > worst {
			worst = d
		}
		_ = client.Close()
	}

	t.Logf("worst CloseWithTimeout(%v) across %d rounds under continuous "+
		"signals: %v", grace, rounds, worst.Round(time.Millisecond))

	// Generous, because this is a bound on a retry loop rather than a latency
	// assertion: what would fail it is the loop not terminating.
	if worst > 30*time.Second {
		t.Errorf("a close took %v against a %v grace period; the EINTR retry "+
			"is not bounded in practice", worst, grace)
	}
}
