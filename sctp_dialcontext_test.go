//go:build linux && !386
// +build linux,!386

package sctp

import (
	"bufio"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// countAssocs reports how many SCTP associations the kernel currently holds.
//
// An abandoned dial that only stopped waiting still leaves one here, in
// COOKIE_WAIT, retransmitting its INIT — which is the thing the context-aware
// dial exists to prevent and the thing an in-process assertion cannot see.
func countAssocs(t *testing.T) int {
	t.Helper()
	f, err := os.Open("/proc/net/sctp/assocs")
	if err != nil {
		t.Skipf("cannot read /proc/net/sctp/assocs: %v", err)
	}
	defer func() { _ = f.Close() }()

	n := 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		// The first line is the column header, which starts with a name rather
		// than the association's socket pointer.
		if line == "" || strings.HasPrefix(line, "ASSOC") {
			continue
		}
		n++
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scanning assocs: %v", err)
	}
	return n
}

// TestDialContextAlreadyCancelledOpensNoSocket checks the cheapest case: a
// context that is done before the call must not reach the kernel at all.
//
// A descriptor count cannot show this on its own. Without the entry check the
// socket is opened and then released by the same call, so the count is back
// where it started by the time the test can look — the mutation that removes
// the check passes a count-only test. The Control hook is the witness: it runs
// between the socket being created and the connect, so if it ran at all, a
// socket was created for a context that was already done.
func TestDialContextAlreadyCancelledOpensNoSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	before := openFds(t)

	sawControl := false
	cfg := SocketConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			sawControl = true
			return nil
		},
	}
	_, err := cfg.DialContext(ctx, "sctp4", nil, unreachableAddr())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if sawControl {
		t.Error("a socket was created for an already-cancelled context; the " +
			"call must return before opening anything")
	}
	if after := openFds(t); after != before {
		t.Errorf("descriptor count went %d -> %d", before, after)
	}

	// The plain entry point must behave the same way.
	if _, err := DialSCTPContext(ctx, "sctp4", nil, unreachableAddr(), InitMsg{}); !errors.Is(err, context.Canceled) {
		t.Errorf("DialSCTPContext err = %v, want context.Canceled", err)
	}
}

// TestDialContextTimeoutAbandonsTheAttempt is the request itself.
//
// Against a peer that silently drops SCTP, a blocking dial returns when the
// kernel gives up rather than when the caller does, and the association stays
// in COOKIE_WAIT emitting INIT retransmissions from a socket the caller
// believes it has finished with. This must return at the caller's deadline with
// the association already gone.
func TestDialContextTimeoutAbandonsTheAttempt(t *testing.T) {
	if !blackholeAvailable(t) {
		t.Skip("SCTP to 192.0.2.1 is refused rather than dropped, so no " +
			"association stays in COOKIE_WAIT; add an iptables DROP rule for " +
			"it to run this")
	}

	baseline := countAssocs(t)
	fdsBefore := openFds(t)

	const budget = 1500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	start := time.Now()
	conn, err := DialSCTPContext(ctx, "sctp4", nil, unreachableAddr(), InitMsg{})
	elapsed := time.Since(start)

	if err == nil {
		_ = conn.CloseWithTimeout(200 * time.Millisecond)
		t.Fatal("dial to a blackholed peer succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed < budget/2 {
		t.Errorf("returned after %v, well before its %v budget", elapsed, budget)
	}
	if elapsed > budget*4 {
		t.Errorf("returned after %v, far past its %v budget; the attempt is "+
			"not being abandoned at the caller's deadline", elapsed, budget)
	}

	// The association must be gone by the time the call returns, not merely
	// unreferenced. This is what separates abandoning the attempt from giving
	// up on waiting for it.
	if got := countAssocs(t); got > baseline {
		t.Errorf("%d associations remain against a baseline of %d; the "+
			"abandoned attempt is still in the kernel retransmitting", got, baseline)
	}
	if after := openFds(t); after > fdsBefore {
		t.Errorf("descriptor count went %d -> %d; the socket was not released",
			fdsBefore, after)
	}
}

// TestDialContextCancelDuringDial is the case the report called the one that
// hurts: a generous budget cancelled early. It must return when cancelled, not
// when the budget would have expired.
func TestDialContextCancelDuringDial(t *testing.T) {
	if !blackholeAvailable(t) {
		t.Skip("needs a blackholed peer; see TestDialContextTimeoutAbandonsTheAttempt")
	}

	baseline := countAssocs(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	conn, err := DialSCTPContext(ctx, "sctp4", nil, unreachableAddr(), InitMsg{})
	elapsed := time.Since(start)

	if err == nil {
		_ = conn.CloseWithTimeout(200 * time.Millisecond)
		t.Fatal("dial to a blackholed peer succeeded")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("returned after %v; the cancellation was ignored and the call "+
			"ran on toward its 30s budget", elapsed)
	}
	if got := countAssocs(t); got > baseline {
		t.Errorf("%d associations remain against a baseline of %d", got, baseline)
	}
}

// TestDialContextAbandonedAttemptsLeakNothing runs the abandoned path enough
// times that a per-attempt leak would be unmistakable.
func TestDialContextAbandonedAttemptsLeakNothing(t *testing.T) {
	if !blackholeAvailable(t) {
		t.Skip("needs a blackholed peer; see TestDialContextTimeoutAbandonsTheAttempt")
	}

	attempts := 50
	if testing.Short() {
		attempts = 10
	}

	baseline := countAssocs(t)
	before := openFds(t)

	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := DialSCTPContext(ctx, "sctp4", nil, unreachableAddr(), InitMsg{})
		cancel()
		if err == nil {
			t.Fatalf("attempt %d: dial to a blackholed peer succeeded", i)
		}
	}

	if after := openFds(t); after > before+2 {
		t.Errorf("descriptor count went %d -> %d over %d abandoned attempts",
			before, after, attempts)
	}
	if got := countAssocs(t); got > baseline {
		t.Errorf("%d associations remain against a baseline of %d after %d "+
			"abandoned attempts", got, baseline, attempts)
	}
}

// TestDialContextSucceeds is the happy path: the context variant must be a
// working dial, not merely a cancellable one.
func TestDialContextSucceeds(t *testing.T) {
	ln := listenForDialContext(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := DialSCTPContext(ctx, "sctp", nil, ln.Addr().(*SCTPAddr), InitMsg{})
	if err != nil {
		t.Fatalf("DialSCTPContext: %v", err)
	}
	defer func() { _ = conn.CloseWithTimeout(200 * time.Millisecond) }()

	srv, err := ln.AcceptSCTP()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = srv.CloseWithTimeout(200 * time.Millisecond) }()

	want := []byte("over a context dial")
	if _, err := conn.SCTPWrite(want, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := srv.SCTPRead(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != string(want) {
		t.Errorf("read %q, want %q", got, want)
	}
}

// TestDialContextReturnsBlockingDescriptor is the mistake the report says they
// made first.
//
// The socket is created non-blocking so the connect can be abandoned, and it
// has to be put back before the caller sees it. Left non-blocking, an idle read
// returns EAGAIN at once — which this package maps onto os.ErrDeadlineExceeded,
// so the caller sees a deadline expire that had not.
func TestDialContextReturnsBlockingDescriptor(t *testing.T) {
	ln := listenForDialContext(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := DialSCTPContext(ctx, "sctp", nil, ln.Addr().(*SCTPAddr), InitMsg{})
	if err != nil {
		t.Fatalf("DialSCTPContext: %v", err)
	}
	defer func() { _ = conn.CloseWithTimeout(200 * time.Millisecond) }()

	srv, err := ln.AcceptSCTP()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = srv.CloseWithTimeout(200 * time.Millisecond) }()

	// Nothing is sent, so this read can only end at its deadline. On a
	// non-blocking descriptor it would return immediately instead.
	const budget = 400 * time.Millisecond
	if err := conn.SetReadDeadline(time.Now().Add(budget)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	start := time.Now()
	_, _, err = conn.SCTPRead(buf)
	elapsed := time.Since(start)

	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed < budget/2 {
		t.Errorf("an idle read returned after %v against a %v deadline; the "+
			"descriptor was handed back still non-blocking, so EAGAIN is being "+
			"reported as a deadline that never expired", elapsed, budget)
	}

	// Confirm directly as well, so the timing above cannot be the only witness.
	if isNonblocking(conn.fd()) {
		t.Error("the returned descriptor still has O_NONBLOCK set")
	}
}

// TestDialContextRefusedPeerReportsTheError covers the SO_ERROR branch.
//
// On a non-blocking socket the connect returns before the peer has answered, so
// a refusal — the ABORT that comes back from a port nobody is listening on —
// cannot surface through it. It arrives via SO_ERROR instead, and without that
// check the dial would sit out its whole context and report a deadline instead
// of the refusal.
func TestDialContextRefusedPeerReportsTheError(t *testing.T) {
	// Bind and immediately release a port, so nothing is listening on it.
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().(*SCTPAddr)
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	const budget = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	start := time.Now()
	conn, err := DialSCTPContext(ctx, "sctp", nil, dead, InitMsg{})
	elapsed := time.Since(start)

	if err == nil {
		_ = conn.CloseWithTimeout(200 * time.Millisecond)
		t.Skip("the port was reused before the dial; nothing to check")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial to a refused port ran out its whole %v context instead "+
			"of reporting the refusal", budget)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Logf("refusal reported as %v", err)
	}
	if elapsed > budget/2 {
		t.Errorf("took %v to report a refusal", elapsed)
	}
}

// TestSocketConfigDialContext covers the SocketConfig entry point, including
// that its Control hook still runs.
func TestSocketConfigDialContext(t *testing.T) {
	ln := listenForDialContext(t)

	sawControl := false
	cfg := SocketConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(uintptr) { sawControl = true })
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := cfg.DialContext(ctx, "sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.CloseWithTimeout(200 * time.Millisecond) }()

	if !sawControl {
		t.Error("the Control hook never ran")
	}
	srv, err := ln.AcceptSCTP()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = srv.CloseWithTimeout(200 * time.Millisecond)
}

// listenForDialContext brings up a loopback listener for the dial tests.
func listenForDialContext(t *testing.T) *SCTPListener {
	t.Helper()
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}
