//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// Covers the EALREADY handling in SCTPConnect.
//
// This was the one residual failure in the suite that resisted measurement for a
// long time: roughly two occurrences in ninety-five suite runs, unreproducible by
// 1024 concurrent dials, by a C sctp_connectx loop, or by forty instrumented
// runs. The errno appears nowhere in RFC 9260 or RFC 6458, so the specification
// could not settle it either.
//
// net/sctp/socket.c did. __sctp_connect and sctp_connect_add_peer both have:
//
//	asoc = sctp_endpoint_lookup_assoc(ep, daddr, &transport);
//	if (asoc)
//	        return asoc->state >= SCTP_STATE_ESTABLISHED ? -EISCONN
//	                                                     : -EALREADY;
//
// EISCONN and EALREADY are one branch at two association states, so both mean the
// endpoint already has the association the caller asked for. That is what makes
// EALREADY safe to treat as success on a blocking socket — and unsafe on a
// non-blocking one, where the kernel has not waited for the handshake.
//
// unreachableAddr is TEST-NET-1 from RFC 5737, reserved for documentation and
// guaranteed not to answer. An unanswered INIT is what holds the association in
// COOKIE_WAIT long enough for a second connect to find it.
func unreachableAddr() *SCTPAddr {
	return &SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}},
		Port:    9999,
	}
}

// newRawSCTPSocket returns a bare SCTP socket, blocking or not, for driving
// SCTPConnect directly.
func newRawSCTPSocket(t *testing.T, nonblocking bool) int {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM,
		syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.SetNonblock(fd, nonblocking); err != nil {
		t.Fatalf("SetNonblock(%v): %v", nonblocking, err)
	}
	return fd
}

// TestSCTPConnectEALREADYOnNonblockingSocket pins that a non-blocking caller
// still sees EALREADY.
//
// This is the half that stops the fix from being a blanket "treat EALREADY as
// success". On a non-blocking socket the kernel returns before the handshake, so
// an association in COOKIE_WAIT is genuinely not connected and reporting success
// would hand the caller a socket that cannot yet carry data.
//
// It doubles as the reproduction: the first connect gives EINPROGRESS, and a
// second one on the same socket finds the in-flight association. That sequence is
// deterministic, unlike the suite failure it explains.
func TestSCTPConnectEALREADYOnNonblockingSocket(t *testing.T) {
	fd := newRawSCTPSocket(t, true)
	raddr := unreachableAddr()

	// The first attempt starts the handshake and returns immediately.
	if _, err := SCTPConnect(fd, raddr); !errors.Is(err, syscall.EINPROGRESS) {
		t.Fatalf("first SCTPConnect gave %v, want EINPROGRESS on a "+
			"non-blocking socket against an unreachable peer", err)
	}

	// A second attempt finds the association the first one created. The kernel
	// alternates EALREADY and EINPROGRESS across retries, so accept either as
	// evidence the handshake is still in flight — but EALREADY must not have
	// been converted to success.
	var sawAlready bool
	for i := 0; i < 4; i++ {
		_, err := SCTPConnect(fd, raddr)
		if err == nil {
			t.Fatalf("attempt %d reported success while the association was "+
				"still handshaking; a non-blocking caller must keep EALREADY "+
				"so it knows the socket is not yet usable", i+1)
		}
		if errors.Is(err, syscall.EALREADY) {
			sawAlready = true
		} else if !errors.Is(err, syscall.EINPROGRESS) {
			t.Fatalf("attempt %d gave %v, want EALREADY or EINPROGRESS",
				i+1, err)
		}
	}
	if !sawAlready {
		t.Skip("the kernel answered every retry with EINPROGRESS rather than " +
			"EALREADY; the branch under test was not reached")
	}
}

// TestSCTPConnectEALREADYOnBlockingSocket is the other half: on a blocking socket
// an existing association means a connected socket, so EALREADY must not surface.
//
// Reaching the branch needs a real association, which loopback provides — and on
// loopback the handshake completes inside the call, so the second connect finds an
// ESTABLISHED association and the kernel says EISCONN rather than EALREADY. Both
// errnos take the same path in SCTPConnect, so this covers the blocking
// conversion; the state that distinguishes them is the kernel's, not this
// package's.
func TestSCTPConnectEALREADYOnBlockingSocket(t *testing.T) {
	ln, err := ListenSCTP("sctp", loopbackAddr())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	fd := newRawSCTPSocket(t, false)
	raddr := listenerAddr(t, ln)

	if _, err := SCTPConnect(fd, raddr); err != nil {
		t.Fatalf("first SCTPConnect: %v", err)
	}
	// The association now exists, so the kernel takes the lookup_assoc branch.
	// A blocking caller must see success: the socket is connected, and returning
	// an error here would discard a working association.
	if _, err := SCTPConnect(fd, raddr); err != nil {
		t.Fatalf("second SCTPConnect on a blocking socket gave %v, want "+
			"success — the association the caller asked for already exists "+
			"and the kernel has waited for its handshake", err)
	}

	// And it really is usable, which is the claim the conversion rests on.
	if _, err := syscall.Write(fd, []byte("established")); err != nil {
		t.Errorf("write after the second SCTPConnect reported success: %v — "+
			"the conversion is only sound if the socket is genuinely "+
			"connected", err)
	}
}

// blackholeAvailable reports whether an INIT to unreachableAddr is dropped rather
// than refused.
//
// This distinction is what makes the blocking EALREADY branch reachable at all.
// With a route to the address the gateway answers with an ICMP unreachable, SCTP
// maps that to ECONNREFUSED, and the connect returns immediately — no association
// is left mid-handshake. Only a dropped packet holds one in COOKIE_WAIT.
//
// Set the drop up with, inside the test container:
//
//	iptables -A OUTPUT -d 192.0.2.1 -j DROP
//
// Detection is by measurement rather than by inspecting firewall rules: a single
// non-blocking connect either reports EINPROGRESS, meaning the INIT went
// unanswered, or ECONNREFUSED, meaning something replied.
//
// The immediate return is not enough on its own. A gateway that answers with an
// ICMP unreachable a few milliseconds later still lets the connect report
// EINPROGRESS first, so checking only that says "blackholed" for a peer that is
// about to refuse — and the tests this guards then fail on a surprising errno
// instead of skipping. Measured in Docker, where the gateway sends ICMP protocol
// unreachable and the socket ends up with ENOPROTOOPT in SO_ERROR. So the reply
// is given a moment to arrive and SO_ERROR is consulted before answering.
func blackholeAvailable(t *testing.T) bool {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM,
		syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatalf("SetNonblock: %v", err)
	}
	if _, err = SCTPConnect(fd, unreachableAddr()); !errors.Is(err, syscall.EINPROGRESS) {
		return false
	}

	// Poll SO_ERROR briefly. A blackholed address leaves it at zero for the
	// whole retransmission window; a refusal lands within a few milliseconds.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		soerr, gerr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if gerr != nil {
			return false
		}
		if soerr != 0 {
			t.Logf("192.0.2.1 answered with errno %d (%v) rather than dropping "+
				"the INIT", soerr, syscall.Errno(soerr))
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return true
}

// TestSCTPConnectEALREADYOnBlockingSocketMidHandshake is the test that gives the
// fix its meaning.
//
// TestSCTPConnectEALREADYOnBlockingSocket above only ever reaches EISCONN, because
// on loopback the handshake finishes inside the first call. Reverting the EALREADY
// handling entirely still passed it — measured, not assumed — so it does not
// demonstrate the fix does anything.
//
// The branch needs a blocking socket whose association is stuck mid-handshake,
// which takes two goroutines and a blackholed peer: one blocks in SCTPConnect
// holding the association in COOKIE_WAIT while the other issues a second connect
// and finds it. That is the situation the suite hit roughly twice in ninety-five
// runs, and it reproduces on demand here.
func TestSCTPConnectEALREADYOnBlockingSocketMidHandshake(t *testing.T) {
	if !blackholeAvailable(t) {
		t.Skip("SCTP to 192.0.2.1 is refused rather than dropped, so no " +
			"association stays in COOKIE_WAIT; add an iptables DROP rule for " +
			"it to run this")
	}

	fd := newRawSCTPSocket(t, false)
	raddr := unreachableAddr()

	// One goroutine blocks in SCTPConnect for the length of the INIT
	// retransmissions. It is deliberately not waited on: the retransmit schedule
	// runs for minutes, and closing the socket is what releases it. The test
	// cleanup registered by newRawSCTPSocket does that.
	started := make(chan struct{})
	go func() {
		close(started)
		_, _ = SCTPConnect(fd, raddr)
	}()
	<-started

	// Give the blocking call time to create the association and enter
	// COOKIE_WAIT. Without an observable state to poll — SCTP_STATUS reports
	// EINVAL mid-handshake — this waits for the condition by retrying below
	// rather than by sleeping once and hoping.
	var reachedBranch bool
	for i := 0; i < 50; i++ {
		if _, err := SCTPConnect(fd, raddr); err == nil {
			// Success is the fixed behaviour: the association the caller asked
			// for exists on this endpoint and the kernel waits for it.
			reachedBranch = true
			break
		} else if !errors.Is(err, syscall.EINPROGRESS) &&
			!errors.Is(err, syscall.EALREADY) {
			t.Fatalf("second SCTPConnect gave %v, want success once the "+
				"association exists", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reachedBranch {
		t.Fatal("a second SCTPConnect against a blocking socket with an " +
			"in-flight association never reported success; EALREADY is " +
			"reaching the caller, which is the defect this covers")
	}
}

// TestIsNonblockingDetectsBothStates covers the helper the distinction rests on.
//
// If this misreported the flag, the EALREADY conversion would apply to the wrong
// sockets, which no other test here would notice: each of the two tests above
// only exercises one branch.
func TestIsNonblockingDetectsBothStates(t *testing.T) {
	blocking := newRawSCTPSocket(t, false)
	if isNonblocking(blocking) {
		t.Error("isNonblocking = true for a blocking socket")
	}

	nonblocking := newRawSCTPSocket(t, true)
	if !isNonblocking(nonblocking) {
		t.Error("isNonblocking = false for a non-blocking socket")
	}

	// Toggling has to be observed, not just the initial state — a helper that
	// returned a constant would pass the two checks above if they happened to
	// use different descriptors.
	if err := syscall.SetNonblock(blocking, true); err != nil {
		t.Fatalf("SetNonblock: %v", err)
	}
	if !isNonblocking(blocking) {
		t.Error("isNonblocking = false after setting O_NONBLOCK on a socket " +
			"that previously read as blocking")
	}

	// A descriptor that cannot be queried must fail safe: the conservative
	// answer is non-blocking, which keeps EALREADY an error rather than
	// reporting a possibly unconnected socket as ready. -1 is used rather than a
	// closed socket so this does not depend on close ordering against the
	// cleanup registered by newRawSCTPSocket.
	if !isNonblocking(-1) {
		t.Error("isNonblocking = false for an invalid descriptor; an " +
			"unqueryable fd must fail safe")
	}
}
