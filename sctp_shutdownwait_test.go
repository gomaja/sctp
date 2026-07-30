//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// stalledPair returns an association whose send queue is full because the peer
// is not reading, and the number of messages queued.
//
// A stalled association cannot complete a shutdown handshake: SHUTDOWN is only
// sent once the outstanding data is acknowledged, so the association sits in
// SHUTDOWN_PENDING for as long as the peer refuses to drain. That is the state
// closeSctpSocket's wait exists to detect, and the one it used to misread as a
// completed handshake.
func stalledPair(t *testing.T) (client, server *SCTPConn) {
	t.Helper()
	client, server = eorPairNoCleanup(t)
	fillSendBuffer(t, client, fill(512))
	return client, server
}

// TestAssocQueryAnswersForALiveAssociation pins the control reading
// closeSctpSocket takes before it shuts anything down.
//
// That reading exists so a getsockopt which does not work on some platform
// cannot be mistaken for "the association is gone" — both are EINVAL. The cost
// of it is that a broken query is no longer a test failure anywhere: Close falls
// back to its old behaviour and every close test stays green while the fix is
// silently inert.
//
// So the query is asserted directly. If this fails, the shutdown wait is not
// running at all and the timeout means nothing again, however green the rest of
// the close tests look.
func TestAssocQueryAnswersForALiveAssociation(t *testing.T) {
	client, _ := eorPair(t)

	if assocGone(client.fd()) {
		t.Fatal("assocGone reports an established association as gone; the " +
			"shutdown wait would fall back and Close would stop waiting for " +
			"the handshake, with no other test noticing")
	}
}

// TestCloseTimeoutBoundsTheShutdownWait is the regression test for a timeout
// that did nothing.
//
// closeSctpSocket used to decide whether the handshake had completed by reading
// from the socket. shutdown(SHUT_RDWR) sets RCV_SHUTDOWN first, and the SCTP
// receive path reports end of stream on that before it consults SO_RCVTIMEO, so
// the read returned (0, nil) immediately whatever the peer had done — and
// CloseWithTimeout(1ms) and CloseWithTimeout(1h) were the same call.
//
// Against a peer that cannot answer, Close must now spend its budget and then
// abort, rather than returning at once having concluded the peer answered.
func TestCloseTimeoutBoundsTheShutdownWait(t *testing.T) {
	client, server := stalledPair(t)
	t.Cleanup(func() { _ = server.CloseWithTimeout(200 * time.Millisecond) })

	const budget = 700 * time.Millisecond
	start := time.Now()
	if err := client.CloseWithTimeout(budget); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}
	elapsed := time.Since(start)

	if elapsed < budget/2 {
		t.Errorf("Close returned after %v against a peer that cannot answer; "+
			"the timeout of %v did not bound anything, which is the defect "+
			"this test exists for", elapsed, budget)
	}
	if elapsed > budget*4 {
		t.Errorf("Close took %v, far past its %v budget", elapsed, budget)
	}
}

// TestCloseWithRespondingPeerReturnsPromptly is the other side: the wait must
// not cost anything when the peer does answer.
//
// Without this, a wait that simply slept for its whole budget would satisfy the
// test above.
func TestCloseWithRespondingPeerReturnsPromptly(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	t.Cleanup(func() { _ = server.CloseWithTimeout(200 * time.Millisecond) })

	// Keep the peer reading so the handshake can complete.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := server.SCTPRead(buf); err != nil {
				return
			}
		}
	}()

	const budget = 5 * time.Second
	start := time.Now()
	if err := client.CloseWithTimeout(budget); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}
	elapsed := time.Since(start)

	// On loopback the association is freed within microseconds of the
	// shutdown; the bound here is loose so that a busy host cannot fail it.
	if elapsed > time.Second {
		t.Errorf("Close took %v against a peer that answered immediately; the "+
			"shutdown wait should end as soon as the association is freed, "+
			"not run to its budget", elapsed)
	}
}

// TestCloseReleasesPortAfterUnresponsivePeer checks the consequence that made
// the old behaviour worth fixing.
//
// Deciding "the handshake completed" for a peer that never answered meant
// skipping the ABORT, which left the association and its bound port in the
// kernel until the retransmissions gave up — up to 5 x RTO.max. Rebinding the
// address immediately afterwards is what proves the abort happened.
func TestCloseReleasesPortAfterUnresponsivePeer(t *testing.T) {
	client, server := stalledPair(t)
	t.Cleanup(func() { _ = server.CloseWithTimeout(200 * time.Millisecond) })

	local, err := sctpGetAddrs(client.fd(), 0, SCTP_GET_LOCAL_ADDRS)
	if err != nil {
		t.Fatalf("local addrs: %v", err)
	}

	if err := client.CloseWithTimeout(500 * time.Millisecond); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}

	ln, err := ListenSCTP("sctp", local)
	if err != nil {
		t.Fatalf("rebinding %v after closing on an unresponsive peer: %v; the "+
			"association was left in the kernel holding the address", local, err)
	}
	_ = ln.Close()
}

// TestListenerAcceptDeadline covers the deadline SCTPListener did not have.
//
// Accept could previously only be unblocked by closing the listener, which
// destroys it. sctp_accept takes its wait budget from SO_RCVTIMEO, so a
// deadline costs one setsockopt and leaves the listener usable afterwards.
func TestListenerAcceptDeadline(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if err := ln.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	start := time.Now()
	_, err = ln.AcceptSCTP()
	elapsed := time.Since(start)

	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("AcceptSCTP err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed < 250*time.Millisecond {
		t.Errorf("Accept gave up after %v, before its deadline", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Errorf("Accept returned after %v, far past its deadline", elapsed)
	}

	// The listener must still work afterwards — that is the whole point of
	// having a deadline rather than closing it.
	if err := ln.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing the deadline: %v", err)
	}
	accepted := make(chan error, 1)
	go func() {
		c, err := ln.AcceptSCTP()
		if c != nil {
			_ = c.CloseWithTimeout(200 * time.Millisecond)
		}
		accepted <- err
	}()
	conn, err := dialRetry(ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("dial after clearing the deadline: %v", err)
	}
	defer func() { _ = conn.CloseWithTimeout(200 * time.Millisecond) }()
	select {
	case err := <-accepted:
		if err != nil {
			t.Errorf("accept after clearing the deadline: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("the listener never accepted after its deadline was cleared")
	}
}

// TestListenerDeadlineInThePast checks the boundary, matching SCTPConn's
// treatment of a deadline that has already elapsed.
func TestListenerDeadlineInThePast(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if err := ln.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	start := time.Now()
	if _, err := ln.AcceptSCTP(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %v; an elapsed deadline must not wait", elapsed)
	}
}

// TestSendDoesNotRaiseSIGPIPE pins MSG_NOSIGNAL.
//
// A send on an association that is gone reports EPIPE and, without the flag,
// also raises SIGPIPE. Go's runtime ignores SIGPIPE for descriptors other than
// 1 and 2, so this was survivable — but a caller that had asked for the signal
// with signal.Notify saw one per refused send, and the retry loop in sendmsg
// makes refused sends more frequent than they were.
func TestSendDoesNotRaiseSIGPIPE(t *testing.T) {
	client, server := eorPairNoCleanup(t)

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGPIPE)
	defer signal.Stop(sig)

	if err := server.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}

	// Writing once is not enough. The first failed write reports ECONNRESET,
	// draining sk_err, and ECONNRESET does not raise SIGPIPE — only EPIPE does,
	// and that appears on the writes after it, once the association is simply
	// gone. A test that stopped at the first error would pass with or without
	// the flag, which is exactly what it did before this was corrected.
	var sawEPIPE bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !sawEPIPE {
		_, werr := client.SCTPWrite([]byte("after the abort"), nil)
		sawEPIPE = errors.Is(werr, syscall.EPIPE)
		if werr == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Keep going past the first EPIPE: one signal per refused send is the
	// behaviour being suppressed, so several sends make the check less
	// dependent on timing.
	for i := 0; i < 20; i++ {
		_, _ = client.SCTPWrite([]byte("after the abort"), nil)
	}
	_ = client.CloseWithTimeout(200 * time.Millisecond)

	if !sawEPIPE {
		t.Skip("the association never reported EPIPE, so SIGPIPE was never " +
			"reachable and this proves nothing")
	}

	select {
	case s := <-sig:
		t.Errorf("received %v; sends must pass MSG_NOSIGNAL so a failed write "+
			"reports EPIPE without raising a signal", s)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestRawWaitTerminatesOnAbortedAssociation covers the POLLERR path.
//
// POLLERR is level-triggered on sk_err and sendmsg does not consume it, so a
// wait that returned on POLLERR and let the caller retry could in principle
// loop with nothing changing. It does not: the state is transient, and the next
// send reports the real errno. Measured at one call to f before the wait
// returned ECONNRESET.
func TestRawWaitTerminatesOnAbortedAssociation(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	t.Cleanup(func() { _ = client.CloseWithTimeout(200 * time.Millisecond) })

	fillSendBuffer(t, client, fill(512))
	if err := server.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}

	rc, err := client.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	// No deadline: only the association failing can end this.
	calls := 0
	var sendErr error
	done := make(chan error, 1)
	go func() {
		done <- rc.Write(func(fd uintptr) bool {
			calls++
			_, sendErr = syscall.SendmsgN(int(fd), []byte("x"), nil, nil,
				syscall.MSG_DONTWAIT)
			return !errors.Is(sendErr, syscall.EAGAIN)
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("rc.Write: %v", err)
		}
		if sendErr == nil {
			t.Error("the send succeeded on an aborted association")
		}
		if errors.Is(sendErr, syscall.EAGAIN) {
			t.Error("the wait returned while the send still reported EAGAIN")
		}
		t.Logf("terminated after %d call(s) to f with %v", calls, sendErr)
	case <-time.After(10 * time.Second):
		t.Fatal("the wait never terminated on an aborted association; a " +
			"level-triggered POLLERR with no progress is a non-terminating loop")
	}
}
