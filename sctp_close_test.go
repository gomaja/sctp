//go:build linux && !386
// +build linux,!386

// Copyright 2019 Wataru Ishida. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sctp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fdIsOpen reports whether fd refers to an open descriptor in this process.
func fdIsOpen(fd int) bool {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL,
		uintptr(fd), uintptr(syscall.F_GETFD), 0)
	return errno == 0
}

// runChild re-executes the test binary for a single test with env set, so a
// test may disturb process-wide state (such as closing stdin) in isolation.
// It returns the child's combined output.
func runChild(exe, testName, env string) (string, error) {
	cmd := exec.Command(exe, "-test.run", "^"+testName+"$", "-test.v")
	cmd.Env = append(os.Environ(), env)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// eorPairNoCleanup is eorPair without the t.Cleanup close hooks, for tests
// that close the connections themselves and would otherwise trip a double
// close during cleanup.
func eorPairNoCleanup(t testingTB) (client, server *SCTPConn) {
	t.Helper()
	client, server, ok := eorPairMaybe(t)
	if !ok {
		// eorPairMaybe logs the dial or accept error before returning false,
		// so that appears immediately above this line.
		t.Fatalf("could not establish association")
	}
	return client, server
}

// eorPairMaybe is eorPairNoCleanup that reports failure instead of aborting
// the test, for callers that run many iterations and can tolerate the
// occasional dial failure under churn.
func eorPairMaybe(t testingTB) (client, server *SCTPConn, ok bool) {
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

	type accepted struct {
		conn *SCTPConn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.AcceptSCTP()
		ch <- accepted{c, err}
	}()

	client, err = dialRetry(ln.Addr().(*SCTPAddr))
	if err != nil {
		// Log rather than discard: callers that turn this into a failure
		// would otherwise report only that no association could be made,
		// leaving nothing to say why.
		t.Logf("eorPair: dial failed after retries: %v", err)
		return nil, nil, false
	}

	a := <-ch
	if a.err != nil {
		t.Logf("eorPair: accept failed: %v", a.err)
		_ = client.Close()
		return nil, nil, false
	}
	return client, a.conn, true
}

// TestDialUnderChurnReportsEISCONN documents a dial-side limitation found
// while fuzzing the close paths.
//
// Under rapid dial/teardown cycles, SCTPConnect can return EISCONN
// ("transport endpoint is already connected") on a freshly created socket.
// The socket is new, so the error reflects kernel association state that has
// not finished tearing down rather than anything the caller did. DialSCTP
// surfaces it unchanged, so callers doing rapid reconnects must retry.
//
// It was originally observed when accepted connections were left open, which
// suggests lingering peer-side associations are what provoke it; aborting
// each accepted connection promptly, as here, usually avoids it. The test
// therefore records what it observes rather than asserting a rate, so it
// documents the behaviour without becoming flaky either way.
//
// This is separate from the close path: connections being closed are released
// correctly, as TestCloseChurnUnderLoad shows.
func TestDialUnderChurnReportsEISCONN(t *testing.T) {
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Abort each accepted connection rather than letting them accumulate:
	// leaving hundreds of server-side associations open would make the
	// listener's own teardown dominate the test's runtime.
	go func() {
		for {
			c, err := ln.AcceptSCTP()
			if err != nil {
				return
			}
			_ = c.Abort()
		}
	}()

	const cycles = 300
	failures := map[string]int{}
	for i := 0; i < cycles; i++ {
		// Dial directly, not through dialRetry: observing the raw failure is
		// the point of this test.
		conn, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
		if err != nil {
			failures[err.Error()]++
			continue
		}
		if err := conn.Abort(); err != nil {
			t.Fatalf("abort %d: %v", i, err)
		}
	}

	if len(failures) == 0 {
		t.Logf("%d rapid dial cycles, no failures", cycles)
		return
	}
	for msg, n := range failures {
		t.Logf("%d/%d dials failed with %q", n, cycles, msg)
	}
}

// TestCloseReleasesFdZero covers a descriptor leak that only appears when a
// connection lands on fd 0.
//
// Close and Abort guarded the descriptor with "fd > 0". Zero is a perfectly
// valid descriptor, so a connection on fd 0 had its _fd swapped to -1 and was
// then never closed: the socket leaked and Close reported EBADF as though
// nothing had been open. Daemons that close stdin routinely hand out fd 0.
//
// The test runs in a subprocess because it must close stdin to force the
// allocation, which would otherwise disturb the rest of the suite.
func TestCloseReleasesFdZero(t *testing.T) {
	if os.Getenv("SCTP_FD_ZERO_CHILD") == "1" {
		fdZeroChild()
		return
	}

	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate test binary: %v", err)
	}
	out, err := runChild(exe, "TestCloseReleasesFdZero", "SCTP_FD_ZERO_CHILD=1")
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	t.Logf("child reported:\n%s", out)
}

// fdZeroChild closes stdin, opens an association that therefore lands on fd 0,
// and checks Close both reports success and actually releases the descriptor.
func fdZeroChild() {
	report := func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}

	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		report("FAIL resolve: %v", err)
		os.Exit(1)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		report("FAIL listen: %v", err)
		os.Exit(1)
	}
	go func() {
		for {
			c, err := ln.AcceptSCTP()
			if err != nil {
				return
			}
			_ = c
		}
	}()

	// Free fd 0 so the next socket lands there.
	if err := syscall.Close(0); err != nil {
		report("SKIP cannot close stdin: %v", err)
		os.Exit(0)
	}

	conn, err := dialRetry(ln.Addr().(*SCTPAddr))
	if err != nil {
		report("SKIP dial: %v", err)
		os.Exit(0)
	}
	fd := conn.fd()
	if fd != 0 {
		report("SKIP association landed on fd %d, not 0; nothing to prove", fd)
		os.Exit(0)
	}

	if err := conn.Close(); err != nil {
		report("FAIL Close on fd 0 returned %v, want nil", err)
		os.Exit(1)
	}
	if fdIsOpen(0) {
		report("FAIL fd 0 is still open after Close; the descriptor leaked")
		os.Exit(1)
	}
	report("ok: connection on fd 0 closed cleanly and the descriptor was released")
	os.Exit(0)
}

// TestAbortReleasesFdZero is the same guarantee for Abort.
func TestAbortReleasesFdZero(t *testing.T) {
	if os.Getenv("SCTP_FD_ZERO_ABORT_CHILD") == "1" {
		abortFdZeroChild()
		return
	}

	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate test binary: %v", err)
	}
	out, err := runChild(exe, "TestAbortReleasesFdZero", "SCTP_FD_ZERO_ABORT_CHILD=1")
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	t.Logf("child reported:\n%s", out)
}

func abortFdZeroChild() {
	report := func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}

	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		report("FAIL listen: %v", err)
		os.Exit(1)
	}
	go func() {
		for {
			c, err := ln.AcceptSCTP()
			if err != nil {
				return
			}
			_ = c
		}
	}()

	if err := syscall.Close(0); err != nil {
		report("SKIP cannot close stdin: %v", err)
		os.Exit(0)
	}
	conn, err := dialRetry(ln.Addr().(*SCTPAddr))
	if err != nil {
		report("SKIP dial: %v", err)
		os.Exit(0)
	}
	if fd := conn.fd(); fd != 0 {
		report("SKIP association landed on fd %d, not 0", fd)
		os.Exit(0)
	}
	// Identify the socket before releasing it. "Is fd 0 open afterwards" cannot
	// answer whether Abort released it: the accept loop above runs concurrently
	// and the kernel hands out the lowest free descriptor, so a socket created
	// in the instant after Abort takes fd 0 back and the fd reads as open
	// through no fault of Abort. That was measured — even a single-threaded C
	// program doing the same accept-then-abort sequence finds fd 0 occupied by a
	// different socket bound to a different port — and it is why this check asks
	// whether *this* association is gone rather than whether the number is free.
	before, nameErr := localPortOf(0)
	if nameErr != nil {
		report("SKIP cannot read the local port of fd 0: %v", nameErr)
		os.Exit(0)
	}

	if err := conn.Abort(); err != nil {
		report("FAIL Abort on fd 0 returned %v, want nil", err)
		os.Exit(1)
	}

	if !fdIsOpen(0) {
		// The descriptor was released and nothing has claimed it yet.
		report("ok: Abort on fd 0 released the descriptor")
		os.Exit(0)
	}
	// fd 0 is open. That is only a leak if it is still the same socket.
	after, err := localPortOf(0)
	if err != nil {
		// Open but not a socket, or not nameable: whatever holds fd 0 now, it is
		// not the association Abort was given.
		report("ok: fd 0 was reclaimed by a non-socket after Abort (%v)", err)
		os.Exit(0)
	}
	if after == before {
		report("FAIL fd 0 is still the aborted association (local port %d); "+
			"the descriptor leaked", before)
		os.Exit(1)
	}
	report("ok: Abort released fd 0; it was reclaimed by a different socket "+
		"(port %d, was %d)", after, before)
	os.Exit(0)
}

// localPortOf reports the port fd is bound to, and fails if fd is not a bound
// socket. It is what distinguishes "this association is still open" from "some
// other socket has taken this descriptor number".
func localPortOf(fd int) (int, error) {
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return 0, err
	}
	switch a := sa.(type) {
	case *syscall.SockaddrInet4:
		return a.Port, nil
	case *syscall.SockaddrInet6:
		return a.Port, nil
	default:
		return 0, fmt.Errorf("fd %d is a %T, not an IP socket", fd, sa)
	}
}

// TestCloseDoesNotLeakDescriptors is the general form: repeated dial/close
// cycles must not accumulate descriptors, whatever fd they land on.
func TestCloseDoesNotLeakDescriptors(t *testing.T) {
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			c, err := ln.AcceptSCTP()
			if err != nil {
				return
			}
			go func(c *SCTPConn) {
				buf := make([]byte, 256)
				for {
					if _, _, err := c.SCTPRead(buf); err != nil {
						// The client has already gone; abort rather than run
						// a graceful shutdown that has no peer to answer it
						// and would serialise the whole test.
						_ = c.Abort()
						return
					}
				}
			}(c)
		}
	}()

	before := countOpenFds(t)
	for i := 0; i < 50; i++ {
		conn, err := dialRetry(ln.Addr().(*SCTPAddr))
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
	}
	after := countOpenFds(t)

	// Allow a small margin for runtime-internal descriptors.
	if after > before+10 {
		t.Errorf("descriptor count grew from %d to %d over 50 dial/close cycles",
			before, after)
	}
	t.Logf("open descriptors before=%d after=%d", before, after)
}

func countOpenFds(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// TestCloseReleasesPortForRebind is the symptom the close rework exists to
// fix: after Close returns, the local address must be immediately reusable
// rather than yielding EADDRINUSE.
func TestCloseReleasesPortForRebind(t *testing.T) {
	// Bind a listener on a fixed port, close it, and rebind the same port.
	for attempt := 0; attempt < 5; attempt++ {
		addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		ln, err := ListenSCTP("sctp", addr)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		bound := ln.Addr().(*SCTPAddr)

		// Hold the accepted connection so it can be closed deterministically:
		// an association still open on the listener's address keeps that
		// address bound, independently of the listener itself.
		accepted := make(chan *SCTPConn, 1)
		go func() {
			c, err := ln.AcceptSCTP()
			if err != nil {
				accepted <- nil
				return
			}
			accepted <- c
		}()

		conn, err := DialSCTP("sctp", nil, bound)
		if err != nil {
			_ = ln.Close()
			t.Fatalf("dial: %v", err)
		}
		srv := <-accepted
		if err := conn.Close(); err != nil {
			t.Fatalf("conn close: %v", err)
		}
		if srv != nil {
			if err := srv.Close(); err != nil {
				t.Fatalf("accepted conn close: %v", err)
			}
		}
		if err := ln.Close(); err != nil {
			t.Fatalf("listener close: %v", err)
		}

		// The exact address must now be bindable again.
		ln2, err := ListenSCTP("sctp", bound)
		if err != nil {
			t.Fatalf("attempt %d: rebinding %s after close failed: %v",
				attempt, bound, err)
		}
		_ = ln2.Close()
	}
}

// TestCloseWithUnreachablePeerReturnsWithinTimeout pins the fallback path.
// When the peer never acknowledges the shutdown, Close must still return
// promptly rather than blocking indefinitely.
func TestCloseWithUnreachablePeerReturnsWithinTimeout(t *testing.T) {
	client, server := eorPair(t)

	// Make the peer unresponsive by abandoning it without a graceful close:
	// drop the server's descriptor so nothing answers the SHUTDOWN.
	if err := server.Abort(); err != nil {
		t.Fatalf("abort server: %v", err)
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- client.Close() }()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		t.Logf("Close returned after %v with err=%v", elapsed, err)
		if elapsed > closeTimeout+2*time.Second {
			t.Errorf("Close took %v, well past the %v timeout", elapsed, closeTimeout)
		}
	case <-time.After(closeTimeout + 5*time.Second):
		t.Fatalf("Close did not return within %v", closeTimeout+5*time.Second)
	}
}

// TestDoubleCloseReturnsEBADF checks the second close is reported rather than
// silently succeeding or closing a descriptor the process has since reused.
func TestDoubleCloseReturnsEBADF(t *testing.T) {
	client, _ := eorPair(t)

	if err := client.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := client.Close(); !errors.Is(err, syscall.EBADF) {
		t.Errorf("second Close = %v, want EBADF", err)
	}
	if err := client.Abort(); !errors.Is(err, syscall.EBADF) {
		t.Errorf("Abort after Close = %v, want EBADF", err)
	}
}

// TestCloseOnNilConn guards the nil receiver path.
func TestCloseOnNilConn(t *testing.T) {
	var c *SCTPConn
	if err := c.Close(); !errors.Is(err, syscall.EBADF) {
		t.Errorf("nil Close = %v, want EBADF", err)
	}
	if err := c.Abort(); !errors.Is(err, syscall.EBADF) {
		t.Errorf("nil Abort = %v, want EBADF", err)
	}
}

// TestConcurrentCloseAndAbort checks only one caller wins the descriptor and
// the rest get EBADF, with no double close of a reused fd.
func TestConcurrentCloseAndAbort(t *testing.T) {
	for round := 0; round < 25; round++ {
		client, _ := eorPairNoCleanup(t)

		const racers = 8
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			okCount int
		)
		wg.Add(racers)
		for i := 0; i < racers; i++ {
			go func(i int) {
				defer wg.Done()
				var err error
				if i%2 == 0 {
					err = client.Close()
				} else {
					err = client.Abort()
				}
				if err == nil {
					mu.Lock()
					okCount++
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()

		if okCount != 1 {
			t.Fatalf("round %d: %d callers reported success, want exactly 1",
				round, okCount)
		}
	}
}

// TestCloseDuringBlockedRead covers a shutdown racing an in-flight read.
func TestCloseDuringBlockedRead(t *testing.T) {
	client, server := eorPair(t)
	_ = client

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		_, _, err := server.SCTPRead(buf)
		readDone <- err
	}()

	// Give the read time to block in recvmsg.
	time.Sleep(200 * time.Millisecond)
	_ = server.Close()

	select {
	case err := <-readDone:
		t.Logf("blocked read returned %v after Close", err)
	case <-time.After(10 * time.Second):
		t.Fatal("read did not return after Close; the descriptor never unblocked")
	}
}

// TestCloseDuringWrite covers close racing a writer.
func TestCloseDuringWrite(t *testing.T) {
	client, server := eorPair(t)

	// Drain the peer. Without a reader the send queue fills and a blocking
	// write never returns, so the test would be measuring send-buffer
	// pressure rather than the close.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := server.SCTPRead(buf); err != nil {
				return
			}
		}
	}()

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		payload := make([]byte, 1024)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := client.SCTPWrite(payload, nil); err != nil {
				return
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	_ = client.Close()
	close(stop)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("writer did not observe the close")
	}
}

var _ net.Conn = (*SCTPConn)(nil)

// TestCloseAfterCompletedHandshakeGivesPeerEOF covers a graceful Close that
// looked like an abort to the peer.
//
// closeSctpSocket set SO_LINGER{Onoff:1, Linger:0} before close()
// unconditionally. Linger 0 makes close() emit an ABORT, which is what makes
// Close release the address promptly when a peer has stopped answering. But
// after a completed SHUTDOWN handshake there is nothing left to abort, and the
// ABORT went out anyway: a peer sitting in a read saw ECONNRESET rather than
// the end of the stream.
//
// Measured before the fix, this failed on every run; the peer read
// "connection reset by peer" five times out of five.
func TestCloseAfterCompletedHandshakeGivesPeerEOF(t *testing.T) {
	for i := 0; i < 5; i++ {
		client, server := eorPairNoCleanup(t)

		// Send and fully consume, so the association is idle and the peer is
		// waiting in a read when the close happens.
		const msgs = 4
		for j := 0; j < msgs; j++ {
			if _, err := client.SCTPWrite([]byte("payload"), nil); err != nil {
				t.Fatalf("round %d: write: %v", i, err)
			}
		}
		buf := make([]byte, 512)
		for j := 0; j < msgs; j++ {
			if _, _, err := server.SCTPRead(buf); err != nil {
				t.Fatalf("round %d: drain: %v", i, err)
			}
		}

		if err := client.Close(); err != nil {
			t.Fatalf("round %d: close: %v", i, err)
		}

		_, _, err := server.SCTPRead(buf)
		if errors.Is(err, syscall.ECONNRESET) {
			t.Errorf("round %d: peer saw ECONNRESET after a graceful Close; "+
				"the completed handshake was followed by an ABORT", i)
		} else if err != io.EOF {
			t.Errorf("round %d: peer read = %v, want io.EOF", i, err)
		}
		_ = server.Abort()
	}
}
