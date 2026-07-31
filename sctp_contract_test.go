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
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestReadWithZeroLengthBufferConsumesNothing pins the io.Reader contract that
// a read into an empty buffer takes nothing from the stream.
//
// The read path always hands recvmsg a control buffer, and recvmsg follows the
// stdlib idiom of substituting a one-byte scratch iovec when the data buffer is
// empty but the control buffer is not — which is right for a genuine
// control-only receive and wrong for a caller's empty slice. The kernel
// dequeued a payload byte into a package-local variable and reported n=1, so
// Read returned n greater than len(p) and the byte was gone. Measured: eight
// bytes queued, Read(nil) returned 1, the next read returned "BCDEFGH".
//
// The second half matters more than the first. A test that only checked the
// return value would pass against a version that still ate the byte, and the
// byte is what the caller loses.
func TestReadWithZeroLengthBufferConsumesNothing(t *testing.T) {
	client, server := eorPair(t)

	const payload = "ABCDEFGH"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitReadable(t, server)

	n, err := server.Read(nil)
	if n != 0 || err != nil {
		t.Errorf("Read(nil) = (%d, %v), want (0, nil): io.Reader requires 0 <= n <= len(p)", n, err)
	}
	n, err = server.Read([]byte{})
	if n != 0 || err != nil {
		t.Errorf("Read([]byte{}) = (%d, %v), want (0, nil)", n, err)
	}

	buf := make([]byte, 64)
	got, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read after the empty reads: %v", err)
	}
	if string(buf[:got]) != payload {
		t.Errorf("message came back as %q, want %q: the empty reads consumed from the stream",
			buf[:got], payload)
	}
}

// TestReadIntoFullBufferTailIsNotAConsumingRead is the way the previous defect
// is reached without anyone writing Read(nil).
//
// The ordinary framing loop reads into buf[total:], which becomes a zero-length
// slice the moment the buffer fills. A read that returns 1 there pushes total
// past cap, so the caller's next line — buf[:total] — panics. Measured with a
// four-byte buffer: the second read returned n=1 and total reached 5.
func TestReadIntoFullBufferTailIsNotAConsumingRead(t *testing.T) {
	client, server := eorPair(t)

	if _, err := client.Write([]byte("WXYZ!")); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitReadable(t, server)

	buf := make([]byte, 4)
	total := 0
	for i := 0; i < 3; i++ {
		n, err := server.Read(buf[total:])
		if n < 0 || total+n > len(buf) {
			t.Fatalf("read %d into a %d-byte tail returned n=%d, taking the total to %d "+
				"with a %d-byte buffer: buf[:total] would panic here",
				i, len(buf)-total, n, total+n, len(buf))
		}
		total += n
		if err != nil || total == len(buf) {
			if total == len(buf) {
				// One more, on the now-empty tail: this is the read that used
				// to consume a byte.
				n, err := server.Read(buf[total:])
				if n != 0 {
					t.Fatalf("read into the empty tail returned n=%d, want 0", n)
				}
				if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("read into the empty tail: %v", err)
				}
			}
			break
		}
	}
}

// TestAcceptDoesNotReturnATypedNilConn checks that a failed Accept reports a
// nil net.Conn, not an interface value wrapping a nil *SCTPConn.
//
// Returning the concrete pointer straight through an interface return type
// gives the result a non-nil type word, so the idiomatic `if conn != nil` is
// true and any use of it panics in (*SCTPConn).fd. net.TCPListener.Accept
// converts explicitly for this reason, and an accept-deadline expiry — the
// ordinary way a polling accept loop ends an iteration — is enough to reach it.
func TestAcceptDoesNotReturnATypedNilConn(t *testing.T) {
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

	// Through the net.Listener interface, which is where the type word matters.
	var l net.Listener = ln
	conn, err := l.Accept()
	if err == nil {
		_ = conn.Close()
		t.Fatal("Accept succeeded against an expired deadline")
	}
	if conn != nil {
		t.Errorf("Accept returned err=%v with a non-nil net.Conn of dynamic type %T; "+
			"a caller testing conn != nil panics on the next use", err, conn)
	}
}

// TestAcceptedConnDoesNotInheritTheAcceptDeadline is the regression test for a
// deadline that leaks from the listener into every connection it accepts.
//
// AcceptSCTP programs SO_RCVTIMEO on the listening descriptor to implement the
// accept deadline, and sctp_copy_sock copies sk_rcvtimeo onto the socket the
// kernel creates for the new association. The accepted descriptor therefore
// arrives with that timeout already armed, while the SCTPConn wrapping it
// records no deadline at all — so the read path's corrective applyTimeout,
// which is gated on there being one, never runs.
//
// Two things go wrong together, and the second is why a caller cannot even
// paper over the first: the read returns early, and because no deadline is
// recorded locally the errno is not mapped, so the caller gets a bare EAGAIN
// for which errors.Is(err, os.ErrDeadlineExceeded) is false.
//
// The polling accept loop this breaks is the standard one — a short deadline so
// the server can notice a shutdown flag between accepts.
func TestAcceptedConnDoesNotInheritTheAcceptDeadline(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	dialed := make(chan *SCTPConn, 1)
	go func() {
		c, err := dialRetry(ln.Addr().(*SCTPAddr))
		if err != nil {
			dialed <- nil
			return
		}
		dialed <- c
	}()

	const acceptWindow = 300 * time.Millisecond
	var server *SCTPConn
	for i := 0; i < 40 && server == nil; i++ {
		if err := ln.SetDeadline(time.Now().Add(acceptWindow)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
		c, err := ln.AcceptSCTP()
		if err == nil {
			server = c
			break
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("accept: %v", err)
		}
	}
	if server == nil {
		t.Fatal("no association accepted")
	}
	defer func() { _ = server.CloseWithTimeout(200 * time.Millisecond) }()

	client := <-dialed
	if client == nil {
		t.Fatal("dial failed")
	}
	defer func() { _ = client.CloseWithTimeout(200 * time.Millisecond) }()

	// Clear the listener's deadline. It makes no difference to the accepted
	// socket, which holds its own copy — that is the point of the test.
	if err := ln.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing the listener deadline: %v", err)
	}

	// The descriptor must carry no timeout at all.
	tv, err := getRcvTimeo(server.fd())
	if err != nil {
		t.Fatalf("getsockopt SO_RCVTIMEO: %v", err)
	}
	if tv.Sec != 0 || tv.Usec != 0 {
		t.Errorf("accepted socket has SO_RCVTIMEO = %ds%dus, want 0: "+
			"it inherited the listener's %v accept deadline", tv.Sec, tv.Usec, acceptWindow)
	}

	// And a read on it must block past that window rather than returning EAGAIN.
	type result struct {
		n   int
		err error
		el  time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		n, err := server.Read(make([]byte, 64))
		done <- result{n, err, time.Since(start)}
	}()

	select {
	case r := <-done:
		t.Errorf("Read on a connection that never had a deadline returned after %v: "+
			"n=%d err=%v (os.ErrDeadlineExceeded=%v, EAGAIN=%v)",
			r.el.Round(time.Millisecond), r.n, r.err,
			errors.Is(r.err, os.ErrDeadlineExceeded), errors.Is(r.err, syscall.EAGAIN))
	case <-time.After(3 * acceptWindow):
		// Still blocked, which is correct. Unblock it so the goroutine exits.
		if _, err := client.Write([]byte("x")); err != nil {
			t.Logf("unblocking write: %v", err)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("reader did not return after the peer wrote")
		}
	}
}

// TestAbortWakesAParkedReader is the regression test for an Abort that reports
// success without doing anything.
//
// abortSctpSocket armed SO_LINGER{1,0} and closed the descriptor. Linux does
// not wake a task blocked in recvmsg when another thread closes the fd: the
// blocked call holds a reference to the struct file, so close only unhooks the
// descriptor number and defers the final release. sctp_close therefore never
// ran while a reader was parked, the ABORT was never put on the wire, and the
// association stayed up — with Abort having returned nil in tens of
// microseconds. Measured: no ABORT chunk in seven seconds of capture, both ends
// still listed in /proc/net/sctp/assocs.
//
// The graceful path never had this problem because it calls shutdown first,
// which sets RCV_SHUTDOWN and wakes the reader.
//
// This test covers the waking half only. Which shutdown mode the fix uses is
// pinned by TestAbortReportsTheUserAbortCause: SHUT_RDWR and SHUT_WR also wake
// the reader, so they pass here, but they ask for a graceful teardown and the
// peer then sees SHUTDOWN/SHUTDOWN_ACK/SHUTDOWN_COMPLETE and no ABORT at all —
// confirmed by capture, and caught there by the absence of SCTP_COMM_LOST.
func TestAbortWakesAParkedReader(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	defer func() { _ = client.CloseWithTimeout(200 * time.Millisecond) }()

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := server.Read(make([]byte, 64))
		done <- result{n, err}
	}()
	// Give the reader time to reach recvmsg. Aborting before it parks tests
	// nothing: the defect is specifically that a blocked reader pins the file.
	time.Sleep(300 * time.Millisecond)

	if err := server.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}

	select {
	case r := <-done:
		if r.err == nil && r.n > 0 {
			t.Errorf("parked Read returned data after Abort: n=%d", r.n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parked Read still blocked 5s after Abort returned nil: " +
			"closing the descriptor does not wake a reader holding it")
	}

	// The peer must be told. Without the ABORT it sees nothing at all and this
	// read simply times out.
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, err := client.Read(make([]byte, 64))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("peer read timed out after the local end aborted: n=%d err=%v; "+
			"no ABORT reached it, so the association is still up", n, err)
	}
	if err == nil {
		t.Errorf("peer read succeeded (n=%d) after the local end aborted", n)
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) &&
		!errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, io.EOF) {
		t.Logf("peer read error was %v; ECONNRESET or EOF expected but any "+
			"prompt failure proves the ABORT arrived", err)
	}
}

// TestErrorsAfterCloseWrapNetErrClosed pins the error a caller gets from a
// connection that has already been closed.
//
// net documents errors.Is(err, net.ErrClosed) as the way to recognise use of a
// closed connection, and the idiomatic shutdown loop is written around it. This
// package returned a bare syscall.EBADF, for which that test is always false —
// so the loop never matched and logged EBADF as an unexpected failure instead
// of exiting.
func TestErrorsAfterCloseWrapNetErrClosed(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	defer func() { _ = server.CloseWithTimeout(200 * time.Millisecond) }()

	if err := client.CloseWithTimeout(200 * time.Millisecond); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Read", func() error { _, err := client.Read(make([]byte, 8)); return err }},
		{"Write", func() error { _, err := client.Write([]byte("x")); return err }},
		{"SCTPRead", func() error { _, _, err := client.SCTPRead(make([]byte, 8)); return err }},
		{"SCTPWrite", func() error { _, err := client.SCTPWrite([]byte("x"), nil); return err }},
		{"ReadMsg", func() error { _, _, err := client.ReadMsg(8); return err }},
	} {
		err := tc.call()
		if err == nil {
			t.Errorf("%s on a closed connection returned nil", tc.name)
			continue
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s on a closed connection = %v; errors.Is(err, net.ErrClosed) is false, "+
				"so the documented shutdown idiom never matches", tc.name, err)
		}
	}
}

// TestWriteWithZeroLengthBufferIsANoOp mirrors the read side: net.Conn's Write
// returns (0, nil) for an empty buffer, and this returned the kernel's EINVAL.
//
// SCTPWrite and SCTPWriteInfo keep passing it through — a zero-length SCTP
// message is a real thing to ask the kernel for, and it is entitled to refuse.
// Only the net.Conn method is held to the net.Conn contract.
func TestWriteWithZeroLengthBufferIsANoOp(t *testing.T) {
	client, _ := eorPair(t)

	n, err := client.Write([]byte{})
	if n != 0 || err != nil {
		t.Errorf("Write([]byte{}) = (%d, %v), want (0, nil) as net.Conn specifies", n, err)
	}
	n, err = client.Write(nil)
	if n != 0 || err != nil {
		t.Errorf("Write(nil) = (%d, %v), want (0, nil)", n, err)
	}
}

// TestPrimaryAddrSettersRejectMultipleAddresses is the regression test for a
// setter that silently acted on the wrong path.
//
// Both setters marshal the whole SCTPAddr into a struct holding one
// sockaddr_storage and let the kernel read the first entry. The only guard
// compares the marshalled length against that buffer, which nine IPv4
// addresses would be needed to trip — so an ordinary two-homed address was
// accepted and quietly applied to whichever address happened to sort first.
//
// That is exactly what the documentation tells callers to pass: it says to
// choose one of the addresses the peer announced, and GetPeerAddrs and
// RemoteAddr both hand back a single *SCTPAddr carrying all of them. Measured
// on a live two-homed association: SetPrimaryPeerAddr with the peer's full
// address returned nil and reset the primary to the first path.
func TestPrimaryAddrSettersRejectMultipleAddresses(t *testing.T) {
	ips := requireLoopbacks(t, 2)
	client, _ := eorPair(t)

	// The peer address as the package hands it back — which is what the
	// documentation points callers at, and the shape the setters must accept.
	peer, ok := client.RemoteAddr().(*SCTPAddr)
	if !ok || len(peer.IPAddrs) != 1 {
		t.Fatalf("expected a single-homed peer address, got %v", client.RemoteAddr())
	}

	// Exactly one address must work. Testing this first establishes that the
	// address and port are ones the kernel accepts, so an EINVAL below can only
	// have come from the guard rather than from the association not knowing the
	// path.
	if err := client.SetPrimaryPeerAddr(peer); err != nil {
		t.Fatalf("SetPrimaryPeerAddr with the peer's own address: %v", err)
	}

	// The same address with a second one appended. Only the first sockaddr
	// reaches the kernel, so before the guard this returned nil having applied
	// a request the caller did not make.
	extra := ips[0]
	if extra == peer.IPAddrs[0].IP.String() && len(ips) > 1 {
		extra = ips[1]
	}
	multi := &SCTPAddr{
		IPAddrs: append(append([]net.IPAddr{}, peer.IPAddrs...), net.IPAddr{IP: net.ParseIP(extra)}),
		Port:    peer.Port,
	}
	if err := client.SetPrimaryPeerAddr(multi); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("SetPrimaryPeerAddr with %d addresses = %v, want EINVAL: "+
			"the option names one path, so the trailing addresses are silently discarded",
			len(multi.IPAddrs), err)
	}
	// SetPeerPrimaryAddr answers EPERM on a stock kernel, since ASCONF is off
	// by default — so EINVAL here can only be the guard, reached before the
	// syscall.
	if err := client.SetPeerPrimaryAddr(multi); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("SetPeerPrimaryAddr with %d addresses = %v, want EINVAL",
			len(multi.IPAddrs), err)
	}

	// An empty address list names no path at all.
	none := &SCTPAddr{Port: peer.Port}
	if err := client.SetPrimaryPeerAddr(none); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("SetPrimaryPeerAddr with no address = %v, want EINVAL", err)
	}
}

// TestIPv6AssociationRoundTrip is the coverage the package had none of.
//
// Every socket test dials 127.0.0.1, so the AF_INET6 half of bindLocal — the
// branch that supplies net.IPv6zero when a caller passes a port and no
// address — is never executed. Changing it to IPv4zero breaks
// ListenSCTP("sctp6", ...) outright and no test notices.
//
// IPv6 SCTP works in the documented container, so this is unwritten coverage
// rather than an environment limit; it skips only where the host has no IPv6.
func TestIPv6AssociationRoundTrip(t *testing.T) {
	// Whether IPv6 SCTP exists here is decided without going through the code
	// under test. Skipping on ListenSCTP's own error would let a broken
	// bindLocal skip the test it exists for: substituting IPv4zero for the v6
	// wildcard makes the listen fail, and a skip reads as a pass.
	requireIPv6SCTP(t)

	// A wildcard bind with a port and no address, which is what exercises
	// bindLocal's address-family branch.
	ln, err := ListenSCTP("sctp6", &SCTPAddr{Port: 0})
	if err != nil {
		t.Fatalf("sctp6 listen on the wildcard: %v", err)
	}
	defer func() { _ = ln.Close() }()

	la, ok := ln.Addr().(*SCTPAddr)
	if !ok || len(la.IPAddrs) == 0 {
		t.Fatalf("listener reports no address: %v", ln.Addr())
	}
	for _, ip := range la.IPAddrs {
		if ip.IP.To4() != nil {
			t.Errorf("sctp6 listener bound the IPv4 address %s; the v6 wildcard "+
				"branch of bindLocal handed over the wrong family", ip.IP)
		}
	}

	accepted := make(chan *SCTPConn, 1)
	go func() {
		c, aerr := ln.AcceptSCTP()
		if aerr != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	raddr := &SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}},
		Port:    la.Port,
	}
	client, err := DialSCTP("sctp6", nil, raddr)
	if err != nil {
		t.Fatalf("sctp6 dial to %v: %v", raddr, err)
	}
	defer func() { _ = client.CloseWithTimeout(200 * time.Millisecond) }()

	server, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer func() { _ = server.CloseWithTimeout(200 * time.Millisecond) }()

	const payload = "over v6"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != payload {
		t.Errorf("read %q, want %q", buf[:n], payload)
	}

	// The association really is v6 on both sides.
	if ra, ok := client.RemoteAddr().(*SCTPAddr); ok && len(ra.IPAddrs) > 0 {
		if ra.IPAddrs[0].IP.To4() != nil {
			t.Errorf("client's peer address is IPv4 (%s) on an sctp6 association",
				ra.IPAddrs[0].IP)
		}
	}
}

// requireIPv6SCTP skips unless an AF_INET6 SCTP socket can bind the v6
// loopback, established with raw syscalls so the answer does not depend on the
// package being tested.
func requireIPv6SCTP(t *testing.T) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("no AF_INET6 SCTP socket here: %v", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	sa := &syscall.SockaddrInet6{}
	copy(sa.Addr[:], net.IPv6loopback.To16())
	if err := syscall.Bind(fd, sa); err != nil {
		t.Skipf("cannot bind ::1 for SCTP here: %v", err)
	}
}

// getRcvTimeo reads SO_RCVTIMEO off a descriptor. The syscall package has a
// setter for a Timeval option but no getter, so this goes to getsockopt
// directly rather than inferring the value from behaviour.
func getRcvTimeo(fd int) (syscall.Timeval, error) {
	var tv syscall.Timeval
	optlen := uint32(unsafe.Sizeof(tv))
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_RCVTIMEO),
		uintptr(unsafe.Pointer(&tv)), uintptr(unsafe.Pointer(&optlen)), 0)
	if errno != 0 {
		return tv, errno
	}
	return tv, nil
}

// waitReadable blocks until the connection has something queued, so a test
// does not race the kernel's delivery. It reads nothing itself.
func waitReadable(t *testing.T, c *SCTPConn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var fds syscall.FdSet
		fd := c.fd()
		if fd < 0 {
			t.Fatal("connection closed while waiting for data")
		}
		fds.Bits[fd/64] |= 1 << (uint(fd) % 64)
		tv := syscall.Timeval{Usec: 50000}
		n, err := syscall.Select(fd+1, &fds, nil, nil, &tv)
		if err != nil && !errors.Is(err, syscall.EINTR) {
			t.Fatalf("select: %v", err)
		}
		if n > 0 {
			return
		}
	}
	t.Fatal("nothing became readable within 3s")
}
