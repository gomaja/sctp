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
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// isCloseOnExec reports whether fd will be closed across an exec.
func isCloseOnExec(t *testing.T, fd int) bool {
	t.Helper()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd),
		syscall.F_GETFD, 0)
	if errno != 0 {
		t.Fatalf("F_GETFD on fd %d: %v", fd, errno)
	}
	return flags&syscall.FD_CLOEXEC != 0
}

// TestAcceptedAssociationIsCloseOnExec pins the flag AcceptSCTP passes to
// accept4.
//
// Every socket this package creates itself asks for SOCK_CLOEXEC; the accepted
// one asked for nothing. That is the descriptor it matters most for, because it
// is a live association: a child forked while the server is running inherits
// every connection open at that instant, can read and write them, and — by
// holding the descriptor — keeps the port bound and swallows the reset the peer
// should get when this side closes.
func TestAcceptedAssociationIsCloseOnExec(t *testing.T) {
	client, server := eorPair(t)

	if !isCloseOnExec(t, server.fd()) {
		t.Error("accepted association is not close-on-exec; a forked child " +
			"inherits it, and closing this side then neither resets the peer " +
			"nor frees the port")
	}
	// The dialled side is the control: it has always been created with
	// SOCK_CLOEXEC, so a failure here means the test is wrong, not the fix.
	if !isCloseOnExec(t, client.fd()) {
		t.Error("dialled association is not close-on-exec either; this test " +
			"is measuring the wrong thing")
	}
}

// TestListenDoesNotMutateItsAddr checks the caller's SCTPAddr survives a listen
// unchanged.
//
// The bind path used to append the wildcard address into laddr.IPAddrs, which
// is the caller's value. Two things follow: it is a data race whenever one
// address is shared between goroutines, which is the ordinary way to run a
// client and server against a fixed endpoint; and it changes the address's
// meaning, so a value that came back from a "sctp6" listen carries [::] and
// fails a later "sctp4" bind.
func TestListenDoesNotMutateItsAddr(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", ":0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	before := len(addr.IPAddrs)

	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if got := len(addr.IPAddrs); got != before {
		t.Errorf("ListenSCTP appended to the caller's IPAddrs: %d -> %d (%v)",
			before, got, addr.IPAddrs)
	}
}

// TestDialDoesNotMutateItsAddr is the same for the dial path, and additionally
// shows the consequence: the same address value is reused for a second dial.
func TestDialDoesNotMutateItsAddr(t *testing.T) {
	ln, err := ListenSCTP("sctp", mustResolve(t, "127.0.0.1:0"))
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
			t.Cleanup(func() { _ = c.Close() })
		}
	}()

	laddr, err := ResolveSCTPAddr("sctp", ":0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	before := len(laddr.IPAddrs)

	raddr := ln.Addr().(*SCTPAddr)
	first, err := DialSCTP("sctp", laddr, raddr)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer func() { _ = first.Close() }()

	if got := len(laddr.IPAddrs); got != before {
		t.Fatalf("DialSCTP appended to the caller's IPAddrs: %d -> %d (%v)",
			before, got, laddr.IPAddrs)
	}

	// Reusing the value must still mean "any local address, any port". If the
	// first dial wrote a wildcard into it, this one binds an address the
	// caller never asked for.
	second, err := DialSCTP("sctp", laddr, raddr)
	if err != nil {
		t.Fatalf("second dial with the same laddr: %v", err)
	}
	_ = second.Close()
}

func mustResolve(t *testing.T, s string) *SCTPAddr {
	t.Helper()
	addr, err := ResolveSCTPAddr("sctp", s)
	if err != nil {
		t.Fatalf("resolve %q: %v", s, err)
	}
	return addr
}

// TestUnknownNetworkIsRejected covers the network string, which reaches this
// package straight from a caller's configuration.
//
// favoriteAddrFamily, vendored from the standard library, indexes the name's
// last byte. The standard library only calls it with a name already validated;
// this package did not, so an empty string panicked with an index out of range
// and "tcp" quietly produced an SCTP socket.
func TestUnknownNetworkIsRejected(t *testing.T) {
	addr := mustResolve(t, "127.0.0.1:0")

	for _, network := range []string{"", "sctp", "sctp4"} {
		ln, err := ListenSCTP(network, mustResolve(t, "127.0.0.1:0"))
		if err != nil {
			t.Errorf("ListenSCTP(%q) = %v, want success", network, err)
			continue
		}
		_ = ln.Close()
	}

	for _, network := range []string{"tcp", "udp", "sctp5", "foo", "SCTP"} {
		t.Run("listen "+network, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ListenSCTP(%q) panicked: %v", network, r)
				}
			}()
			ln, err := ListenSCTP(network, addr)
			if err == nil {
				_ = ln.Close()
				t.Errorf("ListenSCTP(%q) succeeded; an unknown network must "+
					"not silently create an SCTP socket", network)
			}
		})
		t.Run("dial "+network, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DialSCTP(%q) panicked: %v", network, r)
				}
			}()
			if c, err := DialSCTP(network, nil, addr); err == nil {
				_ = c.Close()
				t.Errorf("DialSCTP(%q) succeeded", network)
			}
		})
	}
}

// TestEmptyNetworkDoesNotPanic is the specific case that used to crash, kept
// separate so a failure names it directly.
func TestEmptyNetworkDoesNotPanic(t *testing.T) {
	addr := mustResolve(t, "127.0.0.1:0")

	// "" is a documented synonym for "sctp" in ResolveSCTPAddr, so it must be
	// accepted here rather than merely not crash.
	ln, err := ListenSCTP("", addr)
	if err != nil {
		t.Fatalf(`ListenSCTP("") = %v, want success; "" is ResolveSCTPAddr's `+
			`own synonym for "sctp"`, err)
	}
	_ = ln.Close()
}

// TestUnknownNetworkErrorIsTheStandardType checks the error a caller gets is
// one they can match on.
func TestUnknownNetworkErrorIsTheStandardType(t *testing.T) {
	_, err := ResolveSCTPAddr("tcp", "127.0.0.1:0")
	if err == nil {
		t.Fatal("ResolveSCTPAddr with a tcp network returned no error")
	}
	var unknown net.UnknownNetworkError
	if !errors.As(err, &unknown) {
		t.Errorf("err is %T (%v), want net.UnknownNetworkError", err, err)
	}
}

// TestReadMsgSkipsNotifications checks the whole-message API does not hand a
// notification back as if the peer had sent it.
//
// SCTPReadFlags returns the notification flag, so a caller using it can tell
// the difference. ReadMsg does not return flags at all, and the kernel sets
// MSG_EOR on notifications, so one arriving mid-stream looked exactly like a
// finished application message. Installing a NotificationHandler avoided it,
// but there is no exported way to install one after the connection exists.
func TestReadMsgSkipsNotifications(t *testing.T) {
	// The case that matters is a notification at the head of the receive
	// queue. Writing a message and then generating an event does not test it:
	// the message is delivered first, so ReadMsg returns before it ever sees
	// the notification and passes whether or not it handles one.
	t.Run("notification with nothing behind it", func(t *testing.T) {
		client, server := eorPair(t)

		if err := client.SubscribeEvent(SCTP_ASSOC_CHANGE, true); err != nil {
			t.Fatalf("subscribe: %v", err)
		}
		// An abort queues SCTP_ASSOC_CHANGE and no data at all, so the only
		// thing ReadMsg can find is the notification.
		if err := server.Abort(); err != nil {
			t.Fatalf("abort: %v", err)
		}

		if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		msg, _, err := client.ReadMsg(4096)
		if err == nil {
			t.Fatalf("ReadMsg returned %d bytes (% x) and no error on an "+
				"aborted association; those are the bytes of a struct "+
				"sctp_assoc_change, returned as if the peer had sent them",
				len(msg), msg)
		}
		if len(msg) != 0 {
			t.Errorf("ReadMsg returned %d bytes alongside %v; a notification "+
				"is leaking into the message", len(msg), err)
		}
	})

	t.Run("message ahead of a notification", func(t *testing.T) {
		client, server := eorPair(t)

		if err := client.SubscribeEvent(SCTP_SHUTDOWN_EVENT, true); err != nil {
			t.Fatalf("subscribe: %v", err)
		}
		if err := client.SubscribeEvent(SCTP_ASSOC_CHANGE, true); err != nil {
			t.Fatalf("subscribe: %v", err)
		}

		const payload = "application data"
		if _, err := server.SCTPWrite([]byte(payload), nil); err != nil {
			t.Fatalf("write: %v", err)
		}
		// Close the writing side so a shutdown notification follows.
		go func() { _ = server.Close() }()

		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		msg, _, err := client.ReadMsg(4096)
		if err != nil {
			t.Fatalf("ReadMsg: %v", err)
		}
		if string(msg) != payload {
			t.Fatalf("ReadMsg returned %q (% x), want %q", msg, msg, payload)
		}
	})
}

// TestReadWithoutDeadlineDoesNotReportADeadline checks EAGAIN is only
// translated when a deadline could have caused it.
//
// The read path mapped every EAGAIN to os.ErrDeadlineExceeded. On a descriptor
// that is non-blocking for some other reason — one handed to NewSCTPConn, or
// one a SocketConfig.Control hook set O_NONBLOCK on — an ordinary empty read
// then reported a timeout that was never set, and a caller treating that as
// "my deadline fired, retry" spins. AcceptSCTP and the write path already drew
// the distinction; the read path was the one that did not.
func TestReadWithoutDeadlineDoesNotReportADeadline(t *testing.T) {
	client, _ := eorPair(t)

	if err := syscall.SetNonblock(client.fd(), true); err != nil {
		t.Fatalf("set nonblock: %v", err)
	}
	defer func() { _ = syscall.SetNonblock(client.fd(), false) }()

	// No deadline has ever been set on this connection.
	_, _, err := client.SCTPRead(make([]byte, 64))
	if err == nil {
		t.Fatal("read on an idle non-blocking association returned no error")
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("read reported %v with no deadline set; want the raw EAGAIN, "+
			"since nothing timed out", err)
	}
	if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) {
		t.Errorf("read reported %v, want EAGAIN", err)
	}
}

// TestReadWithDeadlineStillReportsTheDeadline is the other half: the mapping
// must survive for the case it was written for.
func TestReadWithDeadlineStillReportsTheDeadline(t *testing.T) {
	client, _ := eorPair(t)

	if err := client.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	start := time.Now()
	_, _, err := client.SCTPRead(make([]byte, 64))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read after the deadline returned %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("read returned after %v, well before its 150ms deadline", elapsed)
	}
}
