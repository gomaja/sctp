//go:build linux && !386
// +build linux,!386

package sctp

import (
	"strings"
	"syscall"
	"testing"
)

// Covers the RFC 6458 §8.1 options bound in this package that carry either a
// plain integer or a struct sctp_assoc_value. The value shape of each was read
// off a live kernel with a C probe before being bound, because the RFC describes
// the shape and Linux is what actually has to accept it.

// sockoptConn brings up one association and returns the client side.
func sockoptConn(t *testing.T) *SCTPConn {
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
		t.Fatal("listener has no address")
	}
	conn, err := DialSCTP("sctp", nil, la)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	srv, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = srv.Close() })
	return conn
}

// TestFragmentInterleaveRoundTrip checks each documented level is accepted and
// reads back.
func TestFragmentInterleaveRoundTrip(t *testing.T) {
	conn := sockoptConn(t)

	// The kernel default, read rather than assumed.
	got, err := conn.GetFragmentInterleave()
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if got != SCTPFragmentInterleaveNone {
		t.Errorf("default level = %d, want %d", got, SCTPFragmentInterleaveNone)
	}

	// Levels the kernel honours on a one-to-one socket.
	for _, level := range []int{
		SCTPFragmentInterleaveNone,
		SCTPFragmentInterleaveOther,
	} {
		if err := conn.SetFragmentInterleave(level); err != nil {
			t.Fatalf("set level %d: %v", level, err)
		}
		got, err := conn.GetFragmentInterleave()
		if err != nil {
			t.Fatalf("get after level %d: %v", level, err)
		}
		if got != level {
			t.Errorf("level reads back %d, want %d", got, level)
		}
	}

	// Level 2 is accepted but capped. RFC 6458 §8.1.20 describes it as applying
	// to one-to-many sockets, and Linux enforces that on the one-to-one sockets
	// this package creates: the call succeeds and the value reads back as
	// SCTPFragmentInterleaveOther. Measured on both connected and unconnected
	// sockets.
	//
	// Asserting the cap rather than the request is the point: a caller that needs
	// interleaving has to read the level back instead of assuming the set took.
	if err := conn.SetFragmentInterleave(SCTPFragmentInterleaveStreams); err != nil {
		t.Fatalf("set level 2: %v", err)
	}
	got, err = conn.GetFragmentInterleave()
	if err != nil {
		t.Fatalf("get after level 2: %v", err)
	}
	if got != SCTPFragmentInterleaveOther {
		t.Errorf("level 2 reads back %d; expected the kernel to cap it to %d on a "+
			"one-to-one socket", got, SCTPFragmentInterleaveOther)
	}
}

// TestFragmentInterleaveRejectsOutOfRange is the reason SetFragmentInterleave
// validates at all.
//
// RFC 6458 §8.1.20 restricts the level to 0, 1 or 2 and says other values return
// an error. Linux does not: a C probe set level 3 through setsockopt and the
// kernel accepted it, leaving the receiver in a state the specification does not
// describe. Without the check in Go, a caller passing 3 would get no error and no
// defined behaviour.
func TestFragmentInterleaveRejectsOutOfRange(t *testing.T) {
	conn := sockoptConn(t)

	for _, level := range []int{-1, 3, 100} {
		err := conn.SetFragmentInterleave(level)
		if err == nil {
			t.Errorf("level %d was accepted; RFC 6458 §8.1.20 allows only 0, 1 and 2", level)
			continue
		}
		if !strings.Contains(err.Error(), "fragment interleave") {
			t.Errorf("level %d: error does not name the option: %v", level, err)
		}
	}

	// Rejecting an invalid level must not disturb a valid one already set. Level
	// 1 rather than 2, because the kernel caps 2 on a one-to-one socket — see
	// TestFragmentInterleaveRoundTrip.
	if err := conn.SetFragmentInterleave(SCTPFragmentInterleaveOther); err != nil {
		t.Fatalf("set valid level: %v", err)
	}
	if err := conn.SetFragmentInterleave(3); err == nil {
		t.Fatal("level 3 accepted on the second attempt")
	}
	got, err := conn.GetFragmentInterleave()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != SCTPFragmentInterleaveOther {
		t.Errorf("a rejected level changed the setting to %d, want %d",
			got, SCTPFragmentInterleaveOther)
	}
}

// TestPartialDeliveryPointRoundTrip checks the byte threshold round-trips, and
// that a negative value is refused before it reaches the kernel as a large
// unsigned number.
func TestPartialDeliveryPointRoundTrip(t *testing.T) {
	conn := sockoptConn(t)

	for _, want := range []int{0, 1, 4096, 65536} {
		if err := conn.SetPartialDeliveryPoint(want); err != nil {
			t.Fatalf("set %d: %v", want, err)
		}
		got, err := conn.GetPartialDeliveryPoint()
		if err != nil {
			t.Fatalf("get after %d: %v", want, err)
		}
		if got != want {
			t.Errorf("partial delivery point reads back %d, want %d", got, want)
		}
	}

	// A negative value must be refused. The kernel would refuse it anyway — it
	// arrives as a large unsigned number and fails for exceeding the receive
	// buffer — so this asserts the message rather than merely that an error
	// occurred, which is the only part the Go check contributes.
	err := conn.SetPartialDeliveryPoint(-1)
	if err == nil {
		t.Fatal("a negative partial delivery point was accepted")
	}
	if !strings.Contains(err.Error(), "partial delivery point") {
		t.Errorf("error does not name the option, so the Go guard was bypassed "+
			"and this is the kernel's EINVAL: %v", err)
	}
}

// TestMaxBurstRoundTrip checks the assoc_value-carrying option, including the
// kernel default RFC 6458 §8.1.24 documents as 4.
func TestMaxBurstRoundTrip(t *testing.T) {
	conn := sockoptConn(t)

	got, err := conn.GetMaxBurst()
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if got != 4 {
		t.Errorf("default max burst = %d, want 4 as RFC 6458 §8.1.24 documents", got)
	}

	// 0 disables burst mitigation per the RFC, so it must be settable.
	for _, want := range []int{1, 8, 0} {
		if err := conn.SetMaxBurst(want); err != nil {
			t.Fatalf("set %d: %v", want, err)
		}
		got, err := conn.GetMaxBurst()
		if err != nil {
			t.Fatalf("get after %d: %v", want, err)
		}
		if got != want {
			t.Errorf("max burst reads back %d, want %d", got, want)
		}
	}

	if err := conn.SetMaxBurst(-1); err == nil {
		t.Error("a negative max burst was accepted")
	}
}

// TestContextRoundTrip checks the default context option.
func TestContextRoundTrip(t *testing.T) {
	conn := sockoptConn(t)

	got, err := conn.GetContext()
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if got != 0 {
		t.Errorf("default context = %d, want 0", got)
	}

	for _, want := range []uint32{1, 0x1234, ^uint32(0)} {
		if err := conn.SetContext(want); err != nil {
			t.Fatalf("set %#x: %v", want, err)
		}
		got, err := conn.GetContext()
		if err != nil {
			t.Fatalf("get after %#x: %v", want, err)
		}
		if got != want {
			t.Errorf("context reads back %#x, want %#x", got, want)
		}
	}
}

// TestReusePortBeforeBind covers SCTP_REUSE_PORT, which unlike the other
// options here cannot be set on a connection this package hands out.
//
// RFC 6458 §8.1.27 says the option has to be set before bind. Linux enforces
// that rather than ignoring a late call: on a bound or connected socket
// setsockopt fails with EFAULT, which was measured. So the round trip is
// exercised on a raw unbound descriptor — the situation a caller is in inside
// the Control hook of a SocketConfig — and the connected case is asserted to
// fail, because a silent success there would be the misleading outcome.
func TestReusePortBeforeBind(t *testing.T) {
	sock, err := syscall.Socket(syscall.AF_INET,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = syscall.Close(sock) }()

	raw := &SCTPConn{_fd: int32(sock)}

	got, err := raw.GetReusePort()
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if got {
		t.Error("port reuse is enabled by default on a fresh socket, want disabled")
	}

	if err := raw.SetReusePort(true); err != nil {
		t.Fatalf("enable before bind: %v", err)
	}
	got, err = raw.GetReusePort()
	if err != nil {
		t.Fatalf("get after enable: %v", err)
	}
	if !got {
		t.Error("port reuse reads back disabled after being enabled before bind")
	}

	if err := raw.SetReusePort(false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	got, err = raw.GetReusePort()
	if err != nil {
		t.Fatalf("get after disable: %v", err)
	}
	if got {
		t.Error("port reuse reads back enabled after being disabled")
	}

	// The negative case: too late on an established association.
	conn := sockoptConn(t)
	if err := conn.SetReusePort(true); err == nil {
		t.Error("SetReusePort succeeded on a connected socket; RFC 6458 §8.1.27 " +
			"requires it before bind and Linux reports EFAULT")
	}
}

// TestSockoptsOnClosedConn checks every accessor reports an error rather than
// acting on a released descriptor.
//
// fd() returns -1 after Close, so each of these must surface EBADF from the
// syscall rather than operating on whatever now holds that number.
func TestSockoptsOnClosedConn(t *testing.T) {
	conn := sockoptConn(t)
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	checks := []struct {
		name string
		call func() error
	}{
		{"SetFragmentInterleave", func() error {
			return conn.SetFragmentInterleave(SCTPFragmentInterleaveStreams)
		}},
		{"GetFragmentInterleave", func() error {
			_, err := conn.GetFragmentInterleave()
			return err
		}},
		{"SetPartialDeliveryPoint", func() error { return conn.SetPartialDeliveryPoint(4096) }},
		{"GetPartialDeliveryPoint", func() error {
			_, err := conn.GetPartialDeliveryPoint()
			return err
		}},
		{"SetMaxBurst", func() error { return conn.SetMaxBurst(8) }},
		{"GetMaxBurst", func() error { _, err := conn.GetMaxBurst(); return err }},
		{"SetContext", func() error { return conn.SetContext(1) }},
		{"GetContext", func() error { _, err := conn.GetContext(); return err }},
		{"GetReusePort", func() error { _, err := conn.GetReusePort(); return err }},
	}
	for _, c := range checks {
		if err := c.call(); err == nil {
			t.Errorf("%s on a closed connection returned no error", c.name)
		}
	}
}

// TestRcvInfoAndSndRcvBothParsed covers the RFC 6458 §5.3.2 migration: the
// receive path must understand SCTP_RCVINFO as well as the deprecated
// SCTP_SNDRCV.
//
// Before the parser accepted both, enabling only SCTP_RECVRCVINFO lost the
// message's stream and PPID silently — the kernel sent SCTP_RCVINFO, nothing
// recognised the cmsg type, and SCTPRead returned a nil SndRcvInfo with no
// error. Measured, and the reason this test exists.
//
// "neither" is the case that gives the others meaning: with no ancillary data
// subscribed at all, nil is the correct answer, so a parser that fabricated an
// SndRcvInfo would fail here rather than pass everything.
func TestRcvInfoAndSndRcvBothParsed(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

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
		t.Fatal("listener has no address")
	}
	client, err := DialSCTP("sctp", nil, la)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	srv, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer func() { _ = srv.Close() }()

	const wantStream = 3
	const wantPPID = 7

	for _, tc := range []struct {
		name     string
		dataIO   bool
		rcvInfo  bool
		wantInfo bool
	}{
		{"sndrcv only", true, false, true},
		{"rcvinfo only", false, true, true},
		{"both", true, true, true},
		{"neither", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := 0
			if tc.dataIO {
				events = SCTP_EVENT_DATA_IO
			}
			if err := srv.SubscribeEvents(events); err != nil {
				t.Fatalf("SubscribeEvents: %v", err)
			}
			if err := srv.SetRecvRcvInfo(tc.rcvInfo); err != nil {
				t.Fatalf("SetRecvRcvInfo: %v", err)
			}

			if _, err := client.SCTPWrite([]byte("x"),
				&SndRcvInfo{Stream: wantStream, PPID: wantPPID}); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 64)
			_, info, err := srv.SCTPRead(buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			if !tc.wantInfo {
				if info != nil {
					t.Errorf("got info %+v with no ancillary data subscribed, want nil", info)
				}
				return
			}
			if info == nil {
				t.Fatal("no per-message info; the kernel's cmsg type was not recognised")
			}
			if info.Stream != wantStream {
				t.Errorf("stream = %d, want %d", info.Stream, wantStream)
			}
			if info.PPID != wantPPID {
				t.Errorf("ppid = %d, want %d (host byte order)", info.PPID, wantPPID)
			}

			// Pin the fields whose position differs between the two structs.
			// RcvInfo orders them TSN, CumTSN, Context; SndRcvInfo orders them
			// Context, TTL, TSN, CumTSN, so converting between the two is where a
			// field-order slip hides. Stream and PPID sit at the same offset in
			// both and would not catch it.
			//
			// The kernel picks the TSN, so the exact value is not predictable —
			// but Context is whatever SetContext last set, which makes it an
			// anchor: a mapping that put TSN where Context belongs shows up as a
			// kernel-chosen TSN appearing in Context.
			const wantContext = 0x5eed
			if err := srv.SetContext(wantContext); err != nil {
				t.Fatalf("SetContext: %v", err)
			}
			if _, err := client.SCTPWrite([]byte("y"),
				&SndRcvInfo{Stream: wantStream, PPID: wantPPID}); err != nil {
				t.Fatalf("second write: %v", err)
			}
			_, info2, err := srv.SCTPRead(buf)
			if err != nil {
				t.Fatalf("second read: %v", err)
			}
			if info2 == nil {
				t.Fatal("no per-message info on the second read")
			}
			if info2.Context != wantContext {
				t.Errorf("context = %#x, want %#x; a value this far off suggests "+
					"another field was mapped into Context", info2.Context, wantContext)
			}
			if info2.TSN == wantContext {
				t.Error("TSN carries the context value, so the two fields are swapped")
			}
			if info2.TSN == 0 {
				t.Error("TSN is zero; the kernel always assigns one")
			}
		})
	}
}
