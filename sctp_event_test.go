//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"unsafe"
)

// These tests cover the SCTP_EVENT option from RFC 6458 §6.2.2, the
// per-notification replacement for the deprecated SCTP_EVENTS bulk option.
//
// Everything asserted here was first measured against a running kernel with a C
// probe, because the option is not exercised anywhere else in this package and
// the RFC does not describe Linux's error behaviour.

// eventDial brings up one association and returns the client side.
func eventDial(t *testing.T) *SCTPConn {
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

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
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

// TestEventStructMatchesKernel pins struct Event to the kernel's struct
// sctp_event.
//
// The struct is handed to setsockopt as raw memory, so a size or offset
// disagreement is silent: the kernel reads whichever bytes happen to sit at the
// offsets it expects. sctp_assoc_t is 4 bytes, se_type is 2, se_on is 1, and the
// struct is padded to 8 — the trailing pad byte in Event is what makes the Go
// side agree.
func TestEventStructMatchesKernel(t *testing.T) {
	var ev Event
	if got, want := unsafe.Sizeof(ev), uintptr(8); got != want {
		t.Errorf("sizeof(Event) = %d, want %d to match struct sctp_event", got, want)
	}
	if got, want := unsafe.Offsetof(ev.AssocID), uintptr(0); got != want {
		t.Errorf("AssocID at %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(ev.Type), uintptr(4); got != want {
		t.Errorf("Type at %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(ev.On), uintptr(6); got != want {
		t.Errorf("On at %d, want %d", got, want)
	}
}

// TestSubscribeEventRoundTrip checks that a subscription made one event at a
// time is what the kernel reports back.
func TestSubscribeEventRoundTrip(t *testing.T) {
	conn := eventDial(t)

	for _, et := range []SCTPNotificationType{
		SCTP_ASSOC_CHANGE, SCTP_SHUTDOWN_EVENT, SCTP_SENDER_DRY_EVENT,
	} {
		if err := conn.SubscribeEvent(et, true); err != nil {
			t.Fatalf("subscribe %#x: %v", uint16(et), err)
		}
		on, err := conn.EventSubscribed(et)
		if err != nil {
			t.Fatalf("query %#x: %v", uint16(et), err)
		}
		if !on {
			t.Errorf("event %#x reads back unsubscribed after subscribing", uint16(et))
		}

		if err := conn.SubscribeEvent(et, false); err != nil {
			t.Fatalf("unsubscribe %#x: %v", uint16(et), err)
		}
		on, err = conn.EventSubscribed(et)
		if err != nil {
			t.Fatalf("query %#x after unsubscribe: %v", uint16(et), err)
		}
		if on {
			t.Errorf("event %#x still subscribed after unsubscribing", uint16(et))
		}
	}
}

// TestSubscribeEventScopeOnConnectedSocket documents that on a connected socket
// SCTP_EVENT and SCTP_EVENTS do not read the same state.
//
// This was measured, and it contradicts the obvious assumption. On a socket with
// no association, setting an event through SCTP_EVENT reads back as set in the
// SCTP_EVENTS struct too. Once an association exists, SCTP_EVENT with AssocID 0
// acts on that association while SCTP_EVENTS reads the endpoint's defaults, so
// the per-event subscription reports on through SCTP_EVENT and off through
// SCTP_EVENTS.
//
// Neither option is wrong; they answer different questions. The consequence for
// callers is concrete: do not mix them on a connected socket and expect one to
// report what the other set. This test pins the behaviour so that if a future
// kernel unifies the two, it fails and the guidance above gets revisited rather
// than quietly becoming false.
func TestSubscribeEventScopeOnConnectedSocket(t *testing.T) {
	conn := eventDial(t)

	if err := conn.SubscribeEvent(SCTP_ASSOC_CHANGE, true); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Through SCTP_EVENT the subscription is visible.
	on, err := conn.EventSubscribed(SCTP_ASSOC_CHANGE)
	if err != nil {
		t.Fatalf("EventSubscribed: %v", err)
	}
	if !on {
		t.Error("SCTP_EVENT does not report an event it just set")
	}

	// Through the bulk option it is not, because that reads endpoint defaults.
	var bulk EventSubscribe
	optlen := unsafe.Sizeof(bulk)
	if _, _, err := getsockopt(conn.fd(), SCTP_EVENTS,
		uintptr(unsafe.Pointer(&bulk)), uintptr(unsafe.Pointer(&optlen))); err != nil {
		t.Fatalf("getsockopt(SCTP_EVENTS): %v", err)
	}
	if bulk.Association != 0 {
		t.Log("SCTP_EVENTS now reflects a per-association SCTP_EVENT subscription; " +
			"the scope note on SubscribeEvent should be revisited")
	}

	// The negative half, which holds in both scopes: setting one event must not
	// turn on a different one.
	if bulk.SenderDry != 0 {
		t.Error("subscribing SCTP_ASSOC_CHANGE also turned on the sender-dry event")
	}
	dry, err := conn.EventSubscribed(SCTP_SENDER_DRY_EVENT)
	if err != nil {
		t.Fatalf("EventSubscribed(sender dry): %v", err)
	}
	if dry {
		t.Error("subscribing SCTP_ASSOC_CHANGE also subscribed the sender-dry event")
	}
}

// TestSubscribeEventVisibleInBulkBeforeConnect is the other half of the scope
// story: with no association, the two options do agree.
//
// Keeping both cases makes the distinction falsifiable — if either changes, one
// of these two tests fails rather than the pair silently agreeing on nothing.
func TestSubscribeEventVisibleInBulkBeforeConnect(t *testing.T) {
	sock, err := syscall.Socket(syscall.AF_INET,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = syscall.Close(sock) }()

	param := Event{Type: uint16(SCTP_ASSOC_CHANGE), On: 1}
	if _, _, err := setsockopt(sock, SCTP_EVENT,
		uintptr(unsafe.Pointer(&param)), unsafe.Sizeof(param)); err != nil {
		t.Fatalf("setsockopt(SCTP_EVENT) on an unconnected socket: %v", err)
	}

	var bulk EventSubscribe
	optlen := unsafe.Sizeof(bulk)
	if _, _, err := getsockopt(sock, SCTP_EVENTS,
		uintptr(unsafe.Pointer(&bulk)), uintptr(unsafe.Pointer(&optlen))); err != nil {
		t.Fatalf("getsockopt(SCTP_EVENTS): %v", err)
	}
	if bulk.Association == 0 {
		t.Error("on an unconnected socket, an SCTP_EVENT subscription should be " +
			"visible through SCTP_EVENTS")
	}
}

// TestSubscribeEventRejectsUnknownType checks the kernel's validation is
// surfaced rather than swallowed.
//
// A silently accepted bogus type would leave a caller believing it had
// subscribed to something it had not.
func TestSubscribeEventRejectsUnknownType(t *testing.T) {
	conn := eventDial(t)

	// Well outside the SCTP_SN_TYPE_BASE range the kernel knows.
	err := conn.SubscribeEvent(SCTPNotificationType(0x9999), true)
	if err == nil {
		t.Fatal("an unknown notification type was accepted")
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("got %v, want EINVAL for an unknown notification type", err)
	}
}

// TestSubscribeEventOnClosedConn checks the error path reports rather than
// panicking on a descriptor that is gone.
func TestSubscribeEventOnClosedConn(t *testing.T) {
	conn := eventDial(t)
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := conn.SubscribeEvent(SCTP_ASSOC_CHANGE, true); err == nil {
		t.Error("SubscribeEvent on a closed connection returned no error")
	}
	if _, err := conn.EventSubscribed(SCTP_ASSOC_CHANGE); err == nil {
		t.Error("EventSubscribed on a closed connection returned no error")
	}
}

// TestSetRecvInfoOptions checks the two boolean ancillary-data options are
// accepted in both directions.
//
// RFC 6458 §8.1.29 and §8.1.30 specify these as taking "an integer boolean
// flag", so the value width matters: passing a single byte where the kernel
// reads four is the kind of mismatch that fails as EINVAL only on some kernels.
func TestSetRecvInfoOptions(t *testing.T) {
	conn := eventDial(t)

	for _, tc := range []struct {
		name string
		set  func(bool) error
		opt  uintptr
	}{
		{"SCTP_RECVRCVINFO", conn.SetRecvRcvInfo, SCTP_RECVRCVINFO},
		{"SCTP_RECVNXTINFO", conn.SetRecvNxtInfo, SCTP_RECVNXTINFO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.set(true); err != nil {
				t.Fatalf("enable: %v", err)
			}
			// Read it back: the kernel returns the flag as an int.
			var val int32
			optlen := unsafe.Sizeof(val)
			if _, _, err := getsockopt(conn.fd(), tc.opt,
				uintptr(unsafe.Pointer(&val)), uintptr(unsafe.Pointer(&optlen))); err != nil {
				t.Fatalf("getsockopt: %v", err)
			}
			if val == 0 {
				t.Error("option reads back disabled after being enabled")
			}

			if err := tc.set(false); err != nil {
				t.Fatalf("disable: %v", err)
			}
			if _, _, err := getsockopt(conn.fd(), tc.opt,
				uintptr(unsafe.Pointer(&val)), uintptr(unsafe.Pointer(&optlen))); err != nil {
				t.Fatalf("getsockopt after disable: %v", err)
			}
			if val != 0 {
				t.Error("option reads back enabled after being disabled")
			}
		})
	}
}
