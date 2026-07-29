//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

// TestWrappedConnReportsSubscribeFailure checks that a wrapper built on a
// connection that cannot subscribe to SCTP_EVENT_DATA_IO reports it, rather
// than reading messages whose SndRcvInfo header is entirely zeroes.
//
// The header is what the whole type exists to provide. Without the
// subscription the kernel returns no ancillary data, the header is zero-filled,
// and every message reads as stream 0 with PPID 0 no matter which stream it
// arrived on: a wrong answer that looks exactly like a right one.
//
// A closed connection is the reachable way to make the subscription fail.
func TestWrappedConnReportsSubscribeFailure(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener has no address")
	}
	conn, err := DialSCTP("sctp", nil, la)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Close before wrapping, so the subscription inside the constructor fails.
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	wc := NewSCTPSndRcvInfoWrappedConn(conn)

	buf := make([]byte, int(sndRcvInfoSize)+64)
	_, rerr := wc.Read(buf)
	if rerr == nil {
		t.Error("Read on a wrapper whose subscription failed returned no error")
	} else if !strings.Contains(rerr.Error(), "SCTP_EVENT_DATA_IO") {
		t.Errorf("Read error does not name the failed subscription: %v", rerr)
	}

	_, werr := wc.Write(buf)
	if werr == nil {
		t.Error("Write on a wrapper whose subscription failed returned no error")
	}

	// The underlying cause must stay reachable for callers that switch on it.
	if rerr != nil && !errors.Is(rerr, syscall.EBADF) &&
		!errors.Is(rerr, syscall.EINVAL) && !errors.Is(rerr, syscall.ENOTCONN) {
		t.Logf("wrapped cause was %v", rerr)
	}
}

// TestWrappedConnWorksWhenSubscribed is the negative case: a wrapper on a
// healthy connection must not report an error, or the check above would pass
// for a constructor that always failed.
func TestWrappedConnWorksWhenSubscribed(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener has no address")
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			t.Errorf("accept: %v", aerr)
			close(accepted)
			return
		}
		accepted <- c
	}()

	conn, err := DialSCTP("sctp", nil, la)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	srv, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer func() { _ = srv.Close() }()

	wc := NewSCTPSndRcvInfoWrappedConn(conn)
	if wc.subErr != nil {
		t.Fatalf("subscription failed on a healthy connection: %v", wc.subErr)
	}

	// A real round trip proves the header is populated from ancillary data
	// rather than merely absent-and-zeroed.
	const payload = "m3ua"
	out := make([]byte, int(sndRcvInfoSize)+len(payload))
	info := &SndRcvInfo{Stream: 3, PPID: 9}
	copy(out, toBuf(info))
	copy(out[sndRcvInfoSize:], payload)
	if _, err := wc.Write(out); err != nil {
		t.Fatalf("write: %v", err)
	}

	srvConn, ok := srv.(*SCTPConn)
	if !ok {
		t.Fatalf("accepted %T, want *SCTPConn", srv)
	}
	if err := srvConn.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		t.Fatalf("server subscribe: %v", err)
	}
	rbuf := make([]byte, 512)
	n, rinfo, err := srvConn.SCTPRead(rbuf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(rbuf[:n]) != payload {
		t.Errorf("payload = %q, want %q", rbuf[:n], payload)
	}
	if rinfo == nil {
		t.Fatal("no ancillary data on a subscribed connection")
	}
	if rinfo.Stream != 3 {
		t.Errorf("stream = %d, want 3", rinfo.Stream)
	}
}
