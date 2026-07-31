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
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestParseNotificationAgainstKernel parses notifications the kernel actually
// emitted, rather than buffers this test built. Synthetic input proves the
// parser is self-consistent; only real bytes prove it agrees with the kernel
// about where the fields are.
func TestParseNotificationAgainstKernel(t *testing.T) {
	var (
		mu  sync.Mutex
		raw [][]byte
	)
	cfg := &SocketConfig{
		NotificationHandler: func(b []byte) error {
			mu.Lock()
			raw = append(raw, append([]byte(nil), b...))
			mu.Unlock()
			return nil
		},
	}

	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := cfg.Listen("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type accepted struct {
		conn *SCTPConn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		c, err := ln.AcceptSCTP()
		accCh <- accepted{c, err}
	}()

	client, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("accept: %v", acc.err)
	}
	server := acc.conn

	// Ask for the events whose notifications this parser models.
	if err := server.SubscribeEvents(SCTP_EVENT_ASSOCIATION | SCTP_EVENT_SHUTDOWN); err != nil {
		t.Fatalf("SubscribeEvents: %v", err)
	}

	// A graceful close from the peer produces a real SHUTDOWN_EVENT, and the
	// association teardown produces a real ASSOC_CHANGE.
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	buf := make([]byte, NotificationMaxSize)
	for i := 0; i < 16; i++ {
		if _, _, err := server.SCTPRead(buf); err != nil {
			break
		}
	}
	_ = server.Abort()

	mu.Lock()
	captured := raw
	mu.Unlock()

	if len(captured) == 0 {
		t.Skip("kernel delivered no notification; nothing to verify against")
	}

	seen := map[SCTPNotificationType]bool{}
	for i, b := range captured {
		n, err := ParseNotification(b)
		if err != nil {
			t.Errorf("notification %d (%d bytes): ParseNotification: %v", i, len(b), err)
			continue
		}
		if n == nil {
			t.Logf("notification %d: type %d not modelled", i,
				nativeEndian.Uint16(b[0:2]))
			continue
		}
		seen[n.Type()] = true

		// The kernel's declared length must match what it actually sent. A
		// mismatch means the struct this parser expects is the wrong size.
		if int(n.Length()) != len(b) {
			t.Errorf("notification %d: header declares %d bytes, kernel sent %d",
				i, n.Length(), len(b))
		}

		switch v := n.(type) {
		case *AssocChange:
			t.Logf("ASSOC_CHANGE state=%v error=%d in=%d out=%d assoc=%d",
				v.State, v.Error, v.InboundStreams, v.OutboundStreams, v.AssocID)
			// A real association always negotiates at least one stream in
			// each direction, so zero here means the offsets are wrong.
			if v.State == SCTP_COMM_UP && (v.InboundStreams == 0 || v.OutboundStreams == 0) {
				t.Errorf("COMM_UP reported %d inbound / %d outbound streams; "+
					"the field offsets are wrong", v.InboundStreams, v.OutboundStreams)
			}
		case *Shutdown:
			t.Logf("SHUTDOWN assoc=%d", v.AssocID)
		default:
			t.Logf("notification %d: %T", i, v)
		}
	}
	t.Logf("parsed %d kernel notifications, types seen: %v", len(captured), seen)
}

// TestKernelTruncatesNotificationToReadBuffer establishes that the length
// checks in ParseNotification guard a reachable case rather than a theoretical
// one.
//
// The kernel truncates a notification to the caller's read buffer and drops
// the remainder. With a 16 byte buffer it delivers a 16 byte
// SCTP_ASSOC_CHANGE, four bytes short of the 20 byte event. A parser that
// reads its fields without checking the length walks off the end of that
// buffer and panics inside the read path.
func TestKernelTruncatesNotificationToReadBuffer(t *testing.T) {
	var (
		mu    sync.Mutex
		sizes []int
		bad   []error
	)
	cfg := &SocketConfig{
		NotificationHandler: func(b []byte) error {
			mu.Lock()
			sizes = append(sizes, len(b))
			// Parsing must report truncation, not panic and not invent a value.
			if _, err := ParseNotification(b); err != nil && !errors.Is(err, ErrShortNotification) {
				bad = append(bad, err)
			}
			mu.Unlock()
			return nil
		},
	}

	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := cfg.Listen("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accCh := make(chan *SCTPConn, 1)
	go func() {
		c, _ := ln.AcceptSCTP()
		accCh <- c
	}()

	client, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server := <-accCh
	if server == nil {
		t.Fatal("accept returned no connection")
	}
	if err := server.SubscribeEvents(SCTP_EVENT_ASSOCIATION | SCTP_EVENT_SHUTDOWN); err != nil {
		t.Fatalf("SubscribeEvents: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	// Deliberately smaller than sctp_assoc_change.
	buf := make([]byte, 16)
	for i := 0; i < 8; i++ {
		if _, _, err := server.SCTPRead(buf); err != nil {
			break
		}
	}
	_ = server.Abort()

	mu.Lock()
	got := append([]int(nil), sizes...)
	errs := append([]error(nil), bad...)
	mu.Unlock()

	for _, err := range errs {
		t.Errorf("ParseNotification on a truncated notification = %v, "+
			"want nil or ErrShortNotification", err)
	}

	if len(got) == 0 {
		t.Skip("kernel delivered no notification; nothing to verify")
	}
	t.Logf("notification sizes delivered into a 16 byte buffer: %v", got)

	// At least one must come back short of the 20 byte assoc change, or this
	// test is not actually exercising the truncation it claims to.
	short := false
	for _, n := range got {
		if n > 16 {
			t.Errorf("kernel delivered %d bytes into a 16 byte buffer", n)
		}
		if n < assocChangeMinSize {
			short = true
		}
	}
	if !short {
		t.Errorf("no notification came back shorter than %d bytes, so the "+
			"truncation path was never exercised: sizes were %v",
			assocChangeMinSize, got)
	}
}

// TestSendFailedEventExceedsNotificationMaxSize makes the sizing note on
// NotificationMaxSize falsifiable.
//
// The constant is documented as a buffer that holds any *fixed-size*
// notification, with the send-failed events explicitly outside it. Nothing
// asserted that, so the caveat could have been wrong in either direction — the
// kernel could equally have capped the tail at something under 1024 and made
// the whole warning unnecessary.
//
// Measured: the payload is capped at 65484 bytes per notification, so a message
// longer than that comes back as several complete events. This asserts only the
// part a caller depends on, that one event exceeds NotificationMaxSize, because
// the exact cap is a kernel detail while the "your buffer is not big enough"
// consequence is the contract.
func TestSendFailedEventExceedsNotificationMaxSize(t *testing.T) {
	client, server := eorPair(t)

	if err := client.SubscribeEvent(SCTP_SEND_FAILED_EVENT, true); err != nil {
		t.Fatalf("SubscribeEvent(SCTP_SEND_FAILED_EVENT): %v", err)
	}

	// The messages have to be still queued when the association dies, so the
	// receive window is closed down and the send buffer left large enough to
	// hold several. The other way round — a small send buffer — makes the first
	// write block instead of queueing, and nothing fails.
	setBuf := func(c *SCTPConn, opt, size int) {
		t.Helper()
		rc, err := c.SyscallConn()
		if err != nil {
			t.Fatalf("SyscallConn: %v", err)
		}
		if err := rc.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, opt, size)
		}); err != nil {
			t.Fatalf("setsockopt: %v", err)
		}
	}
	setBuf(client, syscall.SO_SNDBUF, 512*1024)
	setBuf(server, syscall.SO_RCVBUF, 8*1024)

	// Comfortably over the 65484-byte cap, so at least one event carries a full
	// tail rather than a remainder that might fit in NotificationMaxSize.
	payload := make([]byte, 200*1024)
	queued := 0
	for i := 0; i < 8; i++ {
		if err := client.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		if _, err := client.Write(payload); err != nil {
			break
		}
		queued++
	}
	if queued == 0 {
		t.Skipf("nothing could be queued, so nothing can fail")
	}
	t.Logf("queued %d messages of %d bytes with the peer not reading",
		queued, len(payload))

	// Abort from the peer, which fails everything still queued.
	if err := server.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}

	buf := make([]byte, 512*1024)
	// Counted so the two ways of finding nothing can be told apart: no events at
	// all is the environment refusing to cooperate, while events that all fit
	// inside the constant means the constant has stopped being a warning about
	// anything. Without this the second case ends in a skip, and a skip is how a
	// broken assertion looks like a passing one.
	seen := 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := client.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, _, flags, err := client.SCTPReadFlags(buf)
		if err != nil {
			continue
		}
		if flags&MSG_NOTIFICATION == 0 {
			continue
		}
		if nativeEndian.Uint16(buf[0:2]) != uint16(SCTP_SEND_FAILED_EVENT) {
			continue
		}
		seen++
		if n <= NotificationMaxSize {
			// Later events carry the remainder and are legitimately small; keep
			// looking for the one that carries a full tail.
			continue
		}
		if flags&MSG_EOR == 0 {
			t.Errorf("a %d byte notification arrived without MSG_EOR from a "+
				"%d byte buffer; the kernel divides a long message into "+
				"complete events, so this should not be truncation", n, len(buf))
		}
		note, err := ParseNotification(buf[:n])
		if err != nil {
			t.Fatalf("ParseNotification of a %d byte event: %v", n, err)
		}
		sf, ok := note.(*SendFailedEvent)
		if !ok {
			t.Fatalf("got %T, want *SendFailedEvent", note)
		}
		if len(sf.Data) == 0 {
			t.Errorf("a %d byte event decoded with no undelivered data; the "+
				"tail is the whole reason these events outgrow the constant", n)
		}
		t.Logf("SCTP_SEND_FAILED_EVENT of %d bytes carrying %d bytes of "+
			"undelivered data; NotificationMaxSize is %d",
			n, len(sf.Data), NotificationMaxSize)
		return
	}
	if seen > 0 {
		t.Fatalf("%d SCTP_SEND_FAILED_EVENTs arrived and every one fitted "+
			"inside NotificationMaxSize (%d); the constant is documented as "+
			"not bounding these events, and a buffer of that size would now "+
			"be enough for them", seen, NotificationMaxSize)
	}
	t.Skip("no SCTP_SEND_FAILED_EVENT arrived at all; the messages were " +
		"transmitted before the abort rather than left queued")
}
