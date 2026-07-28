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
	"bytes"
	"errors"
	"io"
	"sync/atomic"
	"syscall"
	"testing"
)

// TestReadMsgWithNotificationsSubscribed exercises the path that matters in
// production: the reader is subscribed to association events, so the
// SCTPReadFlags retry loop can be entered by a notification arriving while a
// message is being reassembled. Reassembly must still produce whole messages.
func TestReadMsgWithNotificationsSubscribed(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	var notifications int32
	handler := func([]byte) error {
		atomic.AddInt32(&notifications, 1)
		return nil
	}

	type accepted struct {
		conn *SCTPConn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.AcceptSCTP()
		if c != nil {
			c.notificationHandler = handler
			// Subscribe to everything, so events interleave with data.
			_ = c.SubscribeEvents(SCTP_EVENT_DATA_IO | SCTP_EVENT_ASSOCIATION |
				SCTP_EVENT_ADDRESS | SCTP_EVENT_SHUTDOWN |
				SCTP_EVENT_PARTIAL_DELIVERY)
		}
		ch <- accepted{c, err}
	}()

	client, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Closed explicitly at the end of the test to raise a SHUTDOWN event; the
	// cleanup only covers early failure paths.
	closed := false
	defer func() {
		if !closed {
			_ = client.Close()
		}
	}()

	a := <-ch
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	server := a.conn
	defer func() { _ = server.Close() }()

	// Sizes that span the reassembly loop, sent back to back so events and
	// data compete on the same socket.
	sizes := []int{1, 2048, 4096, 20000, 60000}
	for _, size := range sizes {
		msg := fill(size)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Fatalf("write %d: %v", size, err)
		}

		got, _, err := server.ReadMsg(1 << 20)
		if err != nil {
			t.Fatalf("ReadMsg %d: %v", size, err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("size %d: reassembled %d bytes and they do not match",
				size, len(got))
		}
	}

	// A stable loopback association raises no address or error events, so the
	// data phase above may well see none. Close the peer to force a real
	// SHUTDOWN notification and confirm the handler is actually wired up and
	// that the retry loop in SCTPReadFlags is exercised at least once.
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	closed = true
	buf := make([]byte, 4096)
	for i := 0; i < 16; i++ {
		if _, _, err := server.SCTPRead(buf); err != nil {
			break
		}
	}
	if got := atomic.LoadInt32(&notifications); got == 0 {
		t.Error("no notification was ever delivered; the interleaving path in " +
			"SCTPReadFlags was never exercised, so this test proves nothing")
	} else {
		t.Logf("notifications delivered: %d", got)
	}
}

// TestReadMsgPeerAbortMidMessage checks that an association aborted while a
// message is in flight surfaces an error instead of hanging or returning a
// silently short message as if it were complete.
func TestReadMsgPeerAbortMidMessage(t *testing.T) {
	client, server := eorPair(t)

	// Queue a large message, then abort without a graceful shutdown.
	msg := fill(200000)
	if _, err := client.SCTPWrite(msg, nil); err != nil {
		t.Skipf("write did not fit the send buffer: %v", err)
	}
	if err := client.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}

	got, _, err := server.ReadMsg(1 << 20)

	// Either the whole message beat the ABORT to the receiver, or the read
	// fails. What must not happen is a short read reported as success.
	if err == nil {
		if !bytes.Equal(got, msg) {
			t.Errorf("ReadMsg reported success with %d of %d bytes",
				len(got), len(msg))
		}
		return
	}
	t.Logf("aborted association surfaced: %v (%d bytes buffered)", err, len(got))
}

// TestReadMsgAfterPeerClose verifies a clean shutdown terminates ReadMsg
// rather than leaving it blocked.
func TestReadMsgAfterPeerClose(t *testing.T) {
	client, server := eorPair(t)

	want := []byte("final message")
	if _, err := client.SCTPWrite(want, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, _, err := server.ReadMsg(4096)
	if err != nil {
		t.Fatalf("ReadMsg before EOF: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}

	// The next read must report the shutdown, not block.
	_, _, err = server.ReadMsg(4096)
	if err == nil {
		t.Fatal("ReadMsg after peer close returned nil error, want EOF or a socket error")
	}
	if !errors.Is(err, io.EOF) {
		t.Logf("peer close surfaced as %v (not io.EOF, acceptable)", err)
	}
}

// TestReadMsgOnClosedConn ensures ReadMsg on a closed descriptor returns an
// error rather than reading from a recycled fd.
func TestReadMsgOnClosedConn(t *testing.T) {
	client, server := eorPair(t)
	_ = client

	if err := server.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, _, err := server.ReadMsg(4096)
	if err == nil {
		t.Fatal("ReadMsg on a closed conn returned nil error")
	}
	if !errors.Is(err, syscall.EBADF) && !errors.Is(err, io.EOF) {
		t.Logf("closed conn surfaced as %v", err)
	}
}
