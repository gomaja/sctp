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
	"sync"
	"testing"
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
