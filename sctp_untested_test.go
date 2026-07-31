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
	"syscall"
	"testing"
	"unsafe"
)

// TestSubscribedEventsReportsEachFlagIndependently covers a hand-written
// decoder, not a thin wrapper.
//
// SubscribedEvents maps ten EventSubscribe fields onto ten flag bits, one `if`
// each. A transposed pair — Shutdown reported as PartialDelivery, say — is
// invisible to any test that subscribes to everything and checks the total, and
// it had no test at all. The tested sibling EventSubscribed is a different code
// path (SCTP_EVENT rather than SCTP_EVENTS), so it covers none of this.
//
// Each flag is subscribed alone and then read back alone, so a swap shows up as
// the wrong bit rather than the right total.
func TestSubscribedEventsReportsEachFlagIndependently(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag int
	}{
		{"SCTP_EVENT_DATA_IO", SCTP_EVENT_DATA_IO},
		{"SCTP_EVENT_ASSOCIATION", SCTP_EVENT_ASSOCIATION},
		{"SCTP_EVENT_ADDRESS", SCTP_EVENT_ADDRESS},
		{"SCTP_EVENT_SEND_FAILURE", SCTP_EVENT_SEND_FAILURE},
		{"SCTP_EVENT_PEER_ERROR", SCTP_EVENT_PEER_ERROR},
		{"SCTP_EVENT_SHUTDOWN", SCTP_EVENT_SHUTDOWN},
		{"SCTP_EVENT_PARTIAL_DELIVERY", SCTP_EVENT_PARTIAL_DELIVERY},
		{"SCTP_EVENT_ADAPTATION_LAYER", SCTP_EVENT_ADAPTATION_LAYER},
		{"SCTP_EVENT_AUTHENTICATION", SCTP_EVENT_AUTHENTICATION},
		{"SCTP_EVENT_SENDER_DRY", SCTP_EVENT_SENDER_DRY},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := unboundConn(t)

			if err := conn.SubscribeEvents(tc.flag); err != nil {
				t.Fatalf("SubscribeEvents(%s): %v", tc.name, err)
			}
			got, err := conn.SubscribedEvents()
			if err != nil {
				t.Fatalf("SubscribedEvents: %v", err)
			}
			if got != tc.flag {
				t.Errorf("subscribed %s (%#x) alone, read back %#x; a "+
					"transposed field in the decoder shows exactly like this",
					tc.name, tc.flag, got)
			}
		})
	}
}

// TestSubscribedEventsRoundTripsTheWholeSet checks the combined case too, since
// the per-flag test above would pass on a decoder that only ever returns the
// single bit it was given.
func TestSubscribedEventsRoundTripsTheWholeSet(t *testing.T) {
	conn := unboundConn(t)

	all := SCTP_EVENT_DATA_IO | SCTP_EVENT_ASSOCIATION | SCTP_EVENT_ADDRESS |
		SCTP_EVENT_SEND_FAILURE | SCTP_EVENT_PEER_ERROR | SCTP_EVENT_SHUTDOWN |
		SCTP_EVENT_PARTIAL_DELIVERY | SCTP_EVENT_ADAPTATION_LAYER |
		SCTP_EVENT_AUTHENTICATION | SCTP_EVENT_SENDER_DRY

	if err := conn.SubscribeEvents(all); err != nil {
		t.Fatalf("SubscribeEvents(all): %v", err)
	}
	got, err := conn.SubscribedEvents()
	if err != nil {
		t.Fatalf("SubscribedEvents: %v", err)
	}
	if got != all {
		t.Errorf("subscribed %#x, read back %#x (missing %#x)", all, got, all&^got)
	}

	if err := conn.SubscribeEvents(0); err != nil {
		t.Fatalf("SubscribeEvents(0): %v", err)
	}
	if got, err = conn.SubscribedEvents(); err != nil {
		t.Fatalf("SubscribedEvents: %v", err)
	}
	if got != 0 {
		t.Errorf("read back %#x after unsubscribing everything", got)
	}
}

// TestSackTimerLayoutAndRoundTrip covers the one struct that was both
// functionally untested and absent from the layout assertions.
func TestSackTimerLayoutAndRoundTrip(t *testing.T) {
	var st SackTimer
	if got := unsafe.Sizeof(st); got != 12 {
		t.Errorf("sizeof(SackTimer) = %d, kernel's sctp_sack_info is 12", got)
	}
	if got := unsafe.Offsetof(st.SackDelay); got != 4 {
		t.Errorf("SackDelay at offset %d, want 4", got)
	}
	if got := unsafe.Offsetof(st.SackFrequency); got != 8 {
		t.Errorf("SackFrequency at offset %d, want 8", got)
	}

	client, _ := eorPair(t)

	before, err := client.GetSackTimer()
	if err != nil {
		t.Fatalf("GetSackTimer: %v", err)
	}
	if before.SackDelay == 0 {
		t.Errorf("SackDelay = 0; the kernel's default is 200ms, so the field "+
			"is being read from the wrong offset (%+v)", before)
	}

	want := SackTimer{SackDelay: 123, SackFrequency: 4}
	if err := client.SetSackTimer(&want); err != nil {
		t.Fatalf("SetSackTimer: %v", err)
	}
	after, err := client.GetSackTimer()
	if err != nil {
		t.Fatalf("GetSackTimer after set: %v", err)
	}
	if after.SackDelay != want.SackDelay || after.SackFrequency != want.SackFrequency {
		t.Errorf("read back %+v, want delay=%d freq=%d",
			after, want.SackDelay, want.SackFrequency)
	}
}

// TestNoDelayRoundTrips covers SCTP_NODELAY, which had no test despite being
// the option most callers reach for first.
func TestNoDelayRoundTrips(t *testing.T) {
	client, _ := eorPair(t)

	for _, want := range []int{1, 0} {
		if err := client.SetNoDelay(want); err != nil {
			t.Fatalf("SetNoDelay(%d): %v", want, err)
		}
		got, err := client.GetNoDelay()
		if err != nil {
			t.Fatalf("GetNoDelay: %v", err)
		}
		if got != want {
			t.Errorf("GetNoDelay = %d after setting %d", got, want)
		}
	}
}

// TestDefaultSentParamRoundTrips covers the deprecated-but-default send
// parameters. SCTP_DEFAULT_SEND_PARAM is what SCTPWrite uses when the caller
// passes no info, so a wrong layout here changes every such write.
func TestDefaultSentParamRoundTrips(t *testing.T) {
	client, _ := eorPair(t)

	want := &SndRcvInfo{Stream: 3, PPID: 0x11223344, Context: 0x55667788}
	if err := client.SetDefaultSentParam(want); err != nil {
		t.Fatalf("SetDefaultSentParam: %v", err)
	}
	got, err := client.GetDefaultSentParam()
	if err != nil {
		t.Fatalf("GetDefaultSentParam: %v", err)
	}
	if got.Stream != want.Stream || got.PPID != want.PPID || got.Context != want.Context {
		t.Errorf("read back stream=%d ppid=%#x context=%#x, want %d %#x %#x",
			got.Stream, got.PPID, got.Context,
			want.Stream, want.PPID, want.Context)
	}
}

// TestSCTPBindRemoveAndInvalidFlags covers the two arms of SCTPBind that the
// suite never reached: only SCTP_BINDX_ADD_ADDR ran, so neither removal nor the
// guard on an unknown flag had ever executed.
func TestSCTPBindRemoveAndInvalidFlags(t *testing.T) {
	extra := availableLoopbacks(t)
	if len(extra) < 2 {
		t.Skip("removing an address needs a socket bound to at least two")
	}

	fd, err := syscall.Socket(syscall.AF_INET,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("cannot create an SCTP socket: %v", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	both := &SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.ParseIP(extra[0])}, {IP: net.ParseIP(extra[1])}},
		Port:    0,
	}
	if err := SCTPBind(fd, both, SCTP_BINDX_ADD_ADDR); err != nil {
		t.Fatalf("bind two addresses: %v", err)
	}

	second := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP(extra[1])}}}
	if err := SCTPBind(fd, second, SCTP_BINDX_REM_ADDR); err != nil {
		t.Errorf("SCTP_BINDX_REM_ADDR: %v", err)
	}

	// An unknown flag must be refused here rather than passed to the kernel as
	// some other option number.
	err = SCTPBind(fd, second, 0x7f)
	if err == nil {
		t.Error("SCTPBind accepted an unknown flag")
	} else if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("SCTPBind with an unknown flag = %v, want EINVAL", err)
	}
}

// TestToRawSockAddrBufEncodesEachFamily asserts the bytes rather than the
// struct, for the encoder every bind and connect goes through.
//
// Its mainline is covered indirectly by every socket test, but the fallback
// arms are not: breaking them survives a suite that only ever uses one
// loopback address.
func TestToRawSockAddrBufEncodesEachFamily(t *testing.T) {
	t.Run("empty address list falls back to IPv4 zero", func(t *testing.T) {
		addr := &SCTPAddr{Port: 0x1234}
		buf := addr.ToRawSockAddrBuf()
		if len(buf) != int(unsafe.Sizeof(syscall.RawSockaddrInet4{})) {
			t.Fatalf("encoded %d bytes, want a sockaddr_in", len(buf))
		}
		if fam := nativeEndian.Uint16(buf[0:2]); fam != syscall.AF_INET {
			t.Errorf("family = %d, want AF_INET (%d)", fam, syscall.AF_INET)
		}
		// The port is network order on the wire regardless of the host.
		if port := uint16(buf[2])<<8 | uint16(buf[3]); port != 0x1234 {
			t.Errorf("port encoded as %#x, want %#x", port, 0x1234)
		}
	})

	t.Run("v4 and v6 round trip through the decoder", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			ips  []string
		}{
			{"one v4", []string{"127.0.0.1"}},
			{"two v4", []string{"127.0.0.1", "127.0.0.2"}},
			{"one v6", []string{"::1"}},
			{"mixed", []string{"127.0.0.1", "::1"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				addr := &SCTPAddr{Port: 9999}
				for _, s := range tc.ips {
					addr.IPAddrs = append(addr.IPAddrs, net.IPAddr{IP: net.ParseIP(s)})
				}
				buf := addr.ToRawSockAddrBuf()
				back, err := resolveFromRawAddrBuf(unsafe.Pointer(&buf[0]),
					len(tc.ips), uintptr(len(buf)))
				if err != nil {
					t.Fatalf("decode: %v", err)
				}
				if back.Port != addr.Port {
					t.Errorf("port %d survived as %d", addr.Port, back.Port)
				}
				if len(back.IPAddrs) != len(tc.ips) {
					t.Fatalf("encoded %d addresses, decoded %d",
						len(tc.ips), len(back.IPAddrs))
				}
				for i, want := range tc.ips {
					if got := back.IPAddrs[i].IP.String(); got != net.ParseIP(want).String() {
						t.Errorf("address %d: encoded %s, decoded %s", i, want, got)
					}
				}
			})
		}
	})
}

// TestLocalAndRemoteAddrReportTheAssociation covers the two net.Conn accessors,
// which had no test despite being what a caller logs.
func TestLocalAndRemoteAddrReportTheAssociation(t *testing.T) {
	client, server := eorPair(t)

	local := client.LocalAddr()
	remote := client.RemoteAddr()
	if local == nil || remote == nil {
		t.Fatalf("LocalAddr = %v, RemoteAddr = %v; neither should be nil on an "+
			"established association", local, remote)
	}
	if local.Network() != "sctp" {
		t.Errorf("LocalAddr().Network() = %q, want \"sctp\"", local.Network())
	}

	// The client's remote address is the server's local one.
	serverLocal := server.LocalAddr()
	if serverLocal == nil {
		t.Fatal("server LocalAddr is nil")
	}
	clientRemote, ok := remote.(*SCTPAddr)
	if !ok {
		t.Fatalf("RemoteAddr is %T, want *SCTPAddr", remote)
	}
	if clientRemote.Port != serverLocal.(*SCTPAddr).Port {
		t.Errorf("client's remote port %d does not match the server's local "+
			"port %d", clientRemote.Port, serverLocal.(*SCTPAddr).Port)
	}
}

// TestGetReadBufferReportsTheBuffer covers the getter half of SO_RCVBUF, which
// had no test while the setter did.
func TestGetReadBufferReportsTheBuffer(t *testing.T) {
	client, _ := eorPair(t)

	before, err := client.GetReadBuffer()
	if err != nil {
		t.Fatalf("GetReadBuffer: %v", err)
	}
	if before <= 0 {
		t.Fatalf("GetReadBuffer = %d on a live association", before)
	}

	// The kernel doubles what it is given and clamps to net.core.rmem_max, so
	// the assertion is that the value moved, not that it took a exact size.
	if err := client.SetReadBuffer(before * 2); err != nil {
		t.Fatalf("SetReadBuffer: %v", err)
	}
	after, err := client.GetReadBuffer()
	if err != nil {
		t.Fatalf("GetReadBuffer after set: %v", err)
	}
	if after <= before {
		t.Errorf("read buffer %d -> %d after asking for %d; the getter is not "+
			"reporting the socket's value", before, after, before*2)
	}
}
