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
	"time"
	"unsafe"
)

// TestNxtInfoLayoutMatchesKernel pins struct sctp_nxtinfo.
func TestNxtInfoLayoutMatchesKernel(t *testing.T) {
	var n NxtInfo
	if got := unsafe.Sizeof(n); got != 16 {
		t.Errorf("sizeof(NxtInfo) = %d, kernel's sctp_nxtinfo is 16", got)
	}
	for _, tc := range []struct {
		field string
		got   uintptr
		want  uintptr
	}{
		{"nxt_sid", unsafe.Offsetof(n.SID), 0},
		{"nxt_flags", unsafe.Offsetof(n.Flags), 2},
		{"nxt_ppid", unsafe.Offsetof(n.PPID), 4},
		{"nxt_length", unsafe.Offsetof(n.Length), 8},
		{"nxt_assoc_id", unsafe.Offsetof(n.AssocID), 12},
	} {
		if tc.got != tc.want {
			t.Errorf("%s at offset %d, kernel has it at %d", tc.field, tc.got, tc.want)
		}
	}
}

// TestSCTPReadNextInfoReportsTheQueuedMessage covers the option that was
// enableable but discarded.
//
// SetRecvNxtInfo asked the kernel for SCTP_NXTINFO and the kernel sent it;
// parseSndRcvInfo switched on two cmsg types and dropped this one, and no
// NxtInfo type existed. A caller sizing the next buffer got nothing, with no
// error to distinguish "the kernel sent none" from "the package threw it away".
// It is the same defect that was already found and fixed once for SCTP_RCVINFO.
func TestSCTPReadNextInfoReportsTheQueuedMessage(t *testing.T) {
	client, server := eorPair(t)

	if err := client.SetRecvNxtInfo(true); err != nil {
		t.Fatalf("SetRecvNxtInfo: %v", err)
	}
	// SndRcvInfo only arrives when the data-io event is subscribed, and the
	// comparison below needs it.
	if err := client.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		t.Fatalf("SubscribeEvents: %v", err)
	}

	// Two messages of different sizes, so Length cannot be right by accident.
	first := make([]byte, 100)
	second := make([]byte, 250)
	for i := range second {
		second[i] = byte(i)
	}
	const nextPPID = 0x11223344

	if _, err := server.SCTPWrite(first, &SndRcvInfo{Stream: 0}); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if _, err := server.SCTPWrite(second,
		&SndRcvInfo{Stream: 1, PPID: htonl(nextPPID)}); err != nil {
		t.Fatalf("write second: %v", err)
	}

	// Give the second message time to queue behind the first; without it the
	// kernel has nothing to report and the test would pass vacuously.
	time.Sleep(200 * time.Millisecond)

	buf := make([]byte, 4096)
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	n, _, nxt, _, err := client.SCTPReadNextInfo(buf)
	if err != nil {
		t.Fatalf("SCTPReadNextInfo: %v", err)
	}
	if n != len(first) {
		t.Fatalf("read %d bytes, want the first message's %d", n, len(first))
	}
	if nxt == nil {
		t.Fatal("NxtInfo is nil with a second message queued; the kernel sends " +
			"SCTP_NXTINFO here and it is being discarded")
	}
	if nxt.Length != uint32(len(second)) {
		t.Errorf("next Length = %d, want %d — this is the field the option "+
			"exists for", nxt.Length, len(second))
	}
	if nxt.SID != 1 {
		t.Errorf("next SID = %d, want 1", nxt.SID)
	}
	predicted := *nxt

	// Now read the message that was predicted, and check the prediction
	// against what the ordinary read path reports for it.
	//
	// Asserting PPID against the literal that was written would be asserting
	// this package's write-side convention rather than this method: SCTPWrite
	// takes PPID already converted while the read paths convert again, so the
	// two are deliberately not an identity round trip. What has to hold is that
	// SCTPReadNextInfo describes the next message the same way SCTPRead
	// describes it when it arrives — otherwise a caller cannot act on the
	// prediction.
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	n, info, nxt, _, err := client.SCTPReadNextInfo(buf)
	if err != nil {
		t.Fatalf("second SCTPReadNextInfo: %v", err)
	}
	if n != len(second) {
		t.Errorf("second message is %d bytes; NxtInfo predicted %d",
			n, predicted.Length)
	}
	if info == nil {
		t.Fatal("no SndRcvInfo for the second message")
	}
	if info.PPID != predicted.PPID {
		t.Errorf("NxtInfo predicted PPID %#x, SCTPRead reports %#x for the "+
			"same message; the two read paths must agree or the prediction "+
			"cannot be used", predicted.PPID, info.PPID)
	}
	if info.Stream != predicted.SID {
		t.Errorf("NxtInfo predicted stream %d, SCTPRead reports %d",
			predicted.SID, info.Stream)
	}

	// Draining the queue must leave nothing to report rather than repeating
	// what the previous read said.
	if nxt != nil {
		t.Errorf("NxtInfo = %+v after the last message; an empty queue means "+
			"no ancillary data, which is a nil NxtInfo rather than a stale one", nxt)
	}
}

// TestSCTPReadNextInfoIsNilWithoutTheOption checks the other direction: nothing
// is invented when the option was never enabled.
func TestSCTPReadNextInfoIsNilWithoutTheOption(t *testing.T) {
	client, server := eorPair(t)

	if _, err := server.SCTPWrite([]byte("a"), nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := server.SCTPWrite([]byte("b"), nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, _, nxt, _, err := client.SCTPReadNextInfo(make([]byte, 64))
	if err != nil {
		t.Fatalf("SCTPReadNextInfo: %v", err)
	}
	if nxt != nil {
		t.Errorf("NxtInfo = %+v without SetRecvNxtInfo; nothing should be "+
			"reported that the kernel did not send", nxt)
	}
}

// TestSetPrimaryPeerAddrSelectsThePath covers the setter half of
// SCTP_PRIMARY_ADDR, which had only its getter.
//
// Choosing the primary is the point of multi-homing: it decides where data goes
// while every path is usable. An application could see which path was primary
// and not say which one should be.
func TestSetPrimaryPeerAddrSelectsThePath(t *testing.T) {
	avail := requireLoopbacks(t, 3)
	serverIPs := avail[:2]

	ln, err := ListenSCTP("sctp", sctpAddr(serverIPs, 0))
	if err != nil {
		t.Fatalf("multihomed listen on %v: %v", serverIPs, err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if c, aerr := ln.AcceptSCTP(); aerr == nil {
			<-time.After(5 * time.Second)
			_ = c.Close()
		}
	}()

	client, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	primary, err := client.SCTPGetPrimaryPeerAddr()
	if err != nil {
		t.Fatalf("SCTPGetPrimaryPeerAddr: %v", err)
	}
	if len(primary.IPAddrs) == 0 {
		t.Fatal("no primary reported")
	}
	before := primary.IPAddrs[0].IP.String()

	remote, ok := client.RemoteAddr().(*SCTPAddr)
	if !ok {
		t.Fatal("RemoteAddr is not an *SCTPAddr")
	}
	var other *SCTPAddr
	for _, ip := range remote.IPAddrs {
		if ip.IP.String() != before {
			other = &SCTPAddr{IPAddrs: []net.IPAddr{ip}, Port: remote.Port}
			break
		}
	}
	if other == nil {
		t.Skipf("peer announced only %s; nothing to switch to", before)
	}

	if err := client.SetPrimaryPeerAddr(other); err != nil {
		t.Fatalf("SetPrimaryPeerAddr(%v): %v", other.IPAddrs[0].IP, err)
	}

	now, err := client.SCTPGetPrimaryPeerAddr()
	if err != nil {
		t.Fatalf("SCTPGetPrimaryPeerAddr after set: %v", err)
	}
	if got := now.IPAddrs[0].IP.String(); got != other.IPAddrs[0].IP.String() {
		t.Errorf("primary is %s after asking for %s (was %s)",
			got, other.IPAddrs[0].IP, before)
	}
}

// TestSetPeerPrimaryAddrNeedsAsconf records what the other direction does
// without RFC 5061 negotiated.
//
// SCTP_SET_PEER_PRIMARY_ADDR travels as an ASCONF parameter, and
// net.sctp.addip_enable defaults to 0, so this is EPERM on a stock kernel — not
// EOPNOTSUPP, and not a bad address. Asserting it keeps the doc comment honest
// about which of the two primary-address calls needs an extension.
func TestSetPeerPrimaryAddrNeedsAsconf(t *testing.T) {
	client, _ := eorPair(t)

	local, err := client.SCTPLocalAddr(0)
	if err != nil {
		t.Fatalf("SCTPLocalAddr: %v", err)
	}
	// One address, not the whole set. The dialer binds the wildcard, so
	// SCTPLocalAddr returns every address the host has — and the option names a
	// single path, so passing all of them is rejected. This test used to do
	// exactly that and reach the kernel anyway, because only the first sockaddr
	// was ever read.
	if len(local.IPAddrs) == 0 {
		t.Fatal("no local addresses")
	}
	one := &SCTPAddr{IPAddrs: local.IPAddrs[:1], Port: local.Port}

	err = client.SetPeerPrimaryAddr(one)
	if err == nil {
		// Fine if the host has addip_enable on; the call is then meaningful.
		t.Log("SetPeerPrimaryAddr succeeded; net.sctp.addip_enable is on here")
		return
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Errorf("SetPeerPrimaryAddr = %v, want EPERM on a kernel with "+
			"net.sctp.addip_enable at its default", err)
	}
}

// TestPeelOffSucceedsOnAOneToManySocket exercises the path the ABI fix was for.
//
// Until now only two things were asserted: the struct's shape, and that a
// one-to-one socket is refused. Neither runs the code that reads the descriptor
// back out of the reply — which is exactly where the original defect was, so
// reverting the fix left the suite green.
func TestPeelOffSucceedsOnAOneToManySocket(t *testing.T) {
	// A one-to-many socket is the only kind the kernel will peel from.
	m2m, err := syscall.Socket(syscall.AF_INET,
		syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("cannot create a one-to-many SCTP socket: %v", err)
	}
	defer func() { _ = syscall.Close(m2m) }()

	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], []byte{127, 0, 0, 1})
	if err := syscall.Bind(m2m, sa); err != nil {
		t.Skipf("bind: %v", err)
	}
	if err := syscall.Listen(m2m, 1); err != nil {
		t.Skipf("listen: %v", err)
	}
	bound, err := syscall.Getsockname(m2m)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	port := bound.(*syscall.SockaddrInet4).Port

	client, err := DialSCTP("sctp", nil, mustResolve(t, "127.0.0.1:"+itoa(port)))
	if err != nil {
		t.Skipf("dial the one-to-many socket: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Read once so the association is established and has an id to peel.
	server := NewSCTPConn(m2m, nil)
	// Without the data-io subscription the read reports no SndRcvInfo, so
	// there is no association id to peel and the test skips itself.
	if err := server.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		t.Skipf("SubscribeEvents on the one-to-many socket: %v", err)
	}
	if _, err := client.SCTPWrite([]byte("x"), nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	if err := server.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, info, err := server.SCTPRead(buf)
	if err != nil {
		t.Skipf("no message arrived on the one-to-many socket: %v", err)
	}
	if info == nil || info.AssocID == 0 {
		t.Skip("no association id reported; nothing to peel")
	}

	peeled, err := server.PeelOff(int(info.AssocID))
	if err != nil {
		t.Fatalf("PeelOff(%d): %v", info.AssocID, err)
	}
	defer func() { _ = peeled.Close() }()

	// The whole original defect: the descriptor was read from the wrong offset
	// and came back as 0, the process's standard input.
	if fd := peeled.fd(); fd <= 2 {
		t.Fatalf("PeelOff returned descriptor %d; anything at or below 2 is a "+
			"standard stream, which is what the wrong struct offset produced", fd)
	}
	// And it must be close-on-exec, like every other descriptor here.
	if !isCloseOnExec(t, peeled.fd()) {
		t.Error("the peeled descriptor is not close-on-exec; a forked child " +
			"inherits the association it was split off for")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// reconfPair builds an association with RFC 6525 stream reconfiguration
// negotiated on both sides, or skips.
//
// net.sctp.reconf_enable defaults to 0, and the capability is announced in the
// INIT, so both endpoints have to ask for it before they bind. SocketConfig's
// Control hook is the only way to reach the descriptor at that point.
func reconfPair(t *testing.T) (client, server *SCTPConn) {
	t.Helper()

	enable := func(network, address string, c syscall.RawConn) error {
		var seterr error
		if err := c.Control(func(fd uintptr) {
			seterr = setAssocValueBool(int(fd), SCTP_RECONFIG_SUPPORTED, true)
		}); err != nil {
			return err
		}
		return seterr
	}

	cfg := &SocketConfig{Control: enable}
	ln, err := cfg.Listen("sctp", mustResolve(t, "127.0.0.1:0"))
	if err != nil {
		t.Skipf("listen with reconfiguration: %v", err)
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

	client, err = cfg.Dial("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Skipf("dial with reconfiguration: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	select {
	case c, ok := <-accepted:
		if !ok {
			t.Skip("accept failed")
		}
		server = c
	case <-time.After(3 * time.Second):
		t.Skip("no association accepted")
	}
	t.Cleanup(func() { _ = server.Close() })

	on, err := client.ReconfigSupported()
	if err != nil || !on {
		t.Skipf("stream reconfiguration not negotiated (supported=%v err=%v); "+
			"net.sctp.reconf_enable is %s", on, err, "probably 0")
	}
	return client, server
}

// awaitNotification reads until a notification of the wanted type arrives.
func awaitNotification(t *testing.T, c *SCTPConn, want SCTPNotificationType,
	budget time.Duration) Notification {
	t.Helper()

	buf := make([]byte, NotificationMaxSize)
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if err := c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		n, _, flags, err := c.SCTPReadFlags(buf)
		if err != nil {
			continue
		}
		if flags&MSG_NOTIFICATION == 0 {
			continue
		}
		note, err := ParseNotification(buf[:n])
		if err != nil {
			t.Fatalf("ParseNotification of a %d byte notification: %v", n, err)
		}
		if note == nil {
			t.Fatalf("the kernel delivered a notification this package does "+
				"not decode: type %#x, %d bytes",
				nativeEndian.Uint16(buf[0:2]), n)
		}
		if note.Type() == want {
			return note
		}
	}
	return nil
}

// TestReconfigurationEventsDecodeFromKernelBytes drives the decoders added for
// RFC 6525 with bytes the kernel produced.
//
// Everything else asserting these builds the buffer in the test, which proves
// the decoder matches the test's idea of the layout and nothing more. These are
// the events that make ResetStreams and AddStreams meaningful — both return as
// soon as the request is away, so the event is the only thing that says whether
// the peer carried it out or refused.
func TestReconfigurationEventsDecodeFromKernelBytes(t *testing.T) {
	client, server := reconfPair(t)

	// SubscribeEvents cannot reach these. Its struct is the ten RFC 6458
	// §6.2.1 events; stream reset, association reset and stream change are
	// Linux's own additions at fields 11 to 14, outside it. SCTP_EVENT, which
	// SubscribeEvent uses, takes a type and a flag and so reaches any of them —
	// which is the whole reason it exists.
	for _, c := range []*SCTPConn{client, server} {
		for _, typ := range []SCTPNotificationType{
			SCTP_ASSOC_CHANGE, SCTP_STREAM_RESET_EVENT,
			SCTP_ASSOC_RESET_EVENT, SCTP_STREAM_CHANGE_EVENT,
		} {
			if err := c.SubscribeEvent(typ, true); err != nil {
				t.Fatalf("SubscribeEvent(%#x): %v", int(typ), err)
			}
		}
	}
	if err := client.SetEnableStreamReset(SCTPEnableResetStreamReq | SCTPEnableResetAssocReq | SCTPEnableChangeAssocReq); err != nil {
		t.Fatalf("SetEnableStreamReset: %v", err)
	}
	if err := server.SetEnableStreamReset(SCTPEnableResetStreamReq | SCTPEnableResetAssocReq | SCTPEnableChangeAssocReq); err != nil {
		t.Fatalf("SetEnableStreamReset: %v", err)
	}

	t.Run("stream change from AddStreams", func(t *testing.T) {
		// Asymmetric counts, so a decoder that swapped the two fields shows.
		const addIn, addOut = 1, 3
		// What the requesting side is told. Measured: inbound=0, outbound=3
		// after AddStreams(1, 3) — the kernel reports the outbound streams it
		// added and leaves strchange_instrms at zero here, since the inbound
		// side of the request is the peer's to grant.
		//
		// Both values matter. A decoder with the two fields swapped produces
		// inbound=3, outbound=0, which the previous "outbound > inbound"
		// assertion could not see: with instrms always 0 it reduced to
		// "outbound > 0".
		const wantIn, wantOut = 0, addOut
		if err := client.AddStreams(addIn, addOut); err != nil {
			t.Skipf("AddStreams: %v", err)
		}
		note := awaitNotification(t, client, SCTP_STREAM_CHANGE_EVENT, 5*time.Second)
		if note == nil {
			t.Skip("no SCTP_STREAM_CHANGE_EVENT arrived")
		}
		sc, ok := note.(*StreamChange)
		if !ok {
			t.Fatalf("got %T, want *StreamChange", note)
		}
		if sc.Flags()&(SCTP_STREAM_CHANGE_DENIED|SCTP_STREAM_CHANGE_FAILED) != 0 {
			t.Logf("peer refused the request (flags %#x); the decode is still "+
				"what is under test", sc.Flags())
			return
		}
		// Exact values, not just an ordering. On the requesting side the
		// kernel reports the counts it added, and strchange_instrms is 0
		// there — so "outbound > inbound" reduces to "outbound > 0" and a
		// decoder with the two fields swapped survives it.
		if sc.InboundStreams != wantIn || sc.OutboundStreams != wantOut {
			t.Errorf("stream change reports inbound=%d outbound=%d, want %d/%d "+
				"after AddStreams(%d, %d)",
				sc.InboundStreams, sc.OutboundStreams, wantIn, wantOut, addIn, addOut)
		}
	})

	t.Run("stream reset", func(t *testing.T) {
		if err := client.ResetStreams(SCTPStreamResetOutgoing, 0); err != nil {
			t.Skipf("ResetStreams: %v", err)
		}
		note := awaitNotification(t, client, SCTP_STREAM_RESET_EVENT, 5*time.Second)
		if note == nil {
			t.Skip("no SCTP_STREAM_RESET_EVENT arrived")
		}
		sr, ok := note.(*StreamReset)
		if !ok {
			t.Fatalf("got %T, want *StreamReset", note)
		}
		// The flexible stream list is the part a hand-built buffer cannot
		// vouch for: this is the kernel's own framing of it.
		for _, sid := range sr.Streams {
			if sid != 0 {
				t.Errorf("reset reported stream %d; only stream 0 was asked for "+
					"(list %v)", sid, sr.Streams)
			}
		}
	})
}
