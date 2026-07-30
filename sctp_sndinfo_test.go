//go:build linux && !386
// +build linux,!386

package sctp

import (
	"bytes"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Covers SCTPWriteInfo, the send path using the non-deprecated ancillary data
// types. RFC 6458 §5.3.2 titles the struct sctp_sndrcvinfo that SCTPWrite emits
// "DEPRECATED" and splits it into SCTP_SNDINFO for sending and SCTP_RCVINFO for
// receiving; the read side was migrated earlier and this is the write side.
//
// SCTPWrite is deliberately unchanged, so the tests here also pin that the two
// interoperate on one association — the kernel accepts either form, and even both
// in a single sendmsg, which was measured with testdata/optprobe/varlen.c.

// sndinfoPair brings up an association and returns both ends, with data-io
// notifications enabled on the reader so SCTPRead returns the per-message info.
func sndinfoPair(t *testing.T) (client, server *SCTPConn) {
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
	client, err = DialSCTP("sctp", nil, la)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server, ok = <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = server.Close() })

	// Without this the receiver gets no SCTP_SNDRCV cmsg and SCTPRead returns a
	// nil info, so every assertion about stream and PPID would be vacuous.
	if err := server.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		t.Fatalf("server subscribe: %v", err)
	}
	return client, server
}

// readOne reads a single message with a deadline, so a send that never arrives
// fails the test rather than hanging it.
func readOne(t *testing.T, c *SCTPConn) ([]byte, *SndRcvInfo) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 256)
	n, info, err := c.SCTPRead(buf)
	if err != nil {
		t.Fatalf("SCTPRead: %v", err)
	}
	if info == nil {
		t.Fatal("SCTPRead returned no per-message info; the reader's " +
			"SCTP_EVENT_DATA_IO subscription is what provides it")
	}
	return buf[:n], info
}

// TestSCTPWriteInfoCarriesStreamAndPPID is the core assertion: a message sent
// with SCTP_SNDINFO arrives on the stream it named, with the payload protocol
// identifier intact.
//
// Reading it back through SCTPRead — which parses SCTP_SNDRCV — is what proves
// the two forms interoperate. If SCTPWriteInfo emitted the wrong cmsg type the
// kernel would ignore it and the message would land on stream 0, so the stream
// assertion is what catches a mistyped cmsg rather than the absence of an error.
func TestSCTPWriteInfoCarriesStreamAndPPID(t *testing.T) {
	client, server := sndinfoPair(t)

	// A non-zero stream is essential: stream 0 is where an ignored cmsg would
	// put the message, so asserting stream 0 would pass with the cmsg dropped.
	const wantStream = 3
	const wantPPID = 0xabcd
	payload := []byte("sndinfo")

	n, err := client.SCTPWriteInfo(payload,
		&SndInfo{SID: wantStream, PPID: htonl(wantPPID)}, nil, nil)
	if err != nil {
		t.Fatalf("SCTPWriteInfo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("wrote %d of %d bytes", n, len(payload))
	}

	got, info := readOne(t, server)
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if info.Stream != wantStream {
		t.Errorf("stream = %d, want %d — stream 0 here means the SCTP_SNDINFO "+
			"cmsg was ignored rather than applied", info.Stream, wantStream)
	}
	// SCTPRead converts PPID to host order, and SCTPWriteInfo passes it through
	// unchanged, so the htonl above is the caller's responsibility. That
	// asymmetry with SCTPWrite is documented on SCTPWriteInfo.
	if info.PPID != wantPPID {
		t.Errorf("PPID = %#x, want %#x", info.PPID, wantPPID)
	}
}

// TestSCTPWriteInfoNilInfoUsesDefaults pins that a nil SndInfo falls back to the
// socket defaults rather than sending a malformed control message.
func TestSCTPWriteInfoNilInfoUsesDefaults(t *testing.T) {
	client, server := sndinfoPair(t)

	// Set a default stream, then send with no per-message info at all.
	const wantStream = 2
	if err := client.SetDefaultSndInfo(&SndInfo{SID: wantStream}); err != nil {
		t.Fatalf("SetDefaultSndInfo: %v", err)
	}

	payload := []byte("defaults")
	if _, err := client.SCTPWriteInfo(payload, nil, nil, nil); err != nil {
		t.Fatalf("SCTPWriteInfo with nil info: %v", err)
	}

	got, info := readOne(t, server)
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if info.Stream != wantStream {
		t.Errorf("stream = %d, want %d from SetDefaultSndInfo; a nil SndInfo "+
			"must send no cmsg rather than a zeroed one", info.Stream, wantStream)
	}
}

// TestSCTPWriteInfoWithPrInfo covers attaching a per-message partial reliability
// policy, the combination a PR-SCTP send actually needs.
//
// Two control messages in one sendmsg is where the alignment padding between
// cmsgs matters: without it the kernel reads the second header from the wrong
// offset. A single-cmsg test cannot detect that, which is why this case exists
// separately.
func TestSCTPWriteInfoWithPrInfo(t *testing.T) {
	client, server := sndinfoPair(t)

	const wantStream = 1
	payload := []byte("prinfo")
	if _, err := client.SCTPWriteInfo(payload,
		&SndInfo{SID: wantStream},
		&PrInfo{Policy: SCTPPrPolicyTTL, Value: 30000},
		nil); err != nil {
		t.Fatalf("SCTPWriteInfo with PrInfo: %v", err)
	}

	// A generous TTL, so the message must still arrive — a policy that
	// abandoned it would make this read time out.
	got, info := readOne(t, server)
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if info.Stream != wantStream {
		t.Errorf("stream = %d, want %d — a wrong stream with two cmsgs "+
			"present suggests the inter-cmsg padding is wrong, so the kernel "+
			"read the second header at the wrong offset", info.Stream, wantStream)
	}
}

// TestSCTPWriteInfoCmsgPadding covers the alignment padding between control
// messages, which only one combination can detect.
//
// syscall.CmsgSpace equals syscall.CmsgLen for a 16-byte SndInfo and an 8-byte
// PrInfo, so any test using only those two passes whether or not the padding is
// emitted. AuthInfo is 2 bytes, where CmsgLen is 18 and CmsgSpace is 24 — a
// 6-byte gap. So the padding is observable only when a 2-byte cmsg is followed by
// another one, and this is the case that makes it so.
//
// Without the padding the kernel reads the next cmsg header from 6 bytes early,
// finding garbage where cmsg_len should be. It rejects the whole sendmsg, so the
// symptom is an error rather than a misdelivered message.
// TestSCTPWriteInfoCmsgPadding covers the alignment padding between control
// messages, which exactly one combination can detect.
//
// syscall.CmsgSpace equals syscall.CmsgLen for a 16-byte SndInfo and an 8-byte
// PrInfo, so any send using only those passes whether or not the padding is
// emitted. AuthInfo is 2 bytes, where CmsgLen is 18 and CmsgSpace is 24 — a
// 6-byte gap. Padding is only ever read when another control message follows it,
// so the observable case is an AuthInfo followed by something else.
//
// That is why SCTPWriteInfo emits AUTHINFO first rather than last: ordering it
// last would leave the padding logic permanently untestable through the public
// API. Passing all three here exercises the real code path, and a missing pad
// makes the kernel read garbage where the second cmsg_len belongs and reject the
// whole sendmsg.
func TestSCTPWriteInfoCmsgPadding(t *testing.T) {
	if !authEnabled(t) {
		t.Skip("net.sctp.auth_enable is off; a 2-byte AuthInfo cmsg is the " +
			"only one whose padding is non-zero, so this cannot be tested " +
			"without it")
	}
	// Guard against the test silently becoming vacuous if a platform ever made
	// every cmsg size self-aligning.
	if n := int(unsafe.Sizeof(AuthInfo{})); syscall.CmsgSpace(n) == syscall.CmsgLen(n) {
		t.Skip("AuthInfo needs no padding on this platform, so a following " +
			"cmsg cannot detect a missing pad")
	}

	client, server := sndinfoPair(t)

	const wantStream = 6
	payload := []byte("padding")
	if _, err := client.SCTPWriteInfo(payload,
		&SndInfo{SID: wantStream},
		&PrInfo{Policy: SCTPPrPolicyTTL, Value: 30000},
		&AuthInfo{KeyNumber: 0}); err != nil {
		t.Fatalf("SCTPWriteInfo with all three cmsgs: %v — AUTHINFO is emitted "+
			"first and needs 6 bytes of padding before the next header, so "+
			"this is the send that fails when the padding is dropped", err)
	}

	got, info := readOne(t, server)
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if info.Stream != wantStream {
		t.Errorf("stream = %d, want %d — the wrong stream means a later cmsg "+
			"was read at the wrong offset", info.Stream, wantStream)
	}
}

// TestCmsgPaddingIsObservable states the arithmetic the test above depends on, so
// that if a platform ever made every cmsg size self-aligning, the reason
// TestSCTPWriteInfoCmsgPadding exists would fail loudly rather than the test
// quietly becoming vacuous.
func TestCmsgPaddingIsObservable(t *testing.T) {
	// The sizes SCTPWriteInfo actually emits.
	sizes := map[string]int{
		"SndInfo":  int(unsafe.Sizeof(SndInfo{})),
		"PrInfo":   int(unsafe.Sizeof(PrInfo{})),
		"AuthInfo": int(unsafe.Sizeof(AuthInfo{})),
	}
	var anyPadded bool
	for name, n := range sizes {
		pad := syscall.CmsgSpace(n) - syscall.CmsgLen(n)
		t.Logf("%-8s data=%2d CmsgLen=%2d CmsgSpace=%2d pad=%d",
			name, n, syscall.CmsgLen(n), syscall.CmsgSpace(n), pad)
		if pad > 0 {
			anyPadded = true
		}
	}
	if !anyPadded {
		t.Error("no cmsg SCTPWriteInfo emits needs alignment padding on this " +
			"platform, so TestSCTPWriteInfoCmsgPadding cannot detect a missing " +
			"pad and the padding code is untested here")
	}
}

// TestSCTPWriteInfoRejectsBadPrPolicy records that the kernel validates the
// per-message policy just as it validates the socket default.
func TestSCTPWriteInfoRejectsBadPrPolicy(t *testing.T) {
	client, _ := sndinfoPair(t)

	_, err := client.SCTPWriteInfo([]byte("bad"),
		&SndInfo{}, &PrInfo{Policy: 0x40, Value: 1}, nil)
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("SCTPWriteInfo with policy 0x40 gave %v, want EINVAL — if the "+
			"kernel stopped validating, SCTPWriteInfo would need a Go-side "+
			"guard the way SetEnableStreamReset has one", err)
	}
}

// TestSCTPWriteInfoInteropWithSCTPWrite pins that both send paths work on the
// same association, in both directions.
//
// This is the reason SCTPWrite was left emitting the deprecated cmsg: a caller
// migrating one call site at a time must not break the others.
func TestSCTPWriteInfoInteropWithSCTPWrite(t *testing.T) {
	client, server := sndinfoPair(t)
	if err := client.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		t.Fatalf("client subscribe: %v", err)
	}

	// Modern send, deprecated read.
	if _, err := client.SCTPWriteInfo([]byte("modern"),
		&SndInfo{SID: 4, PPID: htonl(0x11)}, nil, nil); err != nil {
		t.Fatalf("SCTPWriteInfo: %v", err)
	}
	got, info := readOne(t, server)
	if string(got) != "modern" || info.Stream != 4 || info.PPID != 0x11 {
		t.Errorf("modern send read back as %q stream=%d ppid=%#x, want "+
			"\"modern\" stream=4 ppid=0x11", got, info.Stream, info.PPID)
	}

	// Deprecated send, same association, replying on a different stream.
	if _, err := server.SCTPWrite([]byte("legacy"),
		&SndRcvInfo{Stream: 5, PPID: 0x22}); err != nil {
		t.Fatalf("SCTPWrite: %v", err)
	}
	got, info = readOne(t, client)
	if string(got) != "legacy" || info.Stream != 5 || info.PPID != 0x22 {
		t.Errorf("legacy send read back as %q stream=%d ppid=%#x, want "+
			"\"legacy\" stream=5 ppid=0x22", got, info.Stream, info.PPID)
	}
}

// TestSCTPWriteInfoHonoursWriteDeadline pins that the deadline check SCTPWrite
// performs is present here too.
//
// Both send paths pass MSG_DONTWAIT, so SO_SNDTIMEO does not apply and the
// deadline has to be enforced in Go. A copy of the send path that omitted the
// check would pass every other test in this file.
func TestSCTPWriteInfoHonoursWriteDeadline(t *testing.T) {
	client, _ := sndinfoPair(t)

	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	_, err := client.SCTPWriteInfo([]byte("late"), &SndInfo{}, nil, nil)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("SCTPWriteInfo with an expired deadline gave %v, want "+
			"os.ErrDeadlineExceeded", err)
	}
}

// TestSCTPWriteInfoWithAuthInfo covers naming a key per message.
//
// Skipped without the sysctl, since SCTP_AUTHINFO needs AUTH enabled to mean
// anything.
func TestSCTPWriteInfoWithAuthInfo(t *testing.T) {
	if !authEnabled(t) {
		t.Skip("net.sctp.auth_enable is off; SCTP_AUTHINFO needs it")
	}
	client, server := sndinfoPair(t)

	// Key 0 is the null key every association starts with, so this needs no
	// SetAuthKey first.
	payload := []byte("authinfo")
	if _, err := client.SCTPWriteInfo(payload,
		&SndInfo{SID: 1}, nil, &AuthInfo{KeyNumber: 0}); err != nil {
		t.Fatalf("SCTPWriteInfo with AuthInfo: %v", err)
	}

	got, info := readOne(t, server)
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if info.Stream != 1 {
		t.Errorf("stream = %d, want 1", info.Stream)
	}
}
