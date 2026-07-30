//go:build linux && !386
// +build linux,!386

package sctp

import (
	"bytes"
	"errors"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// Covers buildSndRcvCmsg, which replaced two reflection-based toBuf calls on the
// send path with a direct byte layout.
//
// The risk in that change is a silently different control message: the kernel
// reads whatever sits at each offset, so a transposed field produces a valid
// send with the wrong stream or PPID. These tests compare against the exact bytes
// the previous implementation produced, so equivalence is demonstrated rather
// than argued.

// legacySndRcvCmsg reproduces the pre-optimisation construction, byte for byte.
//
// Kept as the reference for the comparison below. It is deliberately a copy of
// what was replaced, including the CmsgSpace-rather-than-CmsgLen header length,
// so that any difference the new code introduces shows up as a test failure
// instead of as a behaviour change on a caller's socket.
func legacySndRcvCmsg(info *SndRcvInfo) []byte {
	oldPPID := info.PPID
	info.PPID = htonl(info.PPID)
	cmsgBuf := toBuf(info)
	info.PPID = oldPPID

	hdr := &syscall.Cmsghdr{
		Level: syscall.IPPROTO_SCTP,
		Type:  SCTP_CMSG_SNDRCV,
	}
	hdr.SetLen(syscall.CmsgSpace(len(cmsgBuf)))
	return append(toBuf(hdr), cmsgBuf...)
}

// TestBuildSndRcvCmsgMatchesLegacy is the equivalence proof.
//
// Every field is given a distinct value so a transposition cannot hide behind
// equal bytes, and the whole buffer is compared rather than a few fields.
func TestBuildSndRcvCmsgMatchesLegacy(t *testing.T) {
	cases := []struct {
		name string
		info SndRcvInfo
	}{
		{"zero", SndRcvInfo{}},
		{"distinct fields", SndRcvInfo{
			Stream:  0x1111,
			SSN:     0x2222,
			Flags:   0x3333,
			PPID:    0x44444444,
			Context: 0x55555555,
			TTL:     0x66666666,
			TSN:     0x77777777,
			CumTSN:  0x88888888,
			AssocID: 0x1234abcd,
		}},
		{"max values", SndRcvInfo{
			Stream:  0xffff,
			SSN:     0xffff,
			Flags:   0xffff,
			PPID:    0xffffffff,
			Context: 0xffffffff,
			TTL:     0xffffffff,
			TSN:     0xffffffff,
			CumTSN:  0xffffffff,
			AssocID: -1,
		}},
		{"typical", SndRcvInfo{Stream: 3, PPID: 0x1234}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// legacySndRcvCmsg mutates and restores PPID, so give each a copy
			// and check afterwards that the new one leaves its input alone.
			legacyInput := tc.info
			newInput := tc.info

			want := legacySndRcvCmsg(&legacyInput)
			got := buildSndRcvCmsg(&newInput)

			if !bytes.Equal(got, want) {
				t.Errorf("control message differs from the previous "+
					"implementation:\n got %x\nwant %x", got, want)
			}
			if len(got) != len(want) {
				t.Errorf("length %d, want %d", len(got), len(want))
			}

			// The whole point of replacing the old version: the caller's struct
			// must come back untouched. The old one byte-swapped PPID in place.
			if newInput != tc.info {
				t.Errorf("buildSndRcvCmsg modified its argument: got %+v, "+
					"want %+v — the previous implementation did this and it "+
					"was a data race for a shared *SndRcvInfo",
					newInput, tc.info)
			}
		})
	}
}

// TestBuildSndRcvCmsgHeader checks the control-message header separately, since
// a wrong level or type would make the kernel ignore the message rather than
// reject it — the failure mode is a send on stream 0 with no error.
func TestBuildSndRcvCmsgHeader(t *testing.T) {
	buf := buildSndRcvCmsg(&SndRcvInfo{Stream: 7, PPID: 0x99})

	msgs, err := syscall.ParseSocketControlMessage(buf)
	if err != nil {
		t.Fatalf("the buffer is not a parseable control message: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d control messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.Header.Level != syscall.IPPROTO_SCTP {
		t.Errorf("level = %d, want %d (IPPROTO_SCTP)",
			m.Header.Level, syscall.IPPROTO_SCTP)
	}
	if m.Header.Type != SCTP_CMSG_SNDRCV {
		t.Errorf("type = %d, want %d (SCTP_CMSG_SNDRCV)",
			m.Header.Type, SCTP_CMSG_SNDRCV)
	}
	if len(m.Data) < int(unsafe.Sizeof(SndRcvInfo{})) {
		t.Errorf("data is %d bytes, want at least %d for a struct "+
			"sctp_sndrcvinfo", len(m.Data), unsafe.Sizeof(SndRcvInfo{}))
	}
}

// TestBuildSndRcvCmsgOffsetsMatchStruct pins the literal offsets in
// buildSndRcvCmsg against the Go struct they describe.
//
// The byte comparison against the previous implementation cannot catch a wrong
// offset constant here, because both implementations derive their length from the
// same struct: a mutation changing the payload length to 28 survived that
// comparison entirely. Asserting the offsets directly is what closes it, and it
// also means a future field added to SndRcvInfo fails here rather than silently
// shifting what the kernel reads.
func TestBuildSndRcvCmsgOffsetsMatchStruct(t *testing.T) {
	var s SndRcvInfo

	// The offsets buildSndRcvCmsg writes to, in the order it writes them.
	for _, tc := range []struct {
		name   string
		got    uintptr
		want   uintptr
		offset int
	}{
		{"Stream", unsafe.Offsetof(s.Stream), 0, 0},
		{"SSN", unsafe.Offsetof(s.SSN), 2, 2},
		{"Flags", unsafe.Offsetof(s.Flags), 4, 4},
		{"PPID", unsafe.Offsetof(s.PPID), 8, 8},
		{"Context", unsafe.Offsetof(s.Context), 12, 12},
		{"TTL", unsafe.Offsetof(s.TTL), 16, 16},
		{"TSN", unsafe.Offsetof(s.TSN), 20, 20},
		{"CumTSN", unsafe.Offsetof(s.CumTSN), 24, 24},
		{"AssocID", unsafe.Offsetof(s.AssocID), 28, 28},
	} {
		if tc.got != tc.want {
			t.Errorf("SndRcvInfo.%s is at offset %d but buildSndRcvCmsg writes "+
				"it at %d", tc.name, tc.got, tc.offset)
		}
	}

	// And the total, since the payload length is derived from it.
	if got := unsafe.Sizeof(s); got != 32 {
		t.Errorf("sizeof(SndRcvInfo) = %d, want 32; buildSndRcvCmsg's field "+
			"offsets assume that layout", got)
	}

	// The buffer the builder produces has to be exactly one aligned control
	// message for that payload. A short one would have the kernel read past the
	// data the caller supplied.
	buf := buildSndRcvCmsg(&s)
	if want := syscall.CmsgSpace(int(unsafe.Sizeof(s))); len(buf) != want {
		t.Errorf("control message is %d bytes, want %d for a %d byte payload",
			len(buf), want, unsafe.Sizeof(s))
	}
}

// TestBuildSndRcvCmsgRoundTripsThroughParser closes the loop: the bytes the send
// path produces must decode back to the same values through the package's own
// receive-side parser.
//
// This is the check that would catch a field written at the wrong offset even if
// the legacy comparison were somehow also wrong, since parseSndRcvInfo reads the
// struct through the kernel's layout rather than by repeating these offsets.
func TestBuildSndRcvCmsgRoundTripsThroughParser(t *testing.T) {
	want := &SndRcvInfo{
		Stream:  5,
		SSN:     9,
		Flags:   SCTP_UNORDERED,
		PPID:    0xdeadbeef,
		Context: 0x5eed,
		TSN:     0x1000,
		CumTSN:  0x0fff,
	}

	got, err := parseSndRcvInfo(buildSndRcvCmsg(want))
	if err != nil {
		t.Fatalf("parseSndRcvInfo: %v", err)
	}
	if got.Stream != want.Stream {
		t.Errorf("Stream = %d, want %d", got.Stream, want.Stream)
	}
	if got.SSN != want.SSN {
		t.Errorf("SSN = %d, want %d", got.SSN, want.SSN)
	}
	if got.Flags != want.Flags {
		t.Errorf("Flags = %#x, want %#x", got.Flags, want.Flags)
	}
	// PPID is written in network order and read back in host order, so the
	// round trip must return the original value. A missing conversion on either
	// side shows up here and nowhere else.
	if got.PPID != want.PPID {
		t.Errorf("PPID = %#x, want %#x — the byte-order conversion is "+
			"asymmetric between build and parse", got.PPID, want.PPID)
	}
	if got.Context != want.Context {
		t.Errorf("Context = %#x, want %#x", got.Context, want.Context)
	}
	if got.TSN != want.TSN {
		t.Errorf("TSN = %#x, want %#x", got.TSN, want.TSN)
	}
	if got.CumTSN != want.CumTSN {
		t.Errorf("CumTSN = %#x, want %#x", got.CumTSN, want.CumTSN)
	}
}

// TestParseSndRcvInfoDoesNotAliasInput covers the read-side counterpart of the
// write-side race: parseSndRcvInfo used to return a pointer into the control
// message it was given, and byte-swap PPID inside that buffer.
//
// Two consequences, both real rather than theoretical:
//
//   - Parsing the same bytes twice swapped PPID twice. An 0x11223344 payload read
//     back as 0x11223344 and then 0x44332211. Any caller driving recvmsg itself
//     through SyscallConn could hit that.
//   - The oob buffer in SCTPReadFlags could not be pooled or reused, because the
//     returned value outlived the read that produced it.
//
// It now copies, so the result is independent of the buffer.
func TestParseSndRcvInfoDoesNotAliasInput(t *testing.T) {
	const ppid = 0x11223344
	buf := buildSndRcvCmsg(&SndRcvInfo{Stream: 1, PPID: ppid})

	first, err := parseSndRcvInfo(buf)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	second, err := parseSndRcvInfo(buf)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}

	if first.PPID != ppid {
		t.Errorf("first parse PPID = %#x, want %#x", first.PPID, ppid)
	}
	if second.PPID != ppid {
		t.Errorf("second parse PPID = %#x, want %#x — parsing twice must be "+
			"idempotent, and a byte-swapped value here means the parser is "+
			"mutating its input", second.PPID, ppid)
	}
	if first == second {
		t.Error("both parses returned the same pointer, so the result still " +
			"aliases the input buffer; it has to be a copy for the buffer to " +
			"be reusable")
	}

	// Overwriting the buffer must not disturb an already-returned result. This is
	// the property that makes reusing the read buffer safe.
	for i := range buf {
		buf[i] = 0xff
	}
	if first.PPID != ppid {
		t.Errorf("PPID became %#x after the source buffer was overwritten; the "+
			"returned struct still points into it", first.PPID)
	}
	if first.Stream != 1 {
		t.Errorf("Stream became %d after the source buffer was overwritten",
			first.Stream)
	}
}

// TestSCTPReadInfoSurvivesLaterReads is the same property through the public API:
// the info from one read must stay valid across subsequent reads.
//
// While parseSndRcvInfo aliased its input this only held by accident, because
// SCTPReadFlags allocated a fresh oob buffer every call. A caller keeping the info
// from several messages would break the moment that allocation was reused.
func TestSCTPReadInfoSurvivesLaterReads(t *testing.T) {
	client, server := sndinfoPair(t)

	// Distinct PPIDs so a stale or overwritten struct is identifiable.
	const messages = 4
	for i := 0; i < messages; i++ {
		info := &SndRcvInfo{Stream: uint16(i), PPID: uint32(0x1000 + i)}
		if _, err := client.SCTPWrite([]byte("keep"), info); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Hold every returned info, then check them all after the reads are done.
	got := make([]*SndRcvInfo, 0, messages)
	for i := 0; i < messages; i++ {
		_, info := readOne(t, server)
		got = append(got, info)
	}

	for i, info := range got {
		wantStream := uint16(i)
		wantPPID := uint32(0x1000 + i)
		if info.Stream != wantStream || info.PPID != wantPPID {
			t.Errorf("info %d held across later reads is stream=%d ppid=%#x, "+
				"want stream=%d ppid=%#x", i, info.Stream, info.PPID,
				wantStream, wantPPID)
		}
	}
}

// TestSCTPWriteDoesNotMutateInfo covers the race fix through the public API, on a
// real association, rather than only against the builder.
func TestSCTPWriteDoesNotMutateInfo(t *testing.T) {
	client, server := sndinfoPair(t)

	// A PPID whose byte-swapped form differs from itself, so an in-place swap
	// that was not restored is visible.
	info := &SndRcvInfo{Stream: 2, PPID: 0x11223344}
	before := *info

	if _, err := client.SCTPWrite([]byte("nomutate"), info); err != nil {
		t.Fatalf("write: %v", err)
	}
	if *info != before {
		t.Errorf("SCTPWrite modified its info argument: got %+v, want %+v",
			*info, before)
	}

	// And the message still arrives correctly, so the no-mutation property was
	// not bought by sending the wrong bytes.
	got, rinfo := readOne(t, server)
	if string(got) != "nomutate" {
		t.Errorf("payload = %q, want %q", got, "nomutate")
	}
	if rinfo.Stream != 2 {
		t.Errorf("stream = %d, want 2", rinfo.Stream)
	}
	if rinfo.PPID != 0x11223344 {
		t.Errorf("PPID = %#x, want 0x11223344", rinfo.PPID)
	}
}

// TestSCTPWriteConcurrentSharedInfo exercises the race the old in-place swap
// created. Under -race the previous implementation would report a write/write
// conflict on info.PPID; this asserts the observable consequence as well, since
// the suite is not always run with the detector.
func TestSCTPWriteConcurrentSharedInfo(t *testing.T) {
	client, server := sndinfoPair(t)

	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, _, err := server.SCTPRead(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { close(stop) })

	// One shared, logically read-only info across several senders.
	info := &SndRcvInfo{Stream: 1, PPID: 0x01020304}
	before := *info

	const senders = 8
	const each = 50
	errs := make(chan error, senders)
	for i := 0; i < senders; i++ {
		go func() {
			for j := 0; j < each; j++ {
				// SCTPWrite passes MSG_DONTWAIT, so a full send buffer reports
				// EAGAIN rather than blocking. That is not what this test is
				// about — it only needs concurrent traffic through the cmsg
				// builder — so yield and retry rather than failing.
				for {
					_, err := client.SCTPWrite([]byte("shared"), info)
					if err == nil {
						break
					}
					if !errors.Is(err, syscall.EAGAIN) {
						errs <- err
						return
					}
					runtime.Gosched()
				}
			}
			errs <- nil
		}()
	}
	for i := 0; i < senders; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}

	if *info != before {
		t.Errorf("shared info was modified by concurrent writes: got %+v, "+
			"want %+v", *info, before)
	}
}
