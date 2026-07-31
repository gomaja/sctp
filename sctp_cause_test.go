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
	"encoding/binary"
	"testing"
	"time"
)

// putNotificationHeader writes the eight bytes every notification starts with.
func putNotificationHeader(b []byte, typ SCTPNotificationType, flags uint16, length uint32) {
	nativeEndian.PutUint16(b[0:2], uint16(typ))
	nativeEndian.PutUint16(b[2:4], flags)
	nativeEndian.PutUint32(b[4:8], length)
}

// TestAssocChangeErrorIsDecodedFromNetworkOrder pins the byte order of the
// error cause an SCTP_ASSOC_CHANGE carries.
//
// The kernel declares its cause constants cpu_to_be16 and assigns them into a
// host-typed __u16 without converting, so the two bytes in the buffer are the
// network representation. This package used to read them natively and reported
// SCTP_ERROR_USER_ABORT, cause 12, as 3072.
//
// Every value here is deliberately byte-asymmetric. The test that existed
// before used 0x2222, which is identical under a byte swap and therefore
// cannot fail however the field is decoded — which is why nothing caught this.
func TestAssocChangeErrorIsDecodedFromNetworkOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause uint16
	}{
		{"user abort", SCTP_ERROR_USER_ABORT},
		{"invalid stream", SCTP_ERROR_INV_STRM},
		{"protocol violation", SCTP_ERROR_PROTO_VIOLATION},
		{"no error", SCTP_ERROR_NO_ERROR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, assocChangeMinSize)
			putNotificationHeader(b, SCTP_ASSOC_CHANGE, 0, assocChangeMinSize)
			nativeEndian.PutUint16(b[8:10], uint16(SCTP_COMM_LOST))
			// The kernel stores the be16 constant in a host __u16, so what
			// lands in the buffer is the network byte order of the cause.
			binary.BigEndian.PutUint16(b[10:12], tc.cause)
			nativeEndian.PutUint16(b[12:14], 7)
			nativeEndian.PutUint16(b[14:16], 9)
			nativeEndian.PutUint32(b[16:20], 42)

			note, err := ParseNotification(b)
			if err != nil {
				t.Fatalf("ParseNotification: %v", err)
			}
			ac, ok := note.(*AssocChange)
			if !ok {
				t.Fatalf("got %T, want *AssocChange", note)
			}
			if ac.Error != tc.cause {
				t.Errorf("Error = %d (%s), want %d (%s); the cause is being "+
					"read in the wrong byte order",
					ac.Error, ErrorCauseString(uint32(ac.Error)),
					tc.cause, ErrorCauseString(uint32(tc.cause)))
			}
			// The neighbouring fields are genuinely host order; a fix that
			// swapped the whole struct would break them.
			if ac.State != SCTP_COMM_LOST || ac.OutboundStreams != 7 ||
				ac.InboundStreams != 9 || ac.AssocID != 42 {
				t.Errorf("host-order fields decoded wrong: state=%v out=%d in=%d id=%d",
					ac.State, ac.OutboundStreams, ac.InboundStreams, ac.AssocID)
			}
		})
	}
}

// TestRemoteErrorErrorIsDecodedFromNetworkOrder is the same for
// SCTP_REMOTE_ERROR, whose sre_error is the __be16 copied straight off the
// peer's ERROR chunk.
func TestRemoteErrorErrorIsDecodedFromNetworkOrder(t *testing.T) {
	b := make([]byte, remoteErrorMinSize)
	putNotificationHeader(b, SCTP_REMOTE_ERROR, 0, remoteErrorMinSize)
	binary.BigEndian.PutUint16(b[8:10], SCTP_ERROR_INV_STRM)
	nativeEndian.PutUint32(b[12:16], 7)

	note, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	re, ok := note.(*RemoteError)
	if !ok {
		t.Fatalf("got %T, want *RemoteError", note)
	}
	if re.Error != SCTP_ERROR_INV_STRM {
		t.Errorf("Error = %d (%s), want %d", re.Error,
			ErrorCauseString(uint32(re.Error)), SCTP_ERROR_INV_STRM)
	}
}

// TestSendFailedErrorIsDecodedFromNetworkOrder covers the third field carrying
// a cause, which needs a different rule from the other two.
//
// ssf_error is a __u32 holding the same be16 constant, widened by an ordinary
// integer promotion. The promotion is host arithmetic, so the bytes are not
// the network form the way they are for the __u16 fields — on a little-endian
// host the swapped value sits in the low half of the word.
func TestSendFailedErrorIsDecodedFromNetworkOrder(t *testing.T) {
	minSize := notificationHeaderSize + 4 + int(sndRcvInfoSize) + 4
	b := make([]byte, minSize)
	putNotificationHeader(b, SCTP_SEND_FAILED, SCTP_DATA_UNSENT, uint32(minSize))
	nativeEndian.PutUint32(b[8:12], uint32(ntohs(SCTP_ERROR_NO_DATA)))

	note, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	sf, ok := note.(*SendFailed)
	if !ok {
		t.Fatalf("got %T, want *SendFailed", note)
	}
	if sf.Error != SCTP_ERROR_NO_DATA {
		t.Errorf("Error = %d (%s), want %d", sf.Error,
			ErrorCauseString(sf.Error), SCTP_ERROR_NO_DATA)
	}
}

// TestPeerAddrChangeErrorStaysHostOrder guards the field that must *not* be
// swapped.
//
// spc_error carries an sctp_sn_error_t — SCTP_FAILED_THRESHOLD and friends — a
// small host-order enum the stack sets itself, not a wire cause. A blanket
// "notification error fields are network order" fix breaks it, and nothing
// else would notice.
func TestPeerAddrChangeErrorStaysHostOrder(t *testing.T) {
	const failedThreshold = 0 // enum sctp_sn_error's first member
	const receivedSack = 1

	for _, want := range []uint32{failedThreshold, receivedSack} {
		b := make([]byte, peerAddrChangeSize)
		putNotificationHeader(b, SCTP_PEER_ADDR_CHANGE, 0, peerAddrChangeSize)
		nativeEndian.PutUint32(b[136:140], SCTP_ADDR_UNREACHABLE)
		nativeEndian.PutUint32(b[140:144], want)
		nativeEndian.PutUint32(b[144:148], 3)

		note, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		pc, ok := note.(*PeerAddrChange)
		if !ok {
			t.Fatalf("got %T, want *PeerAddrChange", note)
		}
		if pc.Error != want {
			t.Errorf("Error = %d, want %d; spc_error is a host-order "+
				"sctp_sn_error_t, unlike sac_error and sre_error", pc.Error, want)
		}
	}
}

// TestErrorCauseStringNamesTheRFCCauses checks the vocabulary is wired to the
// right numbers, since a wrong name in a log is worse than a bare number.
func TestErrorCauseStringNamesTheRFCCauses(t *testing.T) {
	for cause, want := range map[uint32]string{
		SCTP_ERROR_NO_ERROR:        "SCTP_ERROR_NO_ERROR",
		SCTP_ERROR_INV_STRM:        "SCTP_ERROR_INV_STRM",
		SCTP_ERROR_USER_ABORT:      "SCTP_ERROR_USER_ABORT",
		SCTP_ERROR_PROTO_VIOLATION: "SCTP_ERROR_PROTO_VIOLATION",
		SCTP_ERROR_UNSUP_HMAC:      "SCTP_ERROR_UNSUP_HMAC",
	} {
		if got := ErrorCauseString(cause); got != want {
			t.Errorf("ErrorCauseString(%d) = %q, want %q", cause, got, want)
		}
	}
	if got := ErrorCauseString(0xbeef); got == "" {
		t.Error("ErrorCauseString of an unknown cause returned an empty string")
	}
}

// TestAbortReportsTheUserAbortCause is the end-to-end half: the value comes
// from the kernel rather than from a buffer this test wrote.
//
// A hand-built buffer only proves the decoder matches this test's idea of the
// layout. Aborting a real association proves it matches the kernel's — and it
// is the measurement that showed the old decoder reporting 3072.
func TestAbortReportsTheUserAbortCause(t *testing.T) {
	client, server := eorPair(t)

	if err := client.SubscribeEvent(SCTP_ASSOC_CHANGE, true); err != nil {
		t.Fatalf("subscribe SCTP_ASSOC_CHANGE: %v", err)
	}

	// Abort rather than Close: only an ABORT carries an error cause, and
	// SCTP_ERROR_USER_ABORT is byte-asymmetric so the decode is falsifiable.
	if err := server.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}

	buf := make([]byte, NotificationMaxSize)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		n, _, flags, err := client.SCTPReadFlags(buf)
		if err != nil {
			continue
		}
		if flags&MSG_NOTIFICATION == 0 {
			continue
		}
		note, err := ParseNotification(buf[:n])
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		ac, ok := note.(*AssocChange)
		if !ok {
			continue
		}
		if ac.State != SCTP_COMM_LOST {
			continue
		}
		if ac.Error != SCTP_ERROR_USER_ABORT {
			t.Fatalf("aborted association reports cause %d (%s), want %d "+
				"(SCTP_ERROR_USER_ABORT); %d is what this reads as when the "+
				"be16 is decoded natively on a little-endian host",
				ac.Error, ErrorCauseString(uint32(ac.Error)),
				SCTP_ERROR_USER_ABORT, ntohs(SCTP_ERROR_USER_ABORT))
		}
		return
	}
	t.Fatal("no SCTP_COMM_LOST notification arrived within 5s of the abort")
}

// TestParsesTheEventsStreamReconfigurationNeeds covers the four notification
// types that had constants but no decoder.
//
// Without them ParseNotification returned (nil, nil) — the "unknown event"
// answer — for events this package's own ResetStreams and AddStreams cause the
// kernel to deliver. Those two report only that the request was sent, so
// without these the extension is write-only.
func TestParsesTheEventsStreamReconfigurationNeeds(t *testing.T) {
	t.Run("stream reset", func(t *testing.T) {
		b := make([]byte, streamResetMinSize+4)
		putNotificationHeader(b, SCTP_STREAM_RESET_EVENT,
			SCTP_STREAM_RESET_DENIED, uint32(len(b)))
		nativeEndian.PutUint32(b[8:12], 11)
		nativeEndian.PutUint16(b[12:14], 3)
		nativeEndian.PutUint16(b[14:16], 5)

		note, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		sr, ok := note.(*StreamReset)
		if !ok {
			t.Fatalf("got %T, want *StreamReset", note)
		}
		if sr.AssocID != 11 || len(sr.Streams) != 2 ||
			sr.Streams[0] != 3 || sr.Streams[1] != 5 {
			t.Errorf("decoded id=%d streams=%v, want id=11 streams=[3 5]",
				sr.AssocID, sr.Streams)
		}
		if sr.Flags()&SCTP_STREAM_RESET_DENIED == 0 {
			t.Error("DENIED flag lost; a caller cannot tell a refused reset " +
				"from a successful one")
		}
	})

	t.Run("stream reset with an odd trailing byte", func(t *testing.T) {
		// The stream list is a flexible array member, so nothing guarantees
		// the tail is a whole number of stream ids. Reading the odd byte as
		// half an id would run past the buffer.
		b := make([]byte, streamResetMinSize+3)
		putNotificationHeader(b, SCTP_STREAM_RESET_EVENT, 0, uint32(len(b)))
		nativeEndian.PutUint16(b[12:14], 8)

		note, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		sr := note.(*StreamReset)
		if len(sr.Streams) != 1 || sr.Streams[0] != 8 {
			t.Errorf("streams = %v, want [8]", sr.Streams)
		}
	})

	t.Run("assoc reset", func(t *testing.T) {
		b := make([]byte, assocResetSize)
		putNotificationHeader(b, SCTP_ASSOC_RESET_EVENT, 0, assocResetSize)
		nativeEndian.PutUint32(b[8:12], 4)
		nativeEndian.PutUint32(b[12:16], 0x11223344)
		nativeEndian.PutUint32(b[16:20], 0x55667788)

		note, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		ar, ok := note.(*AssocReset)
		if !ok {
			t.Fatalf("got %T, want *AssocReset", note)
		}
		if ar.AssocID != 4 || ar.LocalTSN != 0x11223344 || ar.RemoteTSN != 0x55667788 {
			t.Errorf("decoded %+v", ar)
		}
	})

	t.Run("stream change", func(t *testing.T) {
		b := make([]byte, streamChangeSize)
		putNotificationHeader(b, SCTP_STREAM_CHANGE_EVENT,
			SCTP_STREAM_CHANGE_FAILED, streamChangeSize)
		nativeEndian.PutUint32(b[8:12], 6)
		nativeEndian.PutUint16(b[12:14], 20)
		nativeEndian.PutUint16(b[14:16], 30)

		note, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		sc, ok := note.(*StreamChange)
		if !ok {
			t.Fatalf("got %T, want *StreamChange", note)
		}
		if sc.AssocID != 6 || sc.InboundStreams != 20 || sc.OutboundStreams != 30 {
			t.Errorf("decoded %+v", sc)
		}
		if sc.Flags()&SCTP_STREAM_CHANGE_FAILED == 0 {
			t.Error("FAILED flag lost")
		}
	})

	t.Run("send failed event", func(t *testing.T) {
		b := make([]byte, sendFailedEventMinSize+3)
		putNotificationHeader(b, SCTP_SEND_FAILED_EVENT, SCTP_DATA_SENT,
			uint32(len(b)))
		nativeEndian.PutUint32(b[8:12], uint32(ntohs(SCTP_ERROR_NO_DATA)))
		nativeEndian.PutUint16(b[12:14], 2) // SndInfo.SID
		nativeEndian.PutUint32(b[28:32], 13)
		copy(b[sendFailedEventMinSize:], "abc")

		note, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		sf, ok := note.(*SendFailedEvent)
		if !ok {
			t.Fatalf("got %T, want *SendFailedEvent", note)
		}
		if sf.Error != SCTP_ERROR_NO_DATA {
			t.Errorf("Error = %d (%s), want %d", sf.Error,
				ErrorCauseString(sf.Error), SCTP_ERROR_NO_DATA)
		}
		if sf.Info.SID != 2 || sf.AssocID != 13 || string(sf.Data) != "abc" {
			t.Errorf("decoded sid=%d id=%d data=%q", sf.Info.SID, sf.AssocID, sf.Data)
		}
	})

	t.Run("authentication event", func(t *testing.T) {
		b := make([]byte, authKeyEventSize)
		putNotificationHeader(b, SCTP_AUTHENTICATION_EVENT, 0, authKeyEventSize)
		nativeEndian.PutUint16(b[8:10], 5)
		nativeEndian.PutUint16(b[10:12], 6)
		nativeEndian.PutUint32(b[12:16], SCTP_AUTH_FREE_KEY)
		nativeEndian.PutUint32(b[16:20], 14)

		note, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		ae, ok := note.(*AuthKeyEvent)
		if !ok {
			t.Fatalf("got %T, want *AuthKeyEvent", note)
		}
		if ae.KeyNumber != 5 || ae.AltKeyNumber != 6 ||
			ae.Indication != SCTP_AUTH_FREE_KEY || ae.AssocID != 14 {
			t.Errorf("decoded %+v", ae)
		}
	})
}

// TestNewNotificationsRejectTruncation checks each added decoder refuses a
// short buffer rather than reading past its end. The kernel truncates a
// notification to whatever buffer the caller passed, so short buffers are a
// thing that happens rather than a thing that cannot.
func TestNewNotificationsRejectTruncation(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  SCTPNotificationType
		size int
	}{
		{"stream reset", SCTP_STREAM_RESET_EVENT, streamResetMinSize},
		{"assoc reset", SCTP_ASSOC_RESET_EVENT, assocResetSize},
		{"stream change", SCTP_STREAM_CHANGE_EVENT, streamChangeSize},
		{"send failed event", SCTP_SEND_FAILED_EVENT, sendFailedEventMinSize},
		{"authentication", SCTP_AUTHENTICATION_EVENT, authKeyEventSize},
	} {
		b := make([]byte, tc.size-1)
		putNotificationHeader(b, tc.typ, 0, uint32(tc.size))
		if _, err := ParseNotification(b); err != ErrShortNotification {
			t.Errorf("%s: err = %v, want ErrShortNotification", tc.name, err)
		}
	}
}

// TestNotificationTypeNumbersMatchTheKernel pins the four added constants to
// their enum sctp_sn_type positions. They are positional, so an entry inserted
// above them here would silently renumber every one below.
func TestNotificationTypeNumbersMatchTheKernel(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  SCTPNotificationType
		want int
	}{
		{"SCTP_SN_TYPE_BASE", SCTP_SN_TYPE_BASE, 0x8000},
		{"SCTP_ASSOC_CHANGE", SCTP_ASSOC_CHANGE, 0x8001},
		{"SCTP_AUTHENTICATION_EVENT", SCTP_AUTHENTICATION_EVENT, 0x8008},
		{"SCTP_SENDER_DRY_EVENT", SCTP_SENDER_DRY_EVENT, 0x8009},
		{"SCTP_STREAM_RESET_EVENT", SCTP_STREAM_RESET_EVENT, 0x800a},
		{"SCTP_ASSOC_RESET_EVENT", SCTP_ASSOC_RESET_EVENT, 0x800b},
		{"SCTP_STREAM_CHANGE_EVENT", SCTP_STREAM_CHANGE_EVENT, 0x800c},
		{"SCTP_SEND_FAILED_EVENT", SCTP_SEND_FAILED_EVENT, 0x800d},
	} {
		if int(tc.got) != tc.want {
			t.Errorf("%s = %#x, want %#x", tc.name, int(tc.got), tc.want)
		}
	}
}
