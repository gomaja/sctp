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
	"testing"
)

// The sizes below were read out of the running kernel with a C probe over
// linux/sctp.h, not copied from the RFC:
//
//	sctp_assoc_change      20   sctp_paddr_change     148
//	sctp_remote_error      16   sctp_send_failed       48
//	sctp_shutdown_event    12   sctp_adaptation_event  16
//	sctp_pdapi_event       24   sctp_sender_dry_event  12
//	sctp_authkey_event     20   sctp_stream_reset_event   12
//	sctp_assoc_reset_event 20   sctp_stream_change_event  16
//	sctp_send_failed_event 32
//
// A parser that reads past the end of a truncated notification panics in the
// read path, so each minimum below is load-bearing.
func TestNotificationSizesMatchKernel(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"sctp_assoc_change", assocChangeMinSize, 20},
		{"sctp_paddr_change", peerAddrChangeSize, 148},
		{"sctp_remote_error", remoteErrorMinSize, 16},
		{"sctp_shutdown_event", shutdownEventSize, 12},
		{"sctp_adaptation_event", adaptationIndicationSize, 16},
		{"sctp_pdapi_event", partialDeliverySize, 24},
		{"sctp_sender_dry_event", senderDrySize, 12},
		{"sctp_authkey_event", authKeyEventSize, 20},
		{"sctp_stream_reset_event", streamResetMinSize, 12},
		{"sctp_assoc_reset_event", assocResetSize, 20},
		{"sctp_stream_change_event", streamChangeSize, 16},
		{"sctp_send_failed_event", sendFailedEventMinSize, 32},
		{"notification header", notificationHeaderSize, 8},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: parser uses %d bytes, kernel struct is %d", tc.name, tc.got, tc.want)
		}
	}

	// sctp_send_failed is 48: 8 header + 4 error + 32 sndrcvinfo + 4 assoc id.
	if want, got := 48, notificationHeaderSize+4+int(sndRcvInfoSize)+4; got != want {
		t.Errorf("sctp_send_failed minimum = %d, kernel struct is %d", got, want)
	}
}

// TestNotificationMaxSizeHoldsEveryFixedNotification is the assertion that gives
// NotificationMaxSize a reason to be the number it is.
//
// It is documented as a read buffer that holds any fixed-size notification, and
// callers are told to size their buffer by it — but nothing compared it against
// the sizes. Shrinking it to 128 survived the complete suite, and 128 is below
// the 148 of SCTP_PEER_ADDR_CHANGE: a caller following the documentation would
// have read the path-failure event, the one this package exists to surface, in
// fragments and rejected every one as truncated.
func TestNotificationMaxSizeHoldsEveryFixedNotification(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{"sctp_assoc_change", assocChangeMinSize},
		{"sctp_paddr_change", peerAddrChangeSize},
		{"sctp_remote_error", remoteErrorMinSize},
		{"sctp_send_failed", notificationHeaderSize + 4 + int(sndRcvInfoSize) + 4},
		{"sctp_shutdown_event", shutdownEventSize},
		{"sctp_adaptation_event", adaptationIndicationSize},
		{"sctp_pdapi_event", partialDeliverySize},
		{"sctp_sender_dry_event", senderDrySize},
		{"sctp_authkey_event", authKeyEventSize},
		{"sctp_stream_reset_event", streamResetMinSize},
		{"sctp_assoc_reset_event", assocResetSize},
		{"sctp_stream_change_event", streamChangeSize},
		{"sctp_send_failed_event", sendFailedEventMinSize},
	} {
		if tc.size > NotificationMaxSize {
			t.Errorf("%s is %d bytes but NotificationMaxSize is %d; a caller "+
				"sizing their buffer as documented cannot read this event whole",
				tc.name, tc.size, NotificationMaxSize)
		}
	}

	// The largest fixed notification is sctp_paddr_change at 148. Anything at
	// or below that would be too small; the headroom above it is for the
	// variable-tail events, which have no fixed bound at all.
	if NotificationMaxSize <= peerAddrChangeSize {
		t.Errorf("NotificationMaxSize = %d, which does not exceed the largest "+
			"fixed notification (%d)", NotificationMaxSize, peerAddrChangeSize)
	}
}

// notif builds a notification buffer of the given type and length.
func notif(typ SCTPNotificationType, size int) []byte {
	b := make([]byte, size)
	if size >= 2 {
		nativeEndian.PutUint16(b[0:2], uint16(typ))
	}
	if size >= 8 {
		nativeEndian.PutUint32(b[4:8], uint32(size))
	}
	return b
}

// TestParseNotificationRejectsTruncated is the regression test for the bug this
// parser exists to avoid. free5gc's equivalent indexes b[16:20] and b[20:] with
// no length check at all, so any notification shorter than its struct panics
// inside the read path and takes the process down. Every size below one byte
// short of each struct must be rejected, not parsed.
func TestParseNotificationRejectsTruncated(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  SCTPNotificationType
		full int
	}{
		{"assoc_change", SCTP_ASSOC_CHANGE, assocChangeMinSize},
		{"peer_addr_change", SCTP_PEER_ADDR_CHANGE, peerAddrChangeSize},
		{"remote_error", SCTP_REMOTE_ERROR, remoteErrorMinSize},
		{"shutdown", SCTP_SHUTDOWN_EVENT, shutdownEventSize},
		{"adaptation", SCTP_ADAPTATION_INDICATION, adaptationIndicationSize},
		{"partial_delivery", SCTP_PARTIAL_DELIVERY_EVENT, partialDeliverySize},
		{"sender_dry", SCTP_SENDER_DRY_EVENT, senderDrySize},
		{"send_failed", SCTP_SEND_FAILED, notificationHeaderSize + 4 + int(sndRcvInfoSize) + 4},
	} {
		// Every length from empty to one short of the struct must be refused.
		for size := 0; size < tc.full; size++ {
			n, err := ParseNotification(notif(tc.typ, size))
			if !errors.Is(err, ErrShortNotification) {
				t.Errorf("%s at %d bytes: err = %v, want ErrShortNotification",
					tc.name, size, err)
			}
			if n != nil {
				t.Errorf("%s at %d bytes: returned a notification from a truncated buffer",
					tc.name, size)
			}
		}
		// The exact size must parse.
		n, err := ParseNotification(notif(tc.typ, tc.full))
		if err != nil {
			t.Errorf("%s at its full %d bytes: %v", tc.name, tc.full, err)
		}
		if n == nil {
			t.Errorf("%s at its full %d bytes: nil notification", tc.name, tc.full)
		}
	}
}

// notifSized builds a notification whose header declares one length while the
// buffer it arrived in is another, and fills everything past the header with a
// recognisable byte.
//
// notif cannot express this: it derives the declared length from the buffer
// size, so every test built on it has the two agreeing. That is precisely why
// none of them reached the bug below.
func notifSized(typ SCTPNotificationType, declared, bufSize int, fill byte) []byte {
	b := make([]byte, bufSize)
	for i := range b {
		b[i] = fill
	}
	nativeEndian.PutUint16(b[0:2], uint16(typ))
	nativeEndian.PutUint16(b[2:4], 0)
	nativeEndian.PutUint32(b[4:8], uint32(declared))
	return b
}

// TestParseNotificationBoundsByDeclaredLength checks that the length in the
// header is the authoritative extent of the event, not merely an upper bound
// checked against the buffer.
//
// The kernel sets sn_length to the whole size of the event and delivers exactly
// that many bytes: measured on a live association, SCTP_ASSOC_CHANGE arrives as
// 20 bytes declaring 20, and SCTP_PEER_ADDR_CHANGE as 148 declaring 148. So a
// buffer longer than the declared length holds bytes that are not part of this
// event — normally whatever the previous read left there, since a caller who
// passes their read buffer rather than b[:n] hands over the whole thing.
//
// Before this, ParseNotification compared length against len(b) in one
// direction only and then sliced every variable tail by len(b), so those stale
// bytes came back as event data with a nil error. Under-declaring was worse:
// nothing stopped a decoder reading fixed fields from beyond the extent its own
// header described.
func TestParseNotificationBoundsByDeclaredLength(t *testing.T) {
	t.Run("tail past the declared length is not returned", func(t *testing.T) {
		// A complete 20-byte SCTP_ASSOC_CHANGE sitting in a 64-byte read
		// buffer. Info must be empty: the event declares no sac_info.
		b := notifSized(SCTP_ASSOC_CHANGE, assocChangeMinSize, 64, 0xAA)
		nativeEndian.PutUint16(b[8:10], uint16(SCTP_COMM_UP))
		nativeEndian.PutUint16(b[10:12], 0)
		nativeEndian.PutUint16(b[12:14], 10)
		nativeEndian.PutUint16(b[14:16], 10)
		nativeEndian.PutUint32(b[16:20], 7)

		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		ac, ok := n.(*AssocChange)
		if !ok {
			t.Fatalf("got %T, want *AssocChange", n)
		}
		if len(ac.Info) != 0 {
			t.Errorf("Info = % x (%d bytes), want empty: the event declares %d bytes "+
				"and the rest of the buffer is not part of it",
				ac.Info, len(ac.Info), ac.Length())
		}
	})

	t.Run("a declared tail is still returned, exactly", func(t *testing.T) {
		// The same event declaring four bytes of sac_info, in a buffer with
		// room for far more. Bounding must not become dropping.
		b := notifSized(SCTP_ASSOC_CHANGE, assocChangeMinSize+4, 64, 0xAA)
		copy(b[assocChangeMinSize:], []byte{0xDE, 0xAD, 0xBE, 0xEF})

		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		ac := n.(*AssocChange)
		if want := []byte{0xDE, 0xAD, 0xBE, 0xEF}; string(ac.Info) != string(want) {
			t.Errorf("Info = % x, want % x", ac.Info, want)
		}
	})

	t.Run("under-declared events are refused", func(t *testing.T) {
		// A header claiming the event is 8 bytes, in a 24-byte buffer. The
		// fields after the header belong to no event, so decoding them yields
		// invented state — AssocID came back as -1 from the 0xFF fill.
		b := notifSized(SCTP_ASSOC_CHANGE, notificationHeaderSize, 24, 0xFF)
		n, err := ParseNotification(b)
		if !errors.Is(err, ErrShortNotification) {
			t.Errorf("err = %v, want ErrShortNotification", err)
		}
		if n != nil {
			ac, ok := n.(*AssocChange)
			if ok {
				t.Errorf("decoded %T from an 8-byte event: State=%d AssocID=%d, "+
					"read from bytes outside the declared extent",
					n, ac.State, ac.AssocID)
			} else {
				t.Errorf("returned %T from an under-declared event", n)
			}
		}
	})

	t.Run("a length below the header is refused", func(t *testing.T) {
		for _, declared := range []int{0, 1, 4, 7} {
			b := notifSized(SCTP_ASSOC_CHANGE, declared, 64, 0xFF)
			n, err := ParseNotification(b)
			if !errors.Is(err, ErrShortNotification) {
				t.Errorf("declared %d: err = %v, want ErrShortNotification", declared, err)
			}
			if n != nil {
				t.Errorf("declared %d: returned %T", declared, n)
			}
		}
	})

	t.Run("one byte over the buffer is refused, not panicked on", func(t *testing.T) {
		// The interesting length is exactly len(b)+1. Anything beyond it is
		// caught by a bound that is wrong by any amount, so an off-by-one in
		// the comparison survives a test that only over-declares wildly — and
		// an off-by-one here does not merely mis-parse, it reslices past the
		// end of the buffer and panics in the caller's read loop.
		//
		// The exact length must still parse, or the bound has moved the other
		// way and every complete notification is rejected.
		const buf = 64
		for _, declared := range []int{buf + 1, buf + 2, buf + 8, 65516} {
			b := notifSized(SCTP_ASSOC_CHANGE, declared, buf, 0xFF)
			n, err := ParseNotification(b)
			if !errors.Is(err, ErrShortNotification) {
				t.Errorf("declared %d with %d present: err = %v, want ErrShortNotification",
					declared, buf, err)
			}
			if n != nil {
				t.Errorf("declared %d with %d present: returned %T", declared, buf, n)
			}
		}
		b := notifSized(SCTP_ASSOC_CHANGE, buf, buf, 0)
		if _, err := ParseNotification(b); err != nil {
			t.Errorf("declared %d with %d present: %v, want it to parse", buf, buf, err)
		}
	})

	t.Run("the stream list stops at the declared length", func(t *testing.T) {
		// srs_stream_list is a flexible array member, so only the declared
		// length says how many ids are really there. Bounding it by the buffer
		// invents one id per two spare bytes.
		b := notifSized(SCTP_STREAM_RESET_EVENT, streamResetMinSize+2, 24, 0xEE)
		nativeEndian.PutUint32(b[8:12], 3)
		nativeEndian.PutUint16(b[streamResetMinSize:], 1)

		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		sr := n.(*StreamReset)
		if len(sr.Streams) != 1 || sr.Streams[0] != 1 {
			t.Errorf("Streams = %v, want [1]: the event declares one stream id "+
				"and the remaining %d buffer bytes are not part of it",
				sr.Streams, 24-(streamResetMinSize+2))
		}
	})

	t.Run("every variable tail is bounded", func(t *testing.T) {
		// One case per decoder that carries a tail, each complete and each in a
		// buffer with slack behind it.
		for _, tc := range []struct {
			name string
			typ  SCTPNotificationType
			size int
			tail func(Notification) int
		}{
			{"assoc_change", SCTP_ASSOC_CHANGE, assocChangeMinSize,
				func(n Notification) int { return len(n.(*AssocChange).Info) }},
			{"remote_error", SCTP_REMOTE_ERROR, remoteErrorMinSize,
				func(n Notification) int { return len(n.(*RemoteError).Data) }},
			{"send_failed", SCTP_SEND_FAILED, notificationHeaderSize + 4 + int(sndRcvInfoSize) + 4,
				func(n Notification) int { return len(n.(*SendFailed).Data) }},
			{"send_failed_event", SCTP_SEND_FAILED_EVENT, sendFailedEventMinSize,
				func(n Notification) int { return len(n.(*SendFailedEvent).Data) }},
		} {
			b := notifSized(tc.typ, tc.size, tc.size+40, 0xAA)
			n, err := ParseNotification(b)
			if err != nil {
				t.Errorf("%s: ParseNotification: %v", tc.name, err)
				continue
			}
			if got := tc.tail(n); got != 0 {
				t.Errorf("%s: tail = %d bytes, want 0: the event declares %d bytes "+
					"and the buffer holds %d", tc.name, got, tc.size, tc.size+40)
			}
		}
	})
}

// TestParseNotificationAssocChange checks the fields land in the right places.
// A wrong offset reads a neighbouring field and looks entirely plausible, so
// each value here is distinct.
func TestParseNotificationAssocChange(t *testing.T) {
	b := notif(SCTP_ASSOC_CHANGE, assocChangeMinSize+4)
	nativeEndian.PutUint16(b[2:4], 0x1111)                  // flags
	nativeEndian.PutUint16(b[8:10], uint16(SCTP_COMM_LOST)) // state
	nativeEndian.PutUint16(b[10:12], 0x2222)                // error
	nativeEndian.PutUint16(b[12:14], 0x3333)                // outbound
	nativeEndian.PutUint16(b[14:16], 0x4444)                // inbound
	nativeEndian.PutUint32(b[16:20], 0x55555555)            // assoc id
	copy(b[20:], []byte{0xAA, 0xBB, 0xCC, 0xDD})            // info

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	ac, ok := n.(*AssocChange)
	if !ok {
		t.Fatalf("got %T, want *AssocChange", n)
	}
	if ac.Type() != SCTP_ASSOC_CHANGE {
		t.Errorf("Type = %v, want SCTP_ASSOC_CHANGE", ac.Type())
	}
	if ac.Flags() != 0x1111 {
		t.Errorf("Flags = %#x, want 0x1111", ac.Flags())
	}
	if ac.State != SCTP_COMM_LOST {
		t.Errorf("State = %v, want SCTP_COMM_LOST", ac.State)
	}
	if ac.Error != 0x2222 {
		t.Errorf("Error = %#x, want 0x2222", ac.Error)
	}
	if ac.OutboundStreams != 0x3333 {
		t.Errorf("OutboundStreams = %#x, want 0x3333", ac.OutboundStreams)
	}
	if ac.InboundStreams != 0x4444 {
		t.Errorf("InboundStreams = %#x, want 0x4444", ac.InboundStreams)
	}
	if ac.AssocID != SCTPAssocID(0x55555555) {
		t.Errorf("AssocID = %#x, want 0x55555555", ac.AssocID)
	}
	if string(ac.Info) != string([]byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Errorf("Info = % x, want aa bb cc dd", ac.Info)
	}
}

// TestParseNotificationCopiesTrailingData guards against aliasing the caller's
// read buffer. The buffer is reused by the next read, so a notification that
// held a slice of it would silently change contents afterwards.
func TestParseNotificationCopiesTrailingData(t *testing.T) {
	b := notif(SCTP_ASSOC_CHANGE, assocChangeMinSize+4)
	copy(b[20:], []byte{1, 2, 3, 4})

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	ac := n.(*AssocChange)

	// Simulate the buffer being reused for the next read.
	for i := range b {
		b[i] = 0xFF
	}

	if string(ac.Info) != string([]byte{1, 2, 3, 4}) {
		t.Errorf("Info = % x after the read buffer was reused, want 01 02 03 04 "+
			"(the parser aliased the caller's buffer instead of copying)", ac.Info)
	}
}

// TestParseNotificationPartialDeliveryFieldOrder pins the field order the
// kernel actually uses. RFC 6458 lists pdapi_stream before pdapi_assoc_id, but
// struct sctp_pdapi_event places assoc_id at offset 12 and stream at 16.
// Following the RFC ordering here reads the two transposed, which is a wrong
// value rather than an error.
func TestParseNotificationPartialDeliveryFieldOrder(t *testing.T) {
	b := notif(SCTP_PARTIAL_DELIVERY_EVENT, partialDeliverySize)
	nativeEndian.PutUint32(b[8:12], 0x11111111)  // indication
	nativeEndian.PutUint32(b[12:16], 0x22222222) // assoc id
	nativeEndian.PutUint32(b[16:20], 0x33333333) // stream
	nativeEndian.PutUint32(b[20:24], 0x44444444) // seq

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	pd := n.(*PartialDelivery)
	if pd.Indication != 0x11111111 {
		t.Errorf("Indication = %#x, want 0x11111111", pd.Indication)
	}
	if pd.AssocID != SCTPAssocID(0x22222222) {
		t.Errorf("AssocID = %#x, want 0x22222222 (kernel puts assoc_id at offset 12)", pd.AssocID)
	}
	if pd.StreamID != 0x33333333 {
		t.Errorf("StreamID = %#x, want 0x33333333 (kernel puts stream at offset 16)", pd.StreamID)
	}
	if pd.SeqNum != 0x44444444 {
		t.Errorf("SeqNum = %#x, want 0x44444444", pd.SeqNum)
	}
}

// TestParseNotificationPeerAddrChange covers the notification that reports a
// path going unreachable, which is the event a caller watches for to detect a
// peer that has silently gone away.
func TestParseNotificationPeerAddrChange(t *testing.T) {
	b := notif(SCTP_PEER_ADDR_CHANGE, peerAddrChangeSize)
	b[8] = 0x02 // first byte of the embedded sockaddr
	nativeEndian.PutUint32(b[136:140], SCTP_ADDR_UNREACHABLE)
	nativeEndian.PutUint32(b[140:144], 0x66666666)
	nativeEndian.PutUint32(b[144:148], 0x77777777)

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	pac := n.(*PeerAddrChange)
	if pac.State != SCTP_ADDR_UNREACHABLE {
		t.Errorf("State = %d, want SCTP_ADDR_UNREACHABLE (%d)", pac.State, SCTP_ADDR_UNREACHABLE)
	}
	if pac.Error != 0x66666666 {
		t.Errorf("Error = %#x, want 0x66666666", pac.Error)
	}
	if pac.AssocID != SCTPAssocID(0x77777777) {
		t.Errorf("AssocID = %#x, want 0x77777777", pac.AssocID)
	}
	if pac.Addr[0] != 0x02 {
		t.Errorf("Addr[0] = %#x, want 0x02", pac.Addr[0])
	}
}

// TestParseNotificationUnknownType checks an event this package does not model
// is reported as unknown rather than as an error, since the kernel may add
// notification types.
func TestParseNotificationUnknownType(t *testing.T) {
	b := notif(SCTPNotificationType(0x7FFF), 64)
	n, err := ParseNotification(b)
	if err != nil {
		t.Errorf("unknown type returned error %v, want nil", err)
	}
	if n != nil {
		t.Errorf("unknown type returned %T, want nil", n)
	}
}

// FuzzParseNotification asserts the parser never panics. It is reachable
// directly from bytes off the wire, so a panic here is a remote crash.
//
// The fuzzer drives the notification type through a separate uint16 argument
// rather than leaving it in the byte slice. Left in the slice, the mutator
// almost never produces an input that is both a recognised type and short
// enough to overflow, so a parser missing its length checks survives millions
// of executions: removing the guard and fuzzing for 30s found nothing, while
// TestParseNotificationRejectsTruncated fails immediately. Splitting the type
// out makes every length of every known type reachable.
func FuzzParseNotification(f *testing.F) {
	types := []SCTPNotificationType{
		SCTP_ASSOC_CHANGE, SCTP_PEER_ADDR_CHANGE, SCTP_REMOTE_ERROR,
		SCTP_SEND_FAILED, SCTP_SHUTDOWN_EVENT, SCTP_ADAPTATION_INDICATION,
		SCTP_PARTIAL_DELIVERY_EVENT, SCTP_SENDER_DRY_EVENT,
		SCTP_AUTHENTICATION_EVENT, SCTP_STREAM_RESET_EVENT,
		SCTP_ASSOC_RESET_EVENT, SCTP_STREAM_CHANGE_EVENT,
		SCTP_SEND_FAILED_EVENT,
	}
	for _, typ := range types {
		// Seed each type at a few lengths either side of its struct.
		for _, size := range []int{0, 8, 11, 12, 13, 15, 16, 20, 24, 31, 32, 33, 48, 148} {
			f.Add(uint16(typ), notif(typ, size))
		}
	}
	f.Add(uint16(0), []byte{})
	f.Add(uint16(0xFFFF), []byte{0x01})

	f.Fuzz(func(t *testing.T, typ uint16, body []byte) {
		// Stamp the type over the header so the fuzzer reaches every branch
		// instead of bouncing off the unknown-type case.
		b := body
		if len(b) >= 2 {
			b = append([]byte(nil), body...)
			nativeEndian.PutUint16(b[0:2], typ)
		}

		n, err := ParseNotification(b)
		if err != nil && n != nil {
			t.Fatalf("returned both a notification (%T) and an error (%v)", n, err)
		}
		if n == nil {
			return
		}
		// A notification must never be returned from a buffer too short to
		// hold it: that is the read-past-the-end this parser exists to avoid.
		if len(b) < notificationHeaderSize {
			t.Fatalf("parsed %T from %d bytes, shorter than the header", n, len(b))
		}
		// The accessors must not panic either.
		_, _, _ = n.Type(), n.Flags(), n.Length()
	})
}
