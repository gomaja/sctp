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
