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
	"encoding/binary"
	"errors"
	"fmt"
)

// Notification is an event delivered on the data stream when a message is read
// with MSG_NOTIFICATION set in its flags, as described in RFC 6458 section 6.
//
// Notifications are only delivered for events the socket is subscribed to; see
// SubscribeEvents.
type Notification interface {
	// Type reports which notification this is.
	Type() SCTPNotificationType
	// Flags are the notification's type-specific flags.
	Flags() uint16
	// Length is the length the kernel declared for the notification. It may
	// exceed the bytes actually received if the read buffer was too small.
	Length() uint32
}

// ErrShortNotification is returned by ParseNotification when the buffer holds
// fewer bytes than the notification declares itself to be.
//
// A notification read into an undersized buffer arrives split, and what follows
// is not dropped. Measured by reading a 24 byte SCTP_ASSOC_CHANGE with an 8 byte
// buffer: three reads, every one of them flagged MSG_NOTIFICATION, with MSG_EOR
// set only on the last. So the continuation fragments look like fresh
// notifications to anything that only tests the flag — and a fragment whose
// first two bytes happen to match a known type would decode into an event
// assembled from the middle of another one.
//
// Read with a buffer of at least NotificationMaxSize, and treat a fragment
// without MSG_EOR as incomplete rather than as an event.
var ErrShortNotification = errors.New("sctp: notification truncated")

// NotificationMaxSize is a read buffer size that holds any fixed-size
// notification this package parses.
//
// It is not a bound on every notification. SCTP_SEND_FAILED,
// SCTP_SEND_FAILED_EVENT and SCTP_REMOTE_ERROR carry a variable tail — the
// undelivered message, or the peer's ERROR chunk — so their size follows the
// data rather than the struct, and a failed 64 KiB send produces an event far
// larger than this. Those are the reads that come back split, and
// ParseNotification reports them as ErrShortNotification rather than as a
// complete event with a short tail.
const NotificationMaxSize = 1024

// notificationHeaderSize is the common prefix every notification shares:
// uint16 type, uint16 flags, uint32 length.
const notificationHeaderSize = 8

// Error cause codes, RFC 9260 section 3.3.10, as carried by AssocChange.Error,
// RemoteError.Error and SendFailed.Error.
//
// These are the values the peer puts in an ERROR or ABORT chunk, so they answer
// "why did this association fail" — the question those three notifications
// exist to answer. Codes 11 to 14 are not in the base specification's table;
// they come from the Implementation Guide and from RFC 6951, and Linux both
// sends and reports them.
//
// They are deliberately untyped, so that comparing them against Error works
// whether the field is a uint16 or a uint32.
const (
	SCTP_ERROR_NO_ERROR           = 0x00
	SCTP_ERROR_INV_STRM           = 0x01  // Invalid Stream Identifier
	SCTP_ERROR_MISS_PARAM         = 0x02  // Missing Mandatory Parameter
	SCTP_ERROR_STALE_COOKIE       = 0x03  // Stale Cookie
	SCTP_ERROR_NO_RESOURCE        = 0x04  // Out of Resource
	SCTP_ERROR_DNS_FAILED         = 0x05  // Unresolvable Address
	SCTP_ERROR_UNKNOWN_CHUNK      = 0x06  // Unrecognized Chunk Type
	SCTP_ERROR_INV_PARAM          = 0x07  // Invalid Mandatory Parameter
	SCTP_ERROR_UNKNOWN_PARAM      = 0x08  // Unrecognized Parameters
	SCTP_ERROR_NO_DATA            = 0x09  // No User Data
	SCTP_ERROR_COOKIE_IN_SHUTDOWN = 0x0a  // Cookie Received While Shutting Down
	SCTP_ERROR_RESTART            = 0x0b  // Restart with New Addresses
	SCTP_ERROR_USER_ABORT         = 0x0c  // User Initiated Abort
	SCTP_ERROR_PROTO_VIOLATION    = 0x0d  // Protocol Violation
	SCTP_ERROR_NEW_ENCAP_PORT     = 0x0e  // Restart with New Encapsulation Port
	SCTP_ERROR_DEL_LAST_IP        = 0xa0  // Delete Last Remaining Address (RFC 5061)
	SCTP_ERROR_RSRC_LOW           = 0xa1  // Operation Refused Due to Resources
	SCTP_ERROR_DEL_SRC_IP         = 0xa2  // Delete Source IP Address (RFC 5061)
	SCTP_ERROR_ASCONF_ACK         = 0xa3  // Association Aborted due to ASCONF-ACK
	SCTP_ERROR_REQ_REFUSED        = 0xa4  // Request Refused - No Authorization
	SCTP_ERROR_UNSUP_HMAC         = 0x105 // Unsupported HMAC Identifier (RFC 4895)
)

// errorCauseNames is only consulted by ErrorCauseString, which is the sole
// reason the vocabulary is worth carrying at all: a bare number in a log is
// what made the byte-order defect below survive as long as it did.
var errorCauseNames = map[uint32]string{
	SCTP_ERROR_NO_ERROR:           "SCTP_ERROR_NO_ERROR",
	SCTP_ERROR_INV_STRM:           "SCTP_ERROR_INV_STRM",
	SCTP_ERROR_MISS_PARAM:         "SCTP_ERROR_MISS_PARAM",
	SCTP_ERROR_STALE_COOKIE:       "SCTP_ERROR_STALE_COOKIE",
	SCTP_ERROR_NO_RESOURCE:        "SCTP_ERROR_NO_RESOURCE",
	SCTP_ERROR_DNS_FAILED:         "SCTP_ERROR_DNS_FAILED",
	SCTP_ERROR_UNKNOWN_CHUNK:      "SCTP_ERROR_UNKNOWN_CHUNK",
	SCTP_ERROR_INV_PARAM:          "SCTP_ERROR_INV_PARAM",
	SCTP_ERROR_UNKNOWN_PARAM:      "SCTP_ERROR_UNKNOWN_PARAM",
	SCTP_ERROR_NO_DATA:            "SCTP_ERROR_NO_DATA",
	SCTP_ERROR_COOKIE_IN_SHUTDOWN: "SCTP_ERROR_COOKIE_IN_SHUTDOWN",
	SCTP_ERROR_RESTART:            "SCTP_ERROR_RESTART",
	SCTP_ERROR_USER_ABORT:         "SCTP_ERROR_USER_ABORT",
	SCTP_ERROR_PROTO_VIOLATION:    "SCTP_ERROR_PROTO_VIOLATION",
	SCTP_ERROR_NEW_ENCAP_PORT:     "SCTP_ERROR_NEW_ENCAP_PORT",
	SCTP_ERROR_DEL_LAST_IP:        "SCTP_ERROR_DEL_LAST_IP",
	SCTP_ERROR_RSRC_LOW:           "SCTP_ERROR_RSRC_LOW",
	SCTP_ERROR_DEL_SRC_IP:         "SCTP_ERROR_DEL_SRC_IP",
	SCTP_ERROR_ASCONF_ACK:         "SCTP_ERROR_ASCONF_ACK",
	SCTP_ERROR_REQ_REFUSED:        "SCTP_ERROR_REQ_REFUSED",
	SCTP_ERROR_UNSUP_HMAC:         "SCTP_ERROR_UNSUP_HMAC",
}

// ErrorCauseString names an RFC 9260 section 3.3.10 error cause.
func ErrorCauseString(cause uint32) string {
	if name, ok := errorCauseNames[cause]; ok {
		return name
	}
	return fmt.Sprintf("SCTPErrorCause(%d)", cause)
}

// causeFromU16 decodes an error cause the kernel stored in a __u16.
//
// The kernel's cause constants are declared cpu_to_be16, and every path that
// fills sac_error and sre_error assigns one of them — or, for a received ABORT
// or ERROR, the __be16 straight off the wire — into a host-typed field without
// converting. So the two bytes in the buffer are always the network
// representation regardless of the host's byte order, and reading them big-endian
// is right everywhere.
//
// Decoding them natively is what this package used to do, and on a little-endian
// host it reported SCTP_ERROR_USER_ABORT as 3072 rather than 12. Note that the
// kernel's own uapi header points the wrong way here: it documents sac_error as
// holding an sctp_sn_error_t, a small host-order enum. That is true of
// spc_error, which is why PeerAddrChange.Error is still read natively, but no
// path in the stack puts one in sac_error.
func causeFromU16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

// causeFromU32 decodes an error cause the kernel widened into a __u32.
//
// ssf_error is __u32 but holds the same cpu_to_be16 constant, widened by an
// ordinary integer promotion. The promotion happens in host arithmetic, so
// unlike the __u16 case the bytes are not simply the network form: on a
// little-endian host the value 0x0c00 lands in the low half. Reading the field
// natively and then undoing the byte order recovers the cause on both.
func causeFromU32(b []byte) uint32 {
	return uint32(ntohs(uint16(nativeEndian.Uint32(b))))
}

// AssocChange is SCTP_ASSOC_CHANGE (RFC 6458 6.1.1), reporting that an
// association has come up, come down, restarted, or failed to start. State
// says which.
type AssocChange struct {
	typ    uint16
	flags  uint16
	length uint32
	State  SCTPState
	// Error is an RFC 9260 section 3.3.10 error cause, in host byte order —
	// see ErrorCauseString. It is meaningful when State is SCTP_COMM_LOST or
	// SCTP_CANT_STR_ASSOC and zero otherwise.
	Error           uint16
	OutboundStreams uint16
	InboundStreams  uint16
	AssocID         SCTPAssocID
	// Info carries any additional data the kernel appended, most usefully the
	// ABORT chunk when State is SCTP_COMM_LOST.
	Info []byte
}

func (n *AssocChange) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *AssocChange) Flags() uint16              { return n.flags }
func (n *AssocChange) Length() uint32             { return n.length }

// assocChangeMinSize is sizeof(struct sctp_assoc_change) without sac_info.
const assocChangeMinSize = 20

// PeerAddrChange is SCTP_PEER_ADDR_CHANGE (RFC 6458 6.1.2), reporting that one
// of the peer's addresses has changed reachability. This is the notification
// that reports a path going unreachable before the association as a whole
// fails; see testdata/BLACKHOLE.md.
type PeerAddrChange struct {
	typ    uint16
	flags  uint16
	length uint32
	// Addr is the raw sockaddr_storage of the affected peer address.
	Addr    [128]byte
	State   uint32
	Error   uint32
	AssocID SCTPAssocID
}

func (n *PeerAddrChange) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *PeerAddrChange) Flags() uint16              { return n.flags }
func (n *PeerAddrChange) Length() uint32             { return n.length }

// Peer address change states, from the kernel's enum sctp_spc_state. These are
// distinct from PeerState, which GetStatus reports.
const (
	SCTP_ADDR_AVAILABLE = iota
	SCTP_ADDR_UNREACHABLE
	SCTP_ADDR_REMOVED
	SCTP_ADDR_ADDED
	SCTP_ADDR_MADE_PRIM
	SCTP_ADDR_CONFIRMED
	// SCTP_ADDR_POTENTIALLY_FAILED is RFC 7829's early warning: the path has
	// missed enough retransmissions to be suspect but not enough to be
	// unreachable. The kernel suppresses it unless SetExposePotentiallyFailed
	// is on, which is why it is easy to conclude the state does not exist.
	SCTP_ADDR_POTENTIALLY_FAILED
)

// peerAddrChangeSize is sizeof(struct sctp_paddr_change): 8 byte header,
// 128 byte sockaddr_storage, then two uint32 and the association id.
const peerAddrChangeSize = 8 + 128 + 4 + 4 + 4

// RemoteError is SCTP_REMOTE_ERROR (RFC 6458 6.1.3), delivering an ERROR chunk
// the peer sent.
type RemoteError struct {
	typ     uint16
	flags   uint16
	length  uint32
	Error   uint16
	AssocID SCTPAssocID
	// Data is the body of the peer's ERROR chunk.
	Data []byte
}

func (n *RemoteError) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *RemoteError) Flags() uint16              { return n.flags }
func (n *RemoteError) Length() uint32             { return n.length }

// remoteErrorMinSize is sizeof(struct sctp_remote_error) without sre_data.
// The kernel pads sre_assoc_id to a 4 byte boundary after sre_error.
const remoteErrorMinSize = 16

// SendFailed is SCTP_SEND_FAILED (RFC 6458 6.1.4), reporting a message that
// could not be delivered. The undelivered message is returned in Data.
type SendFailed struct {
	typ    uint16
	flags  uint16
	length uint32
	Error  uint32
	// Info is the send parameters the failed message carried.
	//
	// Info.PPID is in network byte order, as the kernel delivered it. That is
	// what SndRcvInfo.PPID documents, but it differs from what SCTPRead hands
	// back for the same type: SCTPRead converts, and this does not. A caller
	// comparing it against a locally held identifier needs ntohl, or the
	// comparison silently never matches.
	Info    SndRcvInfo
	AssocID SCTPAssocID
	// Data is the message that was not delivered.
	Data []byte
}

func (n *SendFailed) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *SendFailed) Flags() uint16              { return n.flags }
func (n *SendFailed) Length() uint32             { return n.length }

// Shutdown is SCTP_SHUTDOWN_EVENT (RFC 6458 6.1.5), reporting that the peer has
// shut the association down and will accept no further data.
type Shutdown struct {
	typ     uint16
	flags   uint16
	length  uint32
	AssocID SCTPAssocID
}

func (n *Shutdown) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *Shutdown) Flags() uint16              { return n.flags }
func (n *Shutdown) Length() uint32             { return n.length }

// shutdownEventSize is sizeof(struct sctp_shutdown_event).
const shutdownEventSize = 12

// AdaptationIndication is SCTP_ADAPTATION_INDICATION (RFC 6458 6.1.6),
// carrying the peer's adaptation layer indication.
type AdaptationIndication struct {
	typ           uint16
	flags         uint16
	length        uint32
	AdaptationInd uint32
	AssocID       SCTPAssocID
}

func (n *AdaptationIndication) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *AdaptationIndication) Flags() uint16              { return n.flags }
func (n *AdaptationIndication) Length() uint32             { return n.length }

const adaptationIndicationSize = 16

// SenderDry is SCTP_SENDER_DRY_EVENT (RFC 6458 6.1.9), reporting that the
// stack has no more user data to send and none outstanding. It is the
// authoritative signal that everything written has been acknowledged.
type SenderDry struct {
	typ     uint16
	flags   uint16
	length  uint32
	AssocID SCTPAssocID
}

func (n *SenderDry) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *SenderDry) Flags() uint16              { return n.flags }
func (n *SenderDry) Length() uint32             { return n.length }

const senderDrySize = 12

// PartialDelivery is SCTP_PARTIAL_DELIVERY_EVENT (RFC 6458 6.1.7), reporting
// that a partially delivered message was aborted.
type PartialDelivery struct {
	typ        uint16
	flags      uint16
	length     uint32
	Indication uint32
	StreamID   uint32
	SeqNum     uint32
	AssocID    SCTPAssocID
}

func (n *PartialDelivery) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *PartialDelivery) Flags() uint16              { return n.flags }
func (n *PartialDelivery) Length() uint32             { return n.length }

const partialDeliverySize = 24

// Flags reported by StreamReset, AssocReset and StreamChange.
//
// DENIED means the peer refused the request; FAILED means it could not be
// carried out. Either way the request did not take effect, which is the whole
// reason these events matter: ResetStreams and AddStreams return as soon as the
// request is away, so success there means "sent", not "done".
const (
	SCTP_STREAM_RESET_INCOMING_SSN = 0x0001
	SCTP_STREAM_RESET_OUTGOING_SSN = 0x0002
	SCTP_STREAM_RESET_DENIED       = 0x0004
	SCTP_STREAM_RESET_FAILED       = 0x0008

	SCTP_ASSOC_RESET_DENIED = 0x0004
	SCTP_ASSOC_RESET_FAILED = 0x0008

	SCTP_STREAM_CHANGE_DENIED = 0x0004
	SCTP_STREAM_CHANGE_FAILED = 0x0008
)

// Indications reported by AuthKeyEvent.
const (
	SCTP_AUTH_NEW_KEY  = iota // a new shared key is usable
	SCTP_AUTH_FREE_KEY        // a key has been released and will not be used again
	SCTP_AUTH_NO_AUTH         // the peer does not support AUTH
)

// Flags reported by SendFailed and SendFailedEvent, saying how far the
// undelivered message got.
const (
	SCTP_DATA_UNSENT = iota // never put on the wire
	SCTP_DATA_SENT          // transmitted, but not acknowledged
)

// StreamReset is SCTP_STREAM_RESET_EVENT (RFC 6525 §6.1.1), reporting the
// outcome of a stream reset — this side's or the peer's.
//
// This is the answer to ResetStreams, which only reports that the request was
// sent. Check Flags for SCTP_STREAM_RESET_DENIED and SCTP_STREAM_RESET_FAILED.
type StreamReset struct {
	typ     uint16
	flags   uint16
	length  uint32
	AssocID SCTPAssocID
	// Streams are the stream identifiers the event covers. Empty means all of
	// them, which is how the kernel reports a request made with no list.
	Streams []uint16
}

func (n *StreamReset) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *StreamReset) Flags() uint16              { return n.flags }
func (n *StreamReset) Length() uint32             { return n.length }

// streamResetMinSize is sizeof(struct sctp_stream_reset_event) without the
// flexible strreset_stream_list.
const streamResetMinSize = 12

// AssocReset is SCTP_ASSOC_RESET_EVENT (RFC 6525 §6.1.2), reporting the outcome
// of an association reset and the TSNs the two sides restarted from.
type AssocReset struct {
	typ       uint16
	flags     uint16
	length    uint32
	AssocID   SCTPAssocID
	LocalTSN  uint32
	RemoteTSN uint32
}

func (n *AssocReset) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *AssocReset) Flags() uint16              { return n.flags }
func (n *AssocReset) Length() uint32             { return n.length }

// assocResetSize is sizeof(struct sctp_assoc_reset_event).
const assocResetSize = 20

// StreamChange is SCTP_STREAM_CHANGE_EVENT (RFC 6525 §6.1.3), reporting the
// stream counts in force after an AddStreams request.
type StreamChange struct {
	typ            uint16
	flags          uint16
	length         uint32
	AssocID        SCTPAssocID
	InboundStreams uint16
	// OutboundStreams is the count that matters to a sender: writing to a
	// stream at or above it fails, whatever AddStreams reported.
	OutboundStreams uint16
}

func (n *StreamChange) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *StreamChange) Flags() uint16              { return n.flags }
func (n *StreamChange) Length() uint32             { return n.length }

// streamChangeSize is sizeof(struct sctp_stream_change_event).
const streamChangeSize = 16

// SendFailedEvent is SCTP_SEND_FAILED_EVENT (RFC 6458 §6.1.11), the replacement
// for SCTP_SEND_FAILED.
//
// It carries SndInfo where the older event carries the deprecated SndRcvInfo,
// and it is the one RFC 6458 §6.1.4 tells new code to subscribe to. Both
// describe the same failure, so a socket subscribed to both sees it twice.
type SendFailedEvent struct {
	typ    uint16
	flags  uint16
	length uint32
	// Error is an RFC 9260 section 3.3.10 error cause; see ErrorCauseString.
	Error uint32
	// Info is the send parameters the failed message carried. As with
	// SendFailed.Info, Info.PPID is in network byte order — the kernel passes
	// the identifier through untouched in both directions, and only SCTPRead
	// converts. Compare it with ntohl.
	Info    SndInfo
	AssocID SCTPAssocID
	// Data is the message that was not delivered.
	Data []byte
}

func (n *SendFailedEvent) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *SendFailedEvent) Flags() uint16              { return n.flags }
func (n *SendFailedEvent) Length() uint32             { return n.length }

// sendFailedEventMinSize is sizeof(struct sctp_send_failed_event) without
// ssf_data: 8 byte header, uint32 error, 16 byte sctp_sndinfo, association id.
const sendFailedEventMinSize = 32

// AuthKeyEvent is SCTP_AUTHENTICATION_EVENT (RFC 6458 §6.1.8), reporting a
// change in the AUTH shared keys in force.
//
// It is what makes key rollover observable: DeactivateAuthKey and
// DeleteAuthKey act locally, and only SCTP_AUTH_FREE_KEY says the peer has
// stopped using the old one.
type AuthKeyEvent struct {
	typ          uint16
	flags        uint16
	length       uint32
	KeyNumber    uint16
	AltKeyNumber uint16
	// Indication is SCTP_AUTH_NEW_KEY, SCTP_AUTH_FREE_KEY or SCTP_AUTH_NO_AUTH.
	Indication uint32
	AssocID    SCTPAssocID
}

func (n *AuthKeyEvent) Type() SCTPNotificationType { return SCTPNotificationType(n.typ) }
func (n *AuthKeyEvent) Flags() uint16              { return n.flags }
func (n *AuthKeyEvent) Length() uint32             { return n.length }

// authKeyEventSize is sizeof(struct sctp_authkey_event).
const authKeyEventSize = 20

// String names the association state an AssocChange reports. SCTP_COMM_LOST is
// the one that surfaces an unreachable peer: the association failed, either
// because the peer aborted it or because it exhausted its retransmission
// budget.
func (s SCTPState) String() string {
	switch s {
	case SCTP_COMM_UP:
		return "SCTP_COMM_UP"
	case SCTP_COMM_LOST:
		return "SCTP_COMM_LOST"
	case SCTP_RESTART:
		return "SCTP_RESTART"
	case SCTP_SHUTDOWN_COMP:
		return "SCTP_SHUTDOWN_COMP"
	case SCTP_CANT_STR_ASSOC:
		return "SCTP_CANT_STR_ASSOC"
	}
	return fmt.Sprintf("SCTPState(%d)", uint16(s))
}

// ParseNotification decodes a notification from bytes read with
// MSG_NOTIFICATION set in the flags, as returned by SCTPReadFlags or handed to
// a NotificationHandler.
//
// It returns ErrShortNotification if b is too short for the notification it
// declares itself to be, rather than reading past the end of the buffer: a
// notification read into an undersized buffer arrives truncated, and the
// length in its header describes the whole event, not the bytes present.
//
// An unrecognised notification type returns a nil Notification and a nil
// error, since new event types may be added by the kernel.
func ParseNotification(b []byte) (Notification, error) {
	if len(b) < notificationHeaderSize {
		return nil, ErrShortNotification
	}
	typ := nativeEndian.Uint16(b[0:2])
	flags := nativeEndian.Uint16(b[2:4])
	length := nativeEndian.Uint32(b[4:8])

	// The header says how long the whole event is; b is what actually arrived.
	// Without this the two were never compared, so a notification split across
	// reads — which is what happens whenever the buffer is smaller than the
	// event, and unavoidable for the ones carrying a variable tail — decoded
	// from its first fragment and came back with a nil error and a short tail.
	// A caller reading Data then saw a truncated message it had no way to know
	// was truncated. Measured: a header declaring 65516 bytes with 20 present
	// returned an AssocChange reporting Length() == 65516 and no error.
	if length > uint32(len(b)) {
		return nil, ErrShortNotification
	}

	switch SCTPNotificationType(typ) {
	case SCTP_ASSOC_CHANGE:
		if len(b) < assocChangeMinSize {
			return nil, ErrShortNotification
		}
		n := &AssocChange{
			typ:             typ,
			flags:           flags,
			length:          length,
			State:           SCTPState(nativeEndian.Uint16(b[8:10])),
			Error:           causeFromU16(b[10:12]),
			OutboundStreams: nativeEndian.Uint16(b[12:14]),
			InboundStreams:  nativeEndian.Uint16(b[14:16]),
			AssocID:         SCTPAssocID(nativeEndian.Uint32(b[16:20])),
		}
		// Copy rather than alias: b is the caller's read buffer and will be
		// reused by the next read.
		if len(b) > assocChangeMinSize {
			n.Info = append([]byte(nil), b[assocChangeMinSize:]...)
		}
		return n, nil

	case SCTP_PEER_ADDR_CHANGE:
		if len(b) < peerAddrChangeSize {
			return nil, ErrShortNotification
		}
		n := &PeerAddrChange{
			typ:     typ,
			flags:   flags,
			length:  length,
			State:   nativeEndian.Uint32(b[136:140]),
			Error:   nativeEndian.Uint32(b[140:144]),
			AssocID: SCTPAssocID(nativeEndian.Uint32(b[144:148])),
		}
		copy(n.Addr[:], b[8:136])
		return n, nil

	case SCTP_REMOTE_ERROR:
		if len(b) < remoteErrorMinSize {
			return nil, ErrShortNotification
		}
		n := &RemoteError{
			typ:     typ,
			flags:   flags,
			length:  length,
			Error:   causeFromU16(b[8:10]),
			AssocID: SCTPAssocID(nativeEndian.Uint32(b[12:16])),
		}
		if len(b) > remoteErrorMinSize {
			n.Data = append([]byte(nil), b[remoteErrorMinSize:]...)
		}
		return n, nil

	case SCTP_SEND_FAILED:
		// 8 byte header, uint32 error, SndRcvInfo, then the association id.
		minSize := notificationHeaderSize + 4 + int(sndRcvInfoSize) + 4
		if len(b) < minSize {
			return nil, ErrShortNotification
		}
		n := &SendFailed{
			typ:    typ,
			flags:  flags,
			length: length,
			Error:  causeFromU32(b[8:12]),
		}
		infoEnd := 12 + int(sndRcvInfoSize)
		if err := binary.Read(bytes.NewReader(b[12:infoEnd]), nativeEndian, &n.Info); err != nil {
			return nil, err
		}
		n.AssocID = SCTPAssocID(nativeEndian.Uint32(b[infoEnd : infoEnd+4]))
		if len(b) > minSize {
			n.Data = append([]byte(nil), b[minSize:]...)
		}
		return n, nil

	case SCTP_SHUTDOWN_EVENT:
		if len(b) < shutdownEventSize {
			return nil, ErrShortNotification
		}
		return &Shutdown{
			typ:     typ,
			flags:   flags,
			length:  length,
			AssocID: SCTPAssocID(nativeEndian.Uint32(b[8:12])),
		}, nil

	case SCTP_ADAPTATION_INDICATION:
		if len(b) < adaptationIndicationSize {
			return nil, ErrShortNotification
		}
		return &AdaptationIndication{
			typ:           typ,
			flags:         flags,
			length:        length,
			AdaptationInd: nativeEndian.Uint32(b[8:12]),
			AssocID:       SCTPAssocID(nativeEndian.Uint32(b[12:16])),
		}, nil

	case SCTP_PARTIAL_DELIVERY_EVENT:
		if len(b) < partialDeliverySize {
			return nil, ErrShortNotification
		}
		// Field order here is not the order the fields are declared in RFC
		// 6458: the kernel places pdapi_assoc_id before pdapi_stream. Verified
		// against struct sctp_pdapi_event.
		return &PartialDelivery{
			typ:        typ,
			flags:      flags,
			length:     length,
			Indication: nativeEndian.Uint32(b[8:12]),
			AssocID:    SCTPAssocID(nativeEndian.Uint32(b[12:16])),
			StreamID:   nativeEndian.Uint32(b[16:20]),
			SeqNum:     nativeEndian.Uint32(b[20:24]),
		}, nil

	case SCTP_SENDER_DRY_EVENT:
		if len(b) < senderDrySize {
			return nil, ErrShortNotification
		}
		return &SenderDry{
			typ:     typ,
			flags:   flags,
			length:  length,
			AssocID: SCTPAssocID(nativeEndian.Uint32(b[8:12])),
		}, nil

	case SCTP_AUTHENTICATION_INDICATION:
		if len(b) < authKeyEventSize {
			return nil, ErrShortNotification
		}
		return &AuthKeyEvent{
			typ:          typ,
			flags:        flags,
			length:       length,
			KeyNumber:    nativeEndian.Uint16(b[8:10]),
			AltKeyNumber: nativeEndian.Uint16(b[10:12]),
			Indication:   nativeEndian.Uint32(b[12:16]),
			AssocID:      SCTPAssocID(nativeEndian.Uint32(b[16:20])),
		}, nil

	case SCTP_STREAM_RESET_EVENT:
		if len(b) < streamResetMinSize {
			return nil, ErrShortNotification
		}
		n := &StreamReset{
			typ:     typ,
			flags:   flags,
			length:  length,
			AssocID: SCTPAssocID(nativeEndian.Uint32(b[8:12])),
		}
		// The stream list is a flexible array member, so its extent is
		// whatever arrived. An odd trailing byte cannot be half a stream id,
		// so the loop stops one short of it rather than reading past the end.
		for off := streamResetMinSize; off+2 <= len(b); off += 2 {
			n.Streams = append(n.Streams, nativeEndian.Uint16(b[off:off+2]))
		}
		return n, nil

	case SCTP_ASSOC_RESET_EVENT:
		if len(b) < assocResetSize {
			return nil, ErrShortNotification
		}
		return &AssocReset{
			typ:       typ,
			flags:     flags,
			length:    length,
			AssocID:   SCTPAssocID(nativeEndian.Uint32(b[8:12])),
			LocalTSN:  nativeEndian.Uint32(b[12:16]),
			RemoteTSN: nativeEndian.Uint32(b[16:20]),
		}, nil

	case SCTP_STREAM_CHANGE_EVENT:
		if len(b) < streamChangeSize {
			return nil, ErrShortNotification
		}
		return &StreamChange{
			typ:             typ,
			flags:           flags,
			length:          length,
			AssocID:         SCTPAssocID(nativeEndian.Uint32(b[8:12])),
			InboundStreams:  nativeEndian.Uint16(b[12:14]),
			OutboundStreams: nativeEndian.Uint16(b[14:16]),
		}, nil

	case SCTP_SEND_FAILED_EVENT:
		if len(b) < sendFailedEventMinSize {
			return nil, ErrShortNotification
		}
		n := &SendFailedEvent{
			typ:    typ,
			flags:  flags,
			length: length,
			Error:  causeFromU32(b[8:12]),
		}
		if err := binary.Read(bytes.NewReader(b[12:28]), nativeEndian, &n.Info); err != nil {
			return nil, err
		}
		n.AssocID = SCTPAssocID(nativeEndian.Uint32(b[28:32]))
		if len(b) > sendFailedEventMinSize {
			n.Data = append([]byte(nil), b[sendFailedEventMinSize:]...)
		}
		return n, nil
	}

	// An event this package does not model yet. Not an error: the caller can
	// still see the type and length through the raw bytes.
	return nil, nil
}
