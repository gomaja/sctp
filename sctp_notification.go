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

// ErrShortNotification is returned by ParseNotification when the buffer is
// too short to contain the notification it claims to be. This happens when a
// notification is truncated to a read buffer smaller than the event, so the
// caller should read with a buffer of at least NotificationMaxSize.
var ErrShortNotification = errors.New("sctp: notification truncated")

// NotificationMaxSize is a read buffer size large enough for any notification
// this package parses, so that none is truncated.
const NotificationMaxSize = 1024

// notificationHeaderSize is the common prefix every notification shares:
// uint16 type, uint16 flags, uint32 length.
const notificationHeaderSize = 8

// AssocChange is SCTP_ASSOC_CHANGE (RFC 6458 6.1.1), reporting that an
// association has come up, come down, restarted, or failed to start. State
// says which.
type AssocChange struct {
	typ             uint16
	flags           uint16
	length          uint32
	State           SCTPState
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
	typ     uint16
	flags   uint16
	length  uint32
	Error   uint32
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
			Error:           nativeEndian.Uint16(b[10:12]),
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
			Error:   nativeEndian.Uint16(b[8:10]),
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
			Error:  nativeEndian.Uint32(b[8:12]),
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
	}

	// An event this package does not model yet. Not an error: the caller can
	// still see the type and length through the raw bytes.
	return nil, nil
}
