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

// Package sctp is a binding for the Linux kernel's SCTP stack.
//
// It does not implement SCTP. Chunk handling, association setup,
// retransmission, congestion control, path management and checksums all belong
// to the kernel; what is here is the socket API around them — net.Conn and
// net.Listener implementations, the socket options of RFC 6458 and its
// extensions, ancillary data, and the notifications the kernel delivers on the
// data stream.
//
// # Platforms
//
// SCTP exists on Linux only, and this package's implementation additionally
// excludes linux/386. Everywhere else the package still compiles and every
// entry point returns ErrUnsupported, which wraps errors.ErrUnsupported.
//
// # Reading
//
// SCTP is message-oriented, so a read returns either a whole message or part of
// one and SCTPRead cannot say which: a message larger than the buffer is split,
// and the remainder arrives looking like a fresh message. Use ReadMsg, which
// reassembles, or SCTPReadFlags and test the flags for MSG_EOR.
//
// SCTPReadFlags also reports MSG_NOTIFICATION, which distinguishes an event
// from application data; pass the bytes to ParseNotification. ReadMsg skips
// notifications, since it returns messages.
//
// # Writing
//
// Write and SCTPWrite do not block when the send buffer is full — they return
// EAGAIN, so that a peer which stops reading cannot hang a caller
// indefinitely. Set a write deadline to wait for space instead; see
// SetWriteDeadline. SyscallConn gives the readiness handling net.Conn does not.
//
// # Options announced in the INIT
//
// Several options are only meaningful before the association exists, because
// they are announced in the INIT chunk: SetInitMsg, SetAdaptationLayer, and the
// capability negotiations SetPrSupported, SetReconfigSupported,
// SetAsconfSupported, SetAuthSupported and SetEcnSupported. Setting one on an
// established association is accepted and does nothing. Several also depend on
// a net.sctp.* sysctl; each says so.
package sctp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	SOL_SCTP = 132

	SCTP_BINDX_ADD_ADDR = 0x01
	SCTP_BINDX_REM_ADDR = 0x02

	MSG_NOTIFICATION = 0x8000

	// MSG_EOR is set in the flags returned by SCTPReadFlags when the buffer
	// received the end of a message. Its absence means the message was
	// truncated to the buffer and the remainder follows on later reads.
	MSG_EOR = 0x80
)

// ErrMsgTooLong is returned by ReadMsg when a message exceeds the caller's
// limit. The bytes read so far are returned with it; the remainder of the
// message stays queued.
var ErrMsgTooLong = errors.New("sctp: message exceeds maximum length")

const (
	SCTP_RTOINFO = iota
	SCTP_ASSOCINFO
	SCTP_INITMSG
	SCTP_NODELAY
	SCTP_AUTOCLOSE
	SCTP_SET_PEER_PRIMARY_ADDR
	SCTP_PRIMARY_ADDR
	SCTP_ADAPTATION_LAYER
	SCTP_DISABLE_FRAGMENTS
	SCTP_PEER_ADDR_PARAMS
	SCTP_DEFAULT_SENT_PARAM
	SCTP_EVENTS
	SCTP_I_WANT_MAPPED_V4_ADDR
	SCTP_MAXSEG
	SCTP_STATUS
	SCTP_GET_PEER_ADDR_INFO
	SCTP_DELAYED_ACK_TIME
	SCTP_DELAYED_ACK  = SCTP_DELAYED_ACK_TIME
	SCTP_DELAYED_SACK = SCTP_DELAYED_ACK_TIME

	SCTP_SOCKOPT_BINDX_ADD = 100
	SCTP_SOCKOPT_BINDX_REM = 101
	SCTP_SOCKOPT_PEELOFF   = 102
	// SCTP_SOCKOPT_PEELOFF_FLAGS is SCTP_SOCKOPT_PEELOFF with a flags word
	// appended, so the peeled descriptor can be asked for close-on-exec.
	SCTP_SOCKOPT_PEELOFF_FLAGS = 122
	SCTP_GET_PEER_ADDRS        = 108
	SCTP_GET_LOCAL_ADDRS       = 109
	SCTP_SOCKOPT_CONNECTX      = 110
	SCTP_SOCKOPT_CONNECTX3     = 111

	// SCTP_EVENT is the per-event subscription option RFC 6458 §6.2.2
	// introduced to replace SCTP_EVENTS. Its value is not part of the
	// contiguous block above, so it is spelled out.
	SCTP_EVENT = 127

	// SCTP_RECVRCVINFO makes the kernel return SCTP_RCVINFO as ancillary data
	// on recvmsg (RFC 6458 §8.1.29). It is the non-deprecated counterpart of
	// the SCTP_SNDRCV data SubscribeEvents(SCTP_EVENT_DATA_IO) asks for.
	SCTP_RECVRCVINFO = 32
	// SCTP_RECVNXTINFO makes the kernel return SCTP_NXTINFO, describing the
	// message *after* the one being read (RFC 6458 §8.1.30).
	SCTP_RECVNXTINFO = 33

	// SCTP_FRAGMENT_INTERLEAVE controls whether a partial delivery on one
	// stream blocks messages on the others (RFC 6458 §8.1.20).
	SCTP_FRAGMENT_INTERLEAVE = 18
	// SCTP_PARTIAL_DELIVERY_POINT is the message size at which the partial
	// delivery API is invoked (RFC 6458 §8.1.21).
	SCTP_PARTIAL_DELIVERY_POINT = 19
	// SCTP_MAX_BURST bounds how many packets may be emitted back to back
	// (RFC 6458 §8.1.24). The kernel default is 4.
	SCTP_MAX_BURST = 20
	// SCTP_CONTEXT is the default context reported with messages received from
	// the peer (RFC 6458 §8.1.25).
	SCTP_CONTEXT = 17
	// SCTP_REUSE_PORT allows several endpoints to bind the same port
	// (RFC 6458 §8.1.27). One-to-one sockets only, which is all this package
	// creates.
	SCTP_REUSE_PORT = 36

	// SCTP_DEFAULT_SNDINFO carries struct sctp_sndinfo and is the replacement
	// RFC 6458 §8.1.31 gives for SCTP_DEFAULT_SEND_PARAM, which §8.1.31 marks
	// deprecated along with the struct sctp_sndrcvinfo it takes.
	SCTP_DEFAULT_SNDINFO = 34

	// SCTP_AUTO_ASCONF makes the kernel announce local address changes to the
	// peer with ASCONF chunks (RFC 6458 §8.1.21).
	SCTP_AUTO_ASCONF = 30

	// SCTP_PEER_ADDR_THLDS carries struct sctp_paddrthlds and sets the
	// per-path failure and Potentially Failed thresholds (RFC 7829 §7.2).
	SCTP_PEER_ADDR_THLDS = 31
	// SCTP_PEER_ADDR_THLDS_V2 is the same option with a third threshold added,
	// governing when a path stops being probed while in the Potentially Failed
	// state. Linux-specific; RFC 7829 describes only the first two.
	SCTP_PEER_ADDR_THLDS_V2 = 37

	// SCTP_GET_ASSOC_STATS reads struct sctp_assoc_stats, the per-association
	// counters. Linux-specific; it has no RFC 6458 equivalent.
	SCTP_GET_ASSOC_STATS = 112

	// SCTP_PR_SUPPORTED negotiates PR-SCTP, the partial reliability extension
	// (RFC 7496 §4.5).
	SCTP_PR_SUPPORTED = 113
	// SCTP_DEFAULT_PRINFO carries struct sctp_default_prinfo, the default
	// partial reliability policy and its lifetime (RFC 7496 §4.1).
	SCTP_DEFAULT_PRINFO = 114
	// SCTP_PR_STREAM_STATUS reads struct sctp_prstatus, the count of messages
	// abandoned on one stream under the partial reliability policy
	// (RFC 7496 §4.4).
	SCTP_PR_STREAM_STATUS = 116
	// SCTP_PR_ASSOC_STATUS reads the same struct sctp_prstatus totalled across
	// every stream of the association (RFC 7496 §4.3).
	SCTP_PR_ASSOC_STATUS = 115

	// SCTP_RECONFIG_SUPPORTED negotiates stream reconfiguration
	// (RFC 6525 §6.1).
	SCTP_RECONFIG_SUPPORTED = 117
	// SCTP_ENABLE_STREAM_RESET selects which reconfiguration requests are
	// permitted (RFC 6525 §6.3).
	SCTP_ENABLE_STREAM_RESET = 118
	// SCTP_ADD_STREAMS asks the peer to widen the association's stream count
	// (RFC 6525 §6.5).
	SCTP_ADD_STREAMS = 121
	// SCTP_RESET_STREAMS restarts the sequence numbering of some or all
	// streams (RFC 6525 §6.3.2).
	SCTP_RESET_STREAMS = 119
	// SCTP_RESET_ASSOC restarts the whole association's sequence numbering
	// (RFC 6525 §6.3.3).
	SCTP_RESET_ASSOC = 120

	// SCTP_HMAC_IDENT carries struct sctp_hmacalgo, the ordered list of HMAC
	// algorithms this endpoint offers (RFC 4895 §6.2).
	SCTP_HMAC_IDENT = 22
	// SCTP_AUTH_ACTIVE_KEY carries struct sctp_authkeyid and selects the key
	// used for outbound AUTH chunks (RFC 4895 §6.5).
	SCTP_AUTH_ACTIVE_KEY = 24
	// SCTP_AUTH_CHUNK adds one chunk type to the set this endpoint requires
	// the peer to authenticate (RFC 4895 §6.1). Set only.
	SCTP_AUTH_CHUNK = 21
	// SCTP_AUTH_KEY installs a shared key, carrying struct sctp_authkey with
	// the key bytes appended (RFC 4895 §6.3). Set only.
	SCTP_AUTH_KEY = 23
	// SCTP_AUTH_DELETE_KEY removes a shared key (RFC 4895 §6.8). Set only.
	SCTP_AUTH_DELETE_KEY = 25
	// SCTP_AUTH_DEACTIVATE_KEY stops a shared key being used for new packets
	// while leaving it able to verify what is already in flight
	// (RFC 4895 §6.9). Set only.
	SCTP_AUTH_DEACTIVATE_KEY = 35
	// SCTP_PEER_AUTH_CHUNKS reads the chunk types the peer requires to be
	// authenticated (RFC 4895 §6.6). Read only.
	SCTP_PEER_AUTH_CHUNKS = 26
	// SCTP_LOCAL_AUTH_CHUNKS reads the chunk types this endpoint requires to
	// be authenticated (RFC 4895 §6.7). Read only.
	SCTP_LOCAL_AUTH_CHUNKS = 27

	// SCTP_STREAM_SCHEDULER selects the order outbound streams are served in
	// (RFC 8260 §4).
	SCTP_STREAM_SCHEDULER = 123
	// SCTP_STREAM_SCHEDULER_VALUE sets a per-stream parameter for the
	// scheduler in force, which for SCTP_SS_PRIO is the stream's priority.
	SCTP_STREAM_SCHEDULER_VALUE = 124
	// SCTP_INTERLEAVING_SUPPORTED negotiates user message interleaving, the
	// I-DATA chunk of RFC 8260. The kernel refuses it with EPERM unless
	// net.sctp.intl_enable is on and SetFragmentInterleave has been given a
	// non-zero level.
	SCTP_INTERLEAVING_SUPPORTED = 125
	// SCTP_ASCONF_SUPPORTED negotiates dynamic address reconfiguration
	// (RFC 5061). See SetAsconfSupported: this is what makes SetAutoAsconf do
	// anything at all.
	SCTP_ASCONF_SUPPORTED = 128
	// SCTP_AUTH_SUPPORTED negotiates AUTH (RFC 4895) for this socket, without
	// net.sctp.auth_enable.
	SCTP_AUTH_SUPPORTED = 129
	// SCTP_ECN_SUPPORTED negotiates explicit congestion notification.
	SCTP_ECN_SUPPORTED = 130
	// SCTP_EXPOSE_POTENTIALLY_FAILED_STATE controls whether the PF state of
	// RFC 7829 is visible; see SetExposePotentiallyFailed.
	SCTP_EXPOSE_POTENTIALLY_FAILED_STATE = 131
	// SCTP_EXPOSE_PF_STATE is the kernel's shorter spelling of the same option.
	SCTP_EXPOSE_PF_STATE = SCTP_EXPOSE_POTENTIALLY_FAILED_STATE
)

// Stream schedulers for SetStreamScheduler, from the kernel's
// enum sctp_sched_type (RFC 8260 §4 describes the idea; the set Linux
// implements is smaller than the one the RFC lists).
const (
	// SCTPSchedFCFS sends messages in the order they were handed over,
	// regardless of stream. It is the default.
	SCTPSchedFCFS = 0
	// SCTPSchedPrio serves streams by the priority set with
	// SetStreamSchedulerValue, lowest number first.
	SCTPSchedPrio = 1
	// SCTPSchedRR serves streams round-robin, one message at a time.
	SCTPSchedRR = 2
)

// PF state exposure levels for SetExposePotentiallyFailed (RFC 7829), from the
// kernel's SCTP_PF_EXPOSE_* enum in include/net/sctp/constants.h.
//
// The values are not a boolean with an extra mode: zero means "no answer
// given", and the two explicit answers are 1 for off and 2 for on. Reading them
// as off/on/locked, which is the shape most of these options have, puts
// "exposed" on the value that disables it — a round-trip test still passes,
// because the number written is the number read back.
const (
	// SCTPPFStateUnset leaves the decision to net.sctp.pf_expose, which
	// defaults to disabled. This is the state of a socket nobody has asked.
	SCTPPFStateUnset = 0
	// SCTPPFStateDisabled suppresses the PF state. GetPeerAddrInfo reports a
	// potentially-failed path as SCTP_ACTIVE and no notification is delivered.
	SCTPPFStateDisabled = 1
	// SCTPPFStateEnabled reports the PF state through both
	// SCTP_PEER_ADDR_CHANGE and GetPeerAddrInfo. This is what a caller wants
	// if they are asking at all.
	SCTPPFStateEnabled = 2
)

// Flags for PeerAddrParams.Flags, from the kernel's spp_flags (RFC 6458
// §8.1.12).
//
// The ENABLE/DISABLE pairs are how the option distinguishes "set this" from
// "leave it alone": with neither bit set the corresponding value field is
// ignored, which is why SetPeerAddrParams cannot be used to clear a setting by
// passing zero.
const (
	SPP_HB_ENABLE         = 1 << 0
	SPP_HB_DISABLE        = 1 << 1
	SPP_HB_DEMAND         = 1 << 2 // send one heartbeat now
	SPP_PMTUD_ENABLE      = 1 << 3
	SPP_PMTUD_DISABLE     = 1 << 4
	SPP_SACKDELAY_ENABLE  = 1 << 5
	SPP_SACKDELAY_DISABLE = 1 << 6
	SPP_HB_TIME_IS_ZERO   = 1 << 7 // heartbeat immediately after each RTO
	SPP_IPV6_FLOWLABEL    = 1 << 8
	SPP_DSCP              = 1 << 9
)

// Partial reliability policies for SetDefaultPrInfo (RFC 7496 §4.1). The value
// accompanying each policy is interpreted differently, which is why they are not
// interchangeable:
//
//   - SCTPPrPolicyNone ignores the value; the message is sent reliably.
//   - SCTPPrPolicyTTL treats it as a lifetime in milliseconds.
//   - SCTPPrPolicyRtx treats it as a retransmission count.
//   - SCTPPrPolicyPrio treats it as a priority, where a larger number is
//     discarded sooner when the send buffer is under pressure.
//
// Unlike the fragment interleave levels, the kernel does police these: a policy
// outside this set is rejected with EINVAL, which was measured.
const (
	SCTPPrPolicyNone = 0x0000
	SCTPPrPolicyTTL  = 0x0010
	SCTPPrPolicyRtx  = 0x0020
	SCTPPrPolicyPrio = 0x0030
)

// Stream reconfiguration request types for SetEnableStreamReset
// (RFC 6525 §6.3). These are a bitmask; a socket may permit any combination.
const (
	// SCTPEnableResetStreamReq permits resetting the sequence numbers of
	// individual streams.
	SCTPEnableResetStreamReq = 0x01
	// SCTPEnableResetAssocReq permits resetting the whole association's
	// sequence numbers.
	SCTPEnableResetAssocReq = 0x02
	// SCTPEnableChangeAssocReq permits adding streams to a live association.
	SCTPEnableChangeAssocReq = 0x04
)

// HMAC algorithm identifiers for SetHmacIdent (RFC 4895 §3.1.1 and the IANA
// registry it establishes). SHA-1 is mandatory to implement; SHA-256 is
// optional. Note that 2 is not assigned — the registry skips it — so these are
// not contiguous.
const (
	SCTPAuthHmacIDSHA1   = 1
	SCTPAuthHmacIDSHA256 = 3
)

// Fragmented interleave levels for SetFragmentInterleave (RFC 6458 §8.1.20).
//
// Linux does not store a level. It keeps a single flag, so anything non-zero
// becomes 1: setting 2 and setting 3 both read back as 1, which was measured.
// That means an out-of-range value is not rejected and not honoured either, and
// nothing tells the caller. SetFragmentInterleave rejects anything outside this
// set so the mistake fails at the call.
const (
	// SCTPFragmentInterleaveNone blocks every other message while a partial
	// delivery is in progress. This is the kernel default.
	SCTPFragmentInterleaveNone = 0
	// SCTPFragmentInterleaveOther allows messages from other associations to be
	// delivered during a partial delivery, but not from other streams of this
	// one.
	SCTPFragmentInterleaveOther = 1
	// SCTPFragmentInterleaveStreams additionally allows messages from other
	// streams of the same association.
	//
	// It never reads back. Linux keeps fragment interleave as a flag rather
	// than a level, so this is accepted and stored as
	// SCTPFragmentInterleaveOther — as is 3, which is how the flag rather than
	// the level shows. What RFC 6458 §8.1.20 describes for this level is
	// reached instead by negotiating the I-DATA chunk of RFC 8260; see
	// SetInterleavingSupported, which needs this set to a non-zero value first
	// and refuses with EPERM otherwise.
	SCTPFragmentInterleaveStreams = 2
)

const (
	SCTP_EVENT_DATA_IO = 1 << iota
	SCTP_EVENT_ASSOCIATION
	SCTP_EVENT_ADDRESS
	SCTP_EVENT_SEND_FAILURE
	SCTP_EVENT_PEER_ERROR
	SCTP_EVENT_SHUTDOWN
	SCTP_EVENT_PARTIAL_DELIVERY
	SCTP_EVENT_ADAPTATION_LAYER
	SCTP_EVENT_AUTHENTICATION
	SCTP_EVENT_SENDER_DRY

	SCTP_EVENT_ALL = SCTP_EVENT_DATA_IO | SCTP_EVENT_ASSOCIATION | SCTP_EVENT_ADDRESS | SCTP_EVENT_SEND_FAILURE | SCTP_EVENT_PEER_ERROR | SCTP_EVENT_SHUTDOWN | SCTP_EVENT_PARTIAL_DELIVERY | SCTP_EVENT_ADAPTATION_LAYER | SCTP_EVENT_AUTHENTICATION | SCTP_EVENT_SENDER_DRY
)

type (
	SCTPNotificationType int
	SCTPAssocID          int32
)

const (
	SCTP_SN_TYPE_BASE = SCTPNotificationType(iota + (1 << 15))
	SCTP_ASSOC_CHANGE
	SCTP_PEER_ADDR_CHANGE
	SCTP_SEND_FAILED
	SCTP_REMOTE_ERROR
	SCTP_SHUTDOWN_EVENT
	SCTP_PARTIAL_DELIVERY_EVENT
	SCTP_ADAPTATION_INDICATION
	SCTP_AUTHENTICATION_INDICATION
	SCTP_SENDER_DRY_EVENT
	SCTP_STREAM_RESET_EVENT
	SCTP_ASSOC_RESET_EVENT
	SCTP_STREAM_CHANGE_EVENT
	SCTP_SEND_FAILED_EVENT
)

// SCTP_AUTHENTICATION_EVENT is the spelling RFC 6458 §6.1.8 and the kernel's
// enum sctp_sn_type use. SCTP_AUTHENTICATION_INDICATION is the name Linux gives
// the same value through its compatibility #define, and is what this package
// has always called it.
const SCTP_AUTHENTICATION_EVENT = SCTP_AUTHENTICATION_INDICATION

type NotificationHandler func([]byte) error

// EventSubscribe mirrors struct sctp_event_subscribe, the bulk subscription
// used by SCTP_EVENTS.
//
// The fields are the ten RFC 6458 §6.2.1 events. Linux appends four of its own
// (stream reset, association reset, stream change, and a second send-failure
// event), so the kernel's struct is 14 bytes against this one's 10. That is
// safe in both directions and was measured rather than assumed: setsockopt
// with a 10 byte option length is accepted and applied, and getsockopt with
// one writes only the first 10 bytes and leaves the rest of the caller's
// buffer untouched. The cost is that those four Linux-only events cannot be
// reached through this struct.
//
// RFC 6458 §6.2.2 deprecates SCTP_EVENTS for precisely this reason — the
// struct has to grow as events are added — and replaces it with SCTP_EVENT,
// which names one event per call. See SubscribeEvent.
type EventSubscribe struct {
	DataIO          uint8
	Association     uint8
	Address         uint8
	SendFailure     uint8
	PeerError       uint8
	Shutdown        uint8
	PartialDelivery uint8
	AdaptationLayer uint8
	Authentication  uint8
	SenderDry       uint8
}

// Event mirrors struct sctp_event (RFC 6458 §6.2.2), which subscribes to or
// unsubscribes from one notification type at a time.
//
// Both this struct and the kernel's are 8 bytes: three fields totalling 7,
// rounded up for the alignment of the leading 4 byte association id. The
// trailing field below is that padding written out. Go would insert it either
// way — removing it does not change the size, which was checked — so it is here
// to make the layout the kernel expects visible at the declaration rather than
// implied by alignment rules. TestEventStructMatchesKernel asserts the size and
// every offset.
// RcvInfo mirrors struct sctp_rcvinfo (RFC 6458 §5.3.5), the per-message
// receive information the kernel attaches as SCTP_RCVINFO ancillary data once
// SetRecvRcvInfo is enabled.
//
// It is the non-deprecated half of what SndRcvInfo carries: RFC 6458 §5.3.2
// titles SCTP_SNDRCV "DEPRECATED" and splits it into SCTP_SNDINFO for sending
// and this for receiving. The field order is not the same as SndRcvInfo's —
// TSN and CumTSN come before Context here and after it there — so the two are
// not interchangeable as raw memory.
//
// TestStructLayoutsMatchKernel pins the layout. Callers normally do not need
// this type: SCTPRead converts whichever form the kernel sent into SndRcvInfo.
type RcvInfo struct {
	// SID is the stream the message arrived on.
	SID uint16
	// SSN is the stream sequence number.
	SSN uint16
	// Flags carries SCTP_UNORDERED and friends.
	Flags uint16
	_     uint16
	// PPID is the payload protocol identifier, in network byte order as the
	// kernel delivers it. SCTPRead converts it.
	PPID uint32
	// TSN is the transmission sequence number.
	TSN uint32
	// CumTSN is the cumulative TSN acknowledged.
	CumTSN uint32
	// Context is the value set with SetContext.
	Context uint32
	// AssocID identifies the association; ignored on one-to-one sockets.
	AssocID SCTPAssocID
}

type Event struct {
	// AssocID is ignored on the one-to-one style sockets this package creates.
	AssocID SCTPAssocID
	// Type is a notification type, e.g. SCTP_ASSOC_CHANGE.
	Type uint16
	// On is 1 to subscribe and 0 to unsubscribe.
	On uint8
	_  uint8
}

// Ancillary data types, enum sctp_cmsg_type. The values are positional in the C
// enum, so the order here is the contract — SCTP_CMSG_PRINFO must stay 5.
const (
	SCTP_CMSG_INIT = iota
	SCTP_CMSG_SNDRCV
	SCTP_CMSG_SNDINFO
	SCTP_CMSG_RCVINFO
	SCTP_CMSG_NXTINFO
	// SCTP_CMSG_PRINFO carries struct sctp_prinfo on a send, setting the
	// partial reliability policy for that one message (RFC 6458 §5.3.7).
	SCTP_CMSG_PRINFO
	// SCTP_CMSG_AUTHINFO carries struct sctp_authinfo, naming the shared key
	// to authenticate that one message with (RFC 6458 §5.3.8).
	SCTP_CMSG_AUTHINFO
	// SCTP_CMSG_DSTADDRV4 and SCTP_CMSG_DSTADDRV6 add a destination address to
	// a send on an unconnected one-to-many socket (RFC 6458 §5.3.9, §5.3.10).
	// This package creates only one-to-one sockets, so they are defined for
	// completeness.
	SCTP_CMSG_DSTADDRV4
	SCTP_CMSG_DSTADDRV6
)

// Direction flags for ResetStreams (RFC 6525 §6.3.2). At least one is required:
// a request with neither is rejected with EINVAL, which was measured.
const (
	// SCTPStreamResetIncoming resets the streams the peer sends on.
	SCTPStreamResetIncoming = 0x01
	// SCTPStreamResetOutgoing resets the streams this endpoint sends on.
	SCTPStreamResetOutgoing = 0x02
)

// Per-message send flags, for SndRcvInfo.Flags and SndInfo.Flags. These are the
// kernel's enum sctp_sinfo_flags (RFC 6458 §5.3.2).
//
// The sequence is not contiguous, which is what makes it worth writing out
// rather than generating with iota. Bits 4 and 5 belong to SCTP_PR_SCTP_MASK —
// the partial reliability policy travels in the same word — and SCTP_EOF is not
// an SCTP-specific bit at all but MSG_FIN, which is 0x200.
//
// SCTP_EOF used to be the fifth iota here, so 1<<4, which is exactly
// SCTP_PR_SCTP_TTL. A caller asking for a graceful shutdown on their last
// message instead selected a partial reliability policy, and got neither the
// shutdown nor an error.
const (
	// SCTP_UNORDERED sends the message without sequencing.
	SCTP_UNORDERED = 1 << 0
	// SCTP_ADDR_OVER overrides the primary destination, using the address in
	// SndRcvInfo. It applies to one-to-many sockets.
	SCTP_ADDR_OVER = 1 << 1
	// SCTP_ABORT tears the association down with an ABORT instead of sending.
	SCTP_ABORT = 1 << 2
	// SCTP_SACK_IMMEDIATELY asks the peer to acknowledge without waiting for
	// its delayed-ack timer.
	SCTP_SACK_IMMEDIATELY = 1 << 3

	// Bits 4 and 5 are SCTP_PR_SCTP_MASK, carrying the partial reliability
	// policy. Use the SCTPPrPolicy constants with SCTPWriteInfo rather than
	// setting them here.

	// SCTP_SENDALL sends the message on every association of a one-to-many
	// socket.
	SCTP_SENDALL = 1 << 6
	// SCTP_PR_SCTP_ALL applies the partial reliability policy to every stream.
	SCTP_PR_SCTP_ALL = 1 << 7

	// SCTP_EOF starts a graceful shutdown once the message is delivered. It is
	// MSG_FIN, not a bit of its own.
	SCTP_EOF = 0x200
)

const (
	SCTP_MAX_STREAM = 0xffff
)

type InitMsg struct {
	NumOstreams    uint16
	MaxInstreams   uint16
	MaxAttempts    uint16
	MaxInitTimeout uint16
}

// SackTimer Parameters defined in RFC 6458 8.1.19 - SCTP_DELAYED_SACK Delayed Sack Timer sack_timeout
type SackTimer struct {
	AssocID       SCTPAssocID
	SackDelay     uint32
	SackFrequency uint32
}

// AssocValue mirrors struct sctp_assoc_value, the association-id-and-value
// pair several socket options take.
//
// AssocID is ignored on the one-to-one style sockets this package creates.
type AssocValue struct {
	AssocID  SCTPAssocID
	AssocVal uint32
}

// DefaultPrInfo mirrors struct sctp_default_prinfo (RFC 7496 §4.1), the default
// partial reliability policy for messages that do not carry their own.
type DefaultPrInfo struct {
	AssocID SCTPAssocID
	// Value is a lifetime, a retransmission count or a priority depending on
	// Policy. See the SCTPPrPolicy constants.
	Value uint32
	// Policy is one of the SCTPPrPolicy constants.
	Policy uint16
	// Go's alignment rules already round the struct to 12 bytes, so this pad
	// is documentation of the C layout rather than the thing producing the
	// size. Removing it changes nothing, which was verified.
	_ uint16
}

// PrStatus mirrors struct sctp_prstatus (RFC 7496 §4.4), the count of messages
// abandoned on one stream under a partial reliability policy.
type PrStatus struct {
	AssocID SCTPAssocID
	// SID selects the stream to report on. Set it before the call.
	SID uint16
	// Policy selects which policy's counters to report. Set it before the
	// call.
	Policy uint16
	// AbandonedUnsent counts messages discarded before any part was sent.
	AbandonedUnsent uint64
	// AbandonedSent counts messages discarded after at least one fragment had
	// gone out.
	AbandonedSent uint64
}

// PeerAddrThlds mirrors struct sctp_paddrthlds (RFC 7829 §7.2), the per-path
// retransmission thresholds that drive failure detection and the Potentially
// Failed state.
type PeerAddrThlds struct {
	AssocID SCTPAssocID
	// struct sockaddr_storage contains a long, so C aligns it to 8 and leaves
	// four pad bytes here. Go would place a [128]byte at offset 4 and shift
	// every following field, so the pad is explicit. Measured with
	// testdata/optprobe; TestStructLayoutsMatchKernel pins it.
	_ uint32
	// Address selects the path. A zeroed address applies to the association as
	// a whole, which is the useful form on the single-homed sockets this
	// package usually creates.
	Address [128]byte
	// PathMaxRxt is the retransmission count at which a path is declared
	// failed.
	PathMaxRxt uint16
	// PathPfThld is the count at which a path enters the Potentially Failed
	// state, ahead of outright failure. It must not exceed PathMaxRxt.
	PathPfThld uint16
	// The struct's 8-byte alignment rounds its size up from 140 to 144. Go
	// would stop at 140, and the four-byte-short option length is rejected.
	_ uint32
}

// PeerAddrThldsV2 mirrors struct sctp_paddrthlds_v2, the Linux extension of
// PeerAddrThlds with a third threshold. RFC 7829 defines only the first two.
type PeerAddrThldsV2 struct {
	AssocID SCTPAssocID
	// Four pad bytes before the sockaddr_storage, as in PeerAddrThlds.
	_ uint32
	// Address selects the path; a zeroed address applies to the association.
	Address [128]byte
	// PathMaxRxt is the retransmission count at which a path is declared
	// failed.
	PathMaxRxt uint16
	// PathPfThld is the count at which a path enters the Potentially Failed
	// state.
	PathPfThld uint16
	// PathCpThld is the count at which the stack stops probing a path that is
	// in the Potentially Failed state. The kernel default is 0xffff, meaning
	// probing continues indefinitely.
	PathCpThld uint16
	// The struct's 8-byte alignment rounds its size up from 142 to 144. Go
	// produces that with or without this pad, so as in DefaultPrInfo it records
	// the C layout rather than causing the size; verified both ways.
	_ uint16
}

// AssocStats mirrors struct sctp_assoc_stats, the per-association counters
// Linux exposes through SCTP_GET_ASSOC_STATS. This has no RFC 6458 counterpart —
// the field set is the kernel's own.
type AssocStats struct {
	AssocID SCTPAssocID
	// Four pad bytes before the sockaddr_storage, as in PeerAddrThlds.
	_ uint32
	// ObsRtoIPAddr is the path on which MaxRto was observed.
	ObsRtoIPAddr [128]byte
	// MaxRto is the largest retransmission timeout observed since the last
	// read. Reading resets it.
	MaxRto uint64
	// ISacks and OSacks count SACK chunks received and sent.
	ISacks, OSacks uint64
	// OPackets and IPackets count packets sent and received.
	OPackets, IPackets uint64
	// RtxChunks counts retransmitted data chunks.
	RtxChunks uint64
	// OutOfSeqTsns counts chunks arriving beyond the next expected TSN.
	OutOfSeqTsns uint64
	// IDupChunks counts duplicate chunks received.
	IDupChunks uint64
	// GapCnt counts gap acknowledgement blocks received.
	GapCnt uint64
	// OUodChunks and IUodChunks count unordered data chunks sent and received.
	OUodChunks, IUodChunks uint64
	// OOdChunks and IOdChunks count ordered data chunks sent and received.
	OOdChunks, IOdChunks uint64
	// OCtrlChunks and ICtrlChunks count control chunks sent and received.
	OCtrlChunks, ICtrlChunks uint64
}

// AddStreamsReq mirrors struct sctp_add_streams (RFC 6525 §6.5), the request to
// widen an association's stream count. The AddStreams method wraps it; this type
// is exported so the layout can be pinned by the layout test.
type AddStreamsReq struct {
	AssocID SCTPAssocID
	// InStreams is how many inbound streams to add.
	InStreams uint16
	// OutStreams is how many outbound streams to add.
	OutStreams uint16
}

// PrInfo mirrors struct sctp_prinfo (RFC 6458 §5.3.7), the per-message partial
// reliability policy carried as SCTP_CMSG_PRINFO ancillary data.
//
// Note the padding: the C struct is a __u16 followed by a __u32, so the value
// sits at offset 4 and the struct is 8 bytes rather than 6.
type PrInfo struct {
	// Policy is one of the SCTPPrPolicy constants.
	Policy uint16
	_      uint16
	// Value is a lifetime, retransmission count or priority, per Policy.
	Value uint32
}

// AuthInfo mirrors struct sctp_authinfo (RFC 6458 §5.3.8), naming the shared key
// to authenticate one message with, carried as SCTP_CMSG_AUTHINFO.
type AuthInfo struct {
	KeyNumber uint16
}

// AuthKeyID mirrors struct sctp_authkeyid (RFC 4895 §6.5), naming one of the
// endpoint's shared keys.
type AuthKeyID struct {
	AssocID   SCTPAssocID
	KeyNumber uint16
	// The C declaration is 6 bytes, but the kernel expects and returns 8.
	// Go's alignment already rounds this struct to 8, so as with DefaultPrInfo
	// the pad records the C layout rather than causing the size; removing it
	// changes nothing, which was verified.
	_ uint16
}

// RtoInfo mirrors struct sctp_rtoinfo (RFC 6458 8.1.1, SCTP_RTOINFO). It
// governs the retransmission timer, and with it how quickly the stack gives up
// on an unresponsive peer.
//
// All durations are milliseconds. A zero field means "leave unchanged" on a
// set, which is how the kernel reads it.
type RtoInfo struct {
	AssocID SCTPAssocID
	// Initial is the RTO used before any round trip has been measured.
	Initial uint32
	// Max caps the exponential backoff. Combined with AssocInfo.AsocMaxRxt it
	// bounds how long a send can sit unacknowledged before the association is
	// declared failed: the retransmission intervals double up to Max, so a
	// large Max means a peer that vanishes is noticed only after minutes.
	Max uint32
	// Min floors the RTO.
	Min uint32
}

// AssocInfo mirrors struct sctp_assocparams (RFC 6458 8.1.2, SCTP_ASSOCINFO).
//
// AsocMaxRxt is the field that matters for detecting an unreachable peer: it
// is Association.Max.Retrans, RFC 9260 section 8.1 — section 8.2 is the path
// counter, not the association one. Once that many
// consecutive retransmissions to a peer go unacknowledged, the association is
// torn down and the socket becomes readable with an error. Lowering it, and
// lowering RtoInfo.Max, is what turns a silent black hole into a prompt,
// reportable failure.
type AssocInfo struct {
	AssocID SCTPAssocID
	// AsocMaxRxt is the maximum retransmission attempts for the association.
	AsocMaxRxt uint16
	// NumberPeerDestinations is how many destination addresses the peer has.
	NumberPeerDestinations uint16
	// PeerRwnd is the peer's last reported receive window, minus outstanding
	// data. It stops shrinking and stays put when a peer stops acknowledging,
	// which makes it a useful companion signal to Status.Unackdata.
	PeerRwnd uint32
	// LocalRwnd is the last receive window reported to the peer.
	LocalRwnd uint32
	// CookieLife is the association's cookie lifetime, in milliseconds.
	CookieLife uint32
}

type PeerState int32

// Per-path states, from enum sctp_spinfo_state in the kernel's uapi
// linux/sctp.h. The order is load-bearing: callers compare PeerAddrinfo.State
// against these to decide whether a path is still usable, so the values must
// match what the kernel reports rather than read in a natural-looking order.
const (
	// SCTP_INACTIVE means the path has failed: it has exceeded
	// Path.Max.Retrans without a response. See RFC 9260 section 8.2.
	SCTP_INACTIVE PeerState = iota
	// SCTP_PF ("potentially failed") is an intermediate state from RFC 7829:
	// some retransmissions have failed but the path is not yet declared
	// inactive.
	SCTP_PF
	// SCTP_ACTIVE means the path is reachable and in use.
	SCTP_ACTIVE
	// SCTP_UNCONFIRMED means the path has not yet been validated by a
	// heartbeat exchange.
	SCTP_UNCONFIRMED

	// SCTP_UNKNOWN is reported when the transport state is not known.
	SCTP_UNKNOWN PeerState = 0xffff
)

// SCTP_POTENTIALLY_FAILED is the spelling RFC 7829 uses for SCTP_PF.
const SCTP_POTENTIALLY_FAILED = SCTP_PF

// PeerAddrinfo Parameters defined in RFC 6458 8.2.2 - Peer Address Information (SCTP_GET_PEER_ADDR_INFO)
type PeerAddrinfo struct {
	AssocID SCTPAssocID
	// Address holds the peer address as a raw sockaddr. Use
	// (*SCTPConn).SCTPGetPrimaryPeerAddr to obtain it decoded: the decoder
	// this package uses is unexported, and decoding the bytes by hand means
	// reproducing the per-entry family and bounds handling it does.
	Address [128]byte
	State   PeerState
	CWND    uint32
	SRTT    uint32
	RTO     uint32
	MTU     uint32
}

type StatusState int32

// Association states, from enum sctp_sstat_state in the kernel's uapi
// linux/sctp.h, as reported by GetStatus.
//
// The enum begins at SCTP_EMPTY rather than SCTP_CLOSED, and has no SCTP_BOUND
// or SCTP_LISTEN members. Numbering from SCTP_CLOSED = 0 shifts every state by
// one, so an established association compares equal to SCTP_COOKIE_ECHOED.
const (
	SCTP_EMPTY StatusState = iota
	SCTP_CLOSED
	SCTP_COOKIE_WAIT
	SCTP_COOKIE_ECHOED
	SCTP_ESTABLISHED
	SCTP_SHUTDOWN_PENDING
	SCTP_SHUTDOWN_SENT
	SCTP_SHUTDOWN_RECEIVED
	SCTP_SHUTDOWN_ACK_SENT
)

// Status Parameters defined in RFC 6458 8.2.1 - Association Status (SCTP_STATUS)
type Status struct {
	AssocID            SCTPAssocID
	State              StatusState
	RWND               uint32
	Unackdata          uint16
	Penddata           uint16
	Instreams          uint16
	Ostreams           uint16
	FragmentationPoint uint32
	PrimaryPeerAddr    PeerAddrinfo
}

type SndRcvInfo struct {
	Stream uint16
	SSN    uint16
	Flags  uint16
	_      uint16
	// This parameter’s endianness is not specified in the SCTP standards, but as is the case with Wireshark, it seems
	// that it is generally treated as network byte order.
	//
	// IANA defines them as integer values, hence we would assume that our users would use the trouble-free host
	PPID    uint32
	Context uint32
	TTL     uint32
	TSN     uint32
	CumTSN  uint32
	AssocID int32
}

// SndInfo mirrors struct sctp_sndinfo (RFC 6458 §5.3.4). It is the
// non-deprecated replacement for the send-side half of SndRcvInfo, and is what
// SCTP_DEFAULT_SNDINFO carries.
//
// Five fields where SndRcvInfo has ten: the deprecated struct doubled as the
// receive-side descriptor, and those fields have moved to RcvInfo.
type SndInfo struct {
	// SID is the stream to send on.
	SID uint16
	// Flags carries SCTP_UNORDERED and friends.
	Flags uint16
	// PPID is the payload protocol identifier, passed to the peer unchanged.
	// The kernel does not byte-swap it; see SetDefaultSndInfo.
	PPID uint32
	// Context is returned with a send failure notification, letting a caller
	// identify which message failed.
	Context uint32
	AssocID int32
}

type GetAddrsOld struct {
	AssocID int32
	AddrNum int32
	Addrs   uintptr
}

type NotificationHeader struct {
	Type   uint16
	Flags  uint16
	Length uint32
}

type SCTPState uint16

const (
	SCTP_COMM_UP = SCTPState(iota)
	SCTP_COMM_LOST
	SCTP_RESTART
	SCTP_SHUTDOWN_COMP
	SCTP_CANT_STR_ASSOC
)

var nativeEndian binary.ByteOrder
var sndRcvInfoSize uintptr

func init() {
	i := uint16(1)
	if *(*byte)(unsafe.Pointer(&i)) == 0 {
		nativeEndian = binary.BigEndian
	} else {
		nativeEndian = binary.LittleEndian
	}
	sndRcvInfoSize = unsafe.Sizeof(SndRcvInfo{})
}

// toBuf serialises a fixed-size value in the host's byte order, for handing to
// the kernel as a socket address or control message.
//
// binary.Write only fails when v is not a fixed-size type, which is a mistake
// in this package rather than anything a caller can cause. Returning the empty
// buffer that failure produces would send a truncated address or control
// message to the kernel, or panic later at buf[0] in ToRawSockAddrBuf, a long
// way from the cause. Panicking here names it.
func toBuf(v interface{}) []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, nativeEndian, v); err != nil {
		panic(fmt.Sprintf("sctp: cannot serialise %T: %v", v, err))
	}
	return buf.Bytes()
}

func htons(h uint16) uint16 {
	if nativeEndian == binary.LittleEndian {
		return (h << 8 & 0xff00) | (h >> 8 & 0xff)
	}
	return h
}

var ntohs = htons

func htonl(h uint32) uint32 {
	if nativeEndian == binary.LittleEndian {
		return (h << 24 & 0xff000000) | (h << 8 & 0x00ff0000) | (h >> 8 & 0x0000ff00) | (h >> 24 & 0x000000ff)
	}
	return h
}

var ntohl = htonl

// setInitOpts sets options for an SCTP association initialization
// see RFC 9260 section 5.1, which obsoleted RFC 4960
func setInitOpts(fd int, options InitMsg) error {
	optlen := unsafe.Sizeof(options)
	_, _, err := setsockopt(fd, SCTP_INITMSG, uintptr(unsafe.Pointer(&options)), uintptr(optlen))
	return err
}

type SCTPAddr struct {
	IPAddrs []net.IPAddr
	Port    int
}

func (a *SCTPAddr) ToRawSockAddrBuf() []byte {
	p := htons(uint16(a.Port))
	if len(a.IPAddrs) == 0 { // if a.IPAddrs list is empty - fall back to IPv4 zero addr
		s := syscall.RawSockaddrInet4{
			Family: syscall.AF_INET,
			Port:   p,
		}
		copy(s.Addr[:], net.IPv4zero)
		return toBuf(s)
	}
	buf := []byte{}
	for _, ip := range a.IPAddrs {
		ipBytes := ip.IP
		if len(ipBytes) == 0 {
			ipBytes = net.IPv4zero
		}
		if ip4 := ipBytes.To4(); ip4 != nil {
			s := syscall.RawSockaddrInet4{
				Family: syscall.AF_INET,
				Port:   p,
			}
			copy(s.Addr[:], ip4)
			buf = append(buf, toBuf(s)...)
		} else {
			var scopeid uint32
			ifi, err := net.InterfaceByName(ip.Zone)
			if err == nil {
				scopeid = uint32(ifi.Index)
			}
			s := syscall.RawSockaddrInet6{
				Family:   syscall.AF_INET6,
				Port:     p,
				Scope_id: scopeid,
			}
			copy(s.Addr[:], ipBytes)
			buf = append(buf, toBuf(s)...)
		}
	}
	return buf
}

func (a *SCTPAddr) String() string {
	var b bytes.Buffer

	for n, i := range a.IPAddrs {
		if i.IP.To4() != nil {
			b.WriteString(i.String())
		} else if i.IP.To16() != nil {
			b.WriteRune('[')
			b.WriteString(i.String())
			b.WriteRune(']')
		}
		if n < len(a.IPAddrs)-1 {
			b.WriteRune('/')
		}
	}
	b.WriteRune(':')
	b.WriteString(strconv.Itoa(a.Port))
	return b.String()
}

func (a *SCTPAddr) Network() string { return "sctp" }

// canonicalNetwork validates an SCTP network name and returns it with the empty
// string spelled out, along with the TCP network used to resolve its addresses.
//
// It is the single place that decides which names are valid, and every entry
// point that takes a network calls it. That matters for two reasons.
//
// favoriteAddrFamily, vendored from the standard library, picks an address
// family from the name's last byte. The standard library only ever calls it
// with a name its own caller has already checked; this package called it with
// whatever the caller passed. So ListenSCTP("") and DialSCTP("") panicked with
// an index out of range — the empty string has no last byte — and
// ListenSCTP("tcp") quietly created an SCTP socket, because "p" is neither '4'
// nor '6' and the default is reached. Rejecting unknown names and expanding the
// empty one here keeps the vendored function byte-identical to upstream.
//
// The empty string means "sctp", which is what ResolveSCTPAddr has always
// accepted and what net.Dial does for its own networks.
func canonicalNetwork(network string) (sctpnet, tcpnet string, err error) {
	switch network {
	case "", "sctp":
		return "sctp", "tcp", nil
	case "sctp4":
		return "sctp4", "tcp4", nil
	case "sctp6":
		return "sctp6", "tcp6", nil
	}
	return "", "", net.UnknownNetworkError(network)
}

func ResolveSCTPAddr(network, addrs string) (*SCTPAddr, error) {
	_, tcpnet, err := canonicalNetwork(network)
	if err != nil {
		return nil, err
	}
	// strings.Split never returns an empty slice, so the last element always
	// exists; the length check that used to be here could not fire.
	elems := strings.Split(addrs, "/")
	ipaddrs := make([]net.IPAddr, 0, len(elems))
	for _, e := range elems[:len(elems)-1] {
		tcpa, err := net.ResolveTCPAddr(tcpnet, e+":")
		if err != nil {
			return nil, err
		}
		if tcpa.IP == nil {
			// An empty element. "/127.0.0.1:80" used to produce a nil IP
			// followed by the real one, and binding that list asks for the
			// wildcard address as well as the one the caller named.
			return nil, &net.AddrError{
				Err:  "empty address in a multi-homed address list",
				Addr: addrs,
			}
		}
		ipaddrs = append(ipaddrs, net.IPAddr{IP: tcpa.IP, Zone: tcpa.Zone})
	}
	tcpa, err := net.ResolveTCPAddr(tcpnet, elems[len(elems)-1])
	if err != nil {
		return nil, err
	}
	if tcpa.IP != nil {
		ipaddrs = append(ipaddrs, net.IPAddr{IP: tcpa.IP, Zone: tcpa.Zone})
	} else if len(ipaddrs) > 0 {
		// The caller listed addresses and then ended with a bare port, as in
		// "1.2.3.4/5.6.7.8/:80". This used to discard every listed address and
		// return a wildcard, so a trailing separator in a configuration file
		// silently turned "listen on these two" into "listen on everything".
		return nil, &net.AddrError{
			Err:  "address list ends with a port and no address",
			Addr: addrs,
		}
	} else {
		// No addresses at all: a bare port means the wildcard, which is the
		// documented meaning of ":80".
		ipaddrs = nil
	}
	return &SCTPAddr{
		IPAddrs: ipaddrs,
		Port:    tcpa.Port,
	}, nil
}

// SCTPConnect establishes an association with addr on the socket fd.
//
// EISCONN and EALREADY are both reported as success, because they are the same
// kernel branch at two different association states. net/sctp/socket.c has, in
// __sctp_connect and again in sctp_connect_add_peer:
//
//	asoc = sctp_endpoint_lookup_assoc(ep, daddr, &transport);
//	if (asoc)
//	        return asoc->state >= SCTP_STATE_ESTABLISHED ? -EISCONN
//	                                                     : -EALREADY;
//
// So both mean "an association to this peer already exists on this endpoint".
// EISCONN says the handshake finished; EALREADY says it is still in CLOSED,
// COOKIE_WAIT or COOKIE_ECHOED. Neither is a failure to connect to somewhere the
// caller did not ask for — the association is the one that was requested.
//
// This matters because the early return skips the sctp_wait_for_connect that
// ends __sctp_connect on the normal path. On a blocking socket, which is what
// this package's dial path uses, that wait is what makes SCTPConnect synchronous;
// a caller that races itself into the EALREADY branch would otherwise be handed a
// hard error for an association that goes on to establish normally.
//
// Reproduced with testdata/optprobe/already.c: two CONNECTX3 calls against an
// unreachable address on one non-blocking socket give EINPROGRESS then EALREADY,
// repeatably.
//
// The blocking distinction is deliberate and is why EALREADY is not simply mapped
// to success unconditionally. On a blocking socket the kernel has already waited
// for the handshake, so an existing association means a connected socket. On a
// non-blocking one it does not wait, and EALREADY there means genuinely not yet
// connected — reporting success would hand the caller a socket that is still
// handshaking. Non-blocking callers get EALREADY unchanged, matching the
// EINPROGRESS they already have to handle. This package's own dial path creates
// blocking sockets, so it takes the first branch; SCTPConnect is exported, so the
// second is reachable.
//
// AssocID is not filled in on either early-return path, so 0 is returned with a
// nil error; callers needing the id read it back from the socket.
func SCTPConnect(fd int, addr *SCTPAddr) (int, error) {
	id, _, err := sctpConnect(fd, addr)
	return id, err
}

// sctpConnect is SCTPConnect, additionally reporting whether it returned
// success through the EALREADY branch rather than from a completed connect.
//
// Only that branch leaves the handshake unfinished, so only that branch needs
// confirming before a connection is handed out. Distinguishing it keeps the
// normal path free of extra syscalls, and — more importantly — keeps a slow but
// healthy handshake from being cut short by a verification timeout, which is
// what happened when the dial path confirmed unconditionally: dials that the
// kernel would have completed were failed with ETIMEDOUT under suite load.
func sctpConnect(fd int, addr *SCTPAddr) (assocID int, viaEALREADY bool, err error) {
	buf := addr.ToRawSockAddrBuf()
	param := GetAddrsOld{
		AddrNum: int32(len(buf)),
		Addrs:   uintptr(uintptr(unsafe.Pointer(&buf[0]))),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err = getsockopt(fd, SCTP_SOCKOPT_CONNECTX3, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err == nil {
		return int(param.AssocID), false, nil
	} else if isEstablishedAssoc(fd, err) {
		return 0, err == syscall.EALREADY, nil
	} else if err != syscall.ENOPROTOOPT {
		return 0, false, err
	}
	r0, _, err := setsockopt(fd, SCTP_SOCKOPT_CONNECTX, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if isEstablishedAssoc(fd, err) {
		return int(r0), err == syscall.EALREADY, nil
	}
	return int(r0), false, err
}

// isEstablishedAssoc reports whether err from a connect attempt means the socket
// already carries the association the caller asked for, and is connected.
//
// EISCONN always does: the kernel returns it only when the association it found
// is already at or past SCTP_STATE_ESTABLISHED.
//
// EALREADY is the same kernel branch below that state, so it means the endpoint
// holds the association but the handshake has not finished. On a blocking
// socket that is reported as success, because the caller driving SCTPConnect
// directly still has a connect in flight that will complete or fail on its own;
// on a non-blocking one the kernel has not waited, so it must reach the caller.
//
// It does *not* follow that the socket is usable yet, and callers that own the
// socket outright must not stop here — see waitEstablished, which the dial path
// uses to make sure it never returns a connection with no association behind it.
func isEstablishedAssoc(fd int, err error) bool {
	switch err {
	case syscall.EISCONN:
		return true
	case syscall.EALREADY:
		return !isNonblocking(fd)
	}
	return false
}

// connectSettleTimeout bounds the wait for an EALREADY handshake to finish.
//
// The association is already in COOKIE_WAIT or COOKIE_ECHOED, so on a healthy
// path it settles in milliseconds. The budget is nonetheless generous, because
// the cost of the two outcomes is asymmetric: waiting too long on a handshake
// that will never finish only delays an error the caller was going to get
// anyway, while giving up too early fails a dial the kernel would have
// completed. An earlier 1s ceiling did exactly that under load.
const connectSettleTimeout = 5 * time.Second

// waitEstablished waits up to timeout for fd's association to establish.
//
// This is what the dial path uses to keep its promise: DialSCTP returns a
// *SCTPConn, so it must not hand back one with no association behind it. The
// connect reporting EALREADY does not mean the handshake will finish — it is
// an early return that skips the kernel's own sctp_wait_for_connect — and
// measured under signal load, one EALREADY dial in two never established. The
// caller then got a connection whose GetStatus failed with EINVAL and whose
// first write failed with EPIPE, having been told the dial succeeded.
//
// It polls because there is nothing to select on: the association belongs to a
// connect that already returned. Returning false means the handshake did not
// finish in time and the dial reports failure, which is the honest answer and
// the one a caller can act on.
func waitEstablished(fd int, timeout time.Duration) bool {
	const interval = 2 * time.Millisecond
	deadline := time.Now().Add(timeout)
	for {
		if hasEstablishedAssoc(fd) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(interval)
	}
}

// hasEstablishedAssoc reports whether fd currently carries an association the
// kernel considers usable.
//
// SCTP_STATUS fails with EINVAL on a socket with no association, and reports
// state 0 (SCTP_EMPTY, which the kernel never leaves an established
// association in) when there is nothing to describe. Either answer means the
// socket is not connected.
func hasEstablishedAssoc(fd int) bool {
	status := &Status{}
	optlen := unsafe.Sizeof(*status)
	if _, _, err := getsockopt(fd, SCTP_STATUS,
		uintptr(unsafe.Pointer(status)), uintptr(unsafe.Pointer(&optlen))); err != nil {
		return false
	}
	return status.State != 0
}

func SCTPBind(fd int, addr *SCTPAddr, flags int) error {
	var option uintptr
	switch flags {
	case SCTP_BINDX_ADD_ADDR:
		option = SCTP_SOCKOPT_BINDX_ADD
	case SCTP_BINDX_REM_ADDR:
		option = SCTP_SOCKOPT_BINDX_REM
	default:
		return syscall.EINVAL
	}

	buf := addr.ToRawSockAddrBuf()
	_, _, err := setsockopt(fd, option, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return err
}

type SCTPConn struct {
	_fd                 int32
	notificationHandler NotificationHandler

	// Deadlines are absolute, as net.Conn specifies, and are converted to a
	// relative SO_RCVTIMEO/SO_SNDTIMEO immediately before each syscall. They
	// are stored as UnixNano; 0 means no deadline. Accessed atomically so a
	// deadline may be set from another goroutine while a call is in flight.
	readDeadline  int64
	writeDeadline int64

	// Tracks whether a non-zero SO_RCVTIMEO is currently programmed, so the
	// no-deadline path does not issue a setsockopt on every read.
	rcvTimeoSet int32
}

func (c *SCTPConn) fd() int {
	return int(atomic.LoadInt32(&c._fd))
}

func NewSCTPConn(fd int, handler NotificationHandler) *SCTPConn {
	conn := &SCTPConn{
		_fd:                 int32(fd),
		notificationHandler: handler,
	}
	return conn
}

func (c *SCTPConn) Write(b []byte) (int, error) {
	return c.SCTPWrite(b, nil)
}

func (c *SCTPConn) Read(b []byte) (int, error) {
	n, _, err := c.SCTPRead(b)
	if n < 0 {
		n = 0
	}
	return n, err
}

// SetInitMsg sets the association initialisation parameters (SCTP_INITMSG).
//
// Every field is a uint16 in the kernel. The arguments are ints, so a value
// outside that range used to be truncated silently: 65536 streams became 0,
// which the kernel reads as "leave the default", and a caller asking for more
// streams than SCTP can carry got the default instead of an error. Read them
// back with GetInitMsg.
func (c *SCTPConn) SetInitMsg(numOstreams, maxInstreams, maxAttempts, maxInitTimeout int) error {
	for _, v := range []int{numOstreams, maxInstreams, maxAttempts, maxInitTimeout} {
		if v < 0 || v > math.MaxUint16 {
			return syscall.EINVAL
		}
	}
	return setInitOpts(c.fd(), InitMsg{
		NumOstreams:    uint16(numOstreams),
		MaxInstreams:   uint16(maxInstreams),
		MaxAttempts:    uint16(maxAttempts),
		MaxInitTimeout: uint16(maxInitTimeout),
	})
}

func (c *SCTPConn) SubscribeEvents(flags int) error {
	var d, a, ad, sf, p, sh, pa, ada, au, se uint8
	if flags&SCTP_EVENT_DATA_IO > 0 {
		d = 1
	}
	if flags&SCTP_EVENT_ASSOCIATION > 0 {
		a = 1
	}
	if flags&SCTP_EVENT_ADDRESS > 0 {
		ad = 1
	}
	if flags&SCTP_EVENT_SEND_FAILURE > 0 {
		sf = 1
	}
	if flags&SCTP_EVENT_PEER_ERROR > 0 {
		p = 1
	}
	if flags&SCTP_EVENT_SHUTDOWN > 0 {
		sh = 1
	}
	if flags&SCTP_EVENT_PARTIAL_DELIVERY > 0 {
		pa = 1
	}
	if flags&SCTP_EVENT_ADAPTATION_LAYER > 0 {
		ada = 1
	}
	if flags&SCTP_EVENT_AUTHENTICATION > 0 {
		au = 1
	}
	if flags&SCTP_EVENT_SENDER_DRY > 0 {
		se = 1
	}
	param := EventSubscribe{
		DataIO:          d,
		Association:     a,
		Address:         ad,
		SendFailure:     sf,
		PeerError:       p,
		Shutdown:        sh,
		PartialDelivery: pa,
		AdaptationLayer: ada,
		Authentication:  au,
		SenderDry:       se,
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := setsockopt(c.fd(), SCTP_EVENTS, uintptr(unsafe.Pointer(&param)), uintptr(optlen))
	return err
}

// SubscribeEvent subscribes to a single notification type, or unsubscribes from
// it when on is false.
//
// This is the SCTP_EVENT option from RFC 6458 §6.2.2, which exists because
// SCTP_EVENTS — what SubscribeEvents uses — is deprecated: its struct has to
// grow every time an event is added, so a binary built against an older
// definition silently cannot reach the newer events. Naming one event per call
// has no such limit.
//
// eventType is a notification type such as SCTP_ASSOC_CHANGE. The kernel
// validates it and reports EINVAL for a type it does not know.
//
// The two options do not read the same state once an association exists, which
// was measured rather than assumed. On a socket with no association, an event
// set here reads back as set in the struct SubscribeEvents sends. On a connected
// socket it does not: AssocID 0 acts on that association, while SCTP_EVENTS
// reads the endpoint defaults, so the subscription shows as on through
// EventSubscribed and off through SCTP_EVENTS. Do not mix the two on a connected
// socket and expect either to report what the other set. Set whichever you use
// before connecting if you need one consistent view.
func (c *SCTPConn) SubscribeEvent(eventType SCTPNotificationType, on bool) error {
	param := Event{Type: uint16(eventType)}
	if on {
		param.On = 1
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := setsockopt(c.fd(), SCTP_EVENT,
		uintptr(unsafe.Pointer(&param)), uintptr(optlen))
	return err
}

// EventSubscribed reports whether a single notification type is subscribed.
//
// It is the getsockopt direction of SCTP_EVENT: the type to query goes in, and
// the kernel fills in whether it is on.
func (c *SCTPConn) EventSubscribed(eventType SCTPNotificationType) (bool, error) {
	param := Event{Type: uint16(eventType)}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(c.fd(), SCTP_EVENT,
		uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return false, err
	}
	return param.On != 0, nil
}

// SetRecvRcvInfo enables or disables delivery of SCTP_RCVINFO as ancillary data
// on each received message (RFC 6458 §8.1.29).
//
// This is the non-deprecated counterpart of the SCTP_SNDRCV data that
// SubscribeEvents(SCTP_EVENT_DATA_IO) asks for: RFC 6458 §5.3.2 marks
// SCTP_SNDRCV deprecated and directs callers to SCTP_SNDINFO and SCTP_RCVINFO.
// SCTPRead still reads the SCTP_SNDRCV form, so enabling this changes what the
// kernel is willing to send rather than what this package parses; it is here
// for callers driving recvmsg themselves through SyscallConn.
func (c *SCTPConn) SetRecvRcvInfo(on bool) error {
	return setsockoptInt(c.fd(), SCTP_RECVRCVINFO, on)
}

// SetRecvNxtInfo enables or disables delivery of SCTP_NXTINFO, which describes
// the message following the one being read (RFC 6458 §8.1.30).
func (c *SCTPConn) SetRecvNxtInfo(on bool) error {
	return setsockoptInt(c.fd(), SCTP_RECVNXTINFO, on)
}

// setsockoptInt sets one of the boolean-valued SCTP options. RFC 6458 specifies
// these as taking "an integer boolean flag", so the value is a 32 bit int
// rather than a single byte.
func setsockoptInt(fd int, optname uintptr, on bool) error {
	var val int32
	if on {
		val = 1
	}
	_, _, err := setsockopt(fd, optname, uintptr(unsafe.Pointer(&val)),
		unsafe.Sizeof(val))
	return err
}

func (c *SCTPConn) SubscribedEvents() (int, error) {
	param := EventSubscribe{}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(c.fd(), SCTP_EVENTS, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return 0, err
	}
	var flags int
	if param.DataIO > 0 {
		flags |= SCTP_EVENT_DATA_IO
	}
	if param.Association > 0 {
		flags |= SCTP_EVENT_ASSOCIATION
	}
	if param.Address > 0 {
		flags |= SCTP_EVENT_ADDRESS
	}
	if param.SendFailure > 0 {
		flags |= SCTP_EVENT_SEND_FAILURE
	}
	if param.PeerError > 0 {
		flags |= SCTP_EVENT_PEER_ERROR
	}
	if param.Shutdown > 0 {
		flags |= SCTP_EVENT_SHUTDOWN
	}
	if param.PartialDelivery > 0 {
		flags |= SCTP_EVENT_PARTIAL_DELIVERY
	}
	if param.AdaptationLayer > 0 {
		flags |= SCTP_EVENT_ADAPTATION_LAYER
	}
	if param.Authentication > 0 {
		flags |= SCTP_EVENT_AUTHENTICATION
	}
	if param.SenderDry > 0 {
		flags |= SCTP_EVENT_SENDER_DRY
	}
	return flags, nil
}

func (c *SCTPConn) SetDefaultSentParam(info *SndRcvInfo) error {
	optlen := unsafe.Sizeof(*info)
	_, _, err := setsockopt(c.fd(), SCTP_DEFAULT_SENT_PARAM, uintptr(unsafe.Pointer(info)), uintptr(optlen))
	return err
}

func (c *SCTPConn) GetDefaultSentParam() (*SndRcvInfo, error) {
	info := &SndRcvInfo{}
	optlen := unsafe.Sizeof(*info)
	_, _, err := getsockopt(c.fd(), SCTP_DEFAULT_SENT_PARAM, uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&optlen)))
	return info, err
}

func (c *SCTPConn) SetNoDelay(optval int) error {
	optlen := unsafe.Sizeof(optval)
	_, _, err := setsockopt(c.fd(), SCTP_NODELAY, uintptr(unsafe.Pointer(&optval)), optlen)
	return err
}

func (c *SCTPConn) GetNoDelay() (int, error) {
	optval := 0
	optlen := unsafe.Sizeof(optval)
	_, _, err := getsockopt(
		c.fd(),
		SCTP_NODELAY,
		uintptr(unsafe.Pointer(&optval)),
		uintptr(unsafe.Pointer(&optlen)),
	)
	return optval, err
}

func (c *SCTPConn) SetSackTimer(timer *SackTimer) error { // SackTimer
	optlen := unsafe.Sizeof(*timer)
	_, _, err := setsockopt(c.fd(), SCTP_DELAYED_SACK, uintptr(unsafe.Pointer(timer)), optlen)
	return err
}

func (c *SCTPConn) GetSackTimer() (*SackTimer, error) { // SackTimer
	timer := &SackTimer{}
	optlen := unsafe.Sizeof(*timer)
	_, _, err := getsockopt(
		c.fd(),
		SCTP_DELAYED_SACK,
		uintptr(unsafe.Pointer(timer)),
		uintptr(unsafe.Pointer(&optlen)),
	)
	return timer, err
}

// SetRtoInfo sets the association's retransmission timer parameters
// (SCTP_RTOINFO). Fields left zero are unchanged.
//
// Reducing Max is half of making an unreachable peer detectable promptly; see
// SetAssocInfo for the other half.
func (c *SCTPConn) SetRtoInfo(info *RtoInfo) error {
	optlen := unsafe.Sizeof(*info)
	_, _, err := setsockopt(c.fd(), SCTP_RTOINFO, uintptr(unsafe.Pointer(info)), optlen)
	return err
}

// GetRtoInfo reports the association's retransmission timer parameters.
func (c *SCTPConn) GetRtoInfo() (*RtoInfo, error) {
	info := &RtoInfo{}
	optlen := unsafe.Sizeof(*info)
	_, _, err := getsockopt(
		c.fd(),
		SCTP_RTOINFO,
		uintptr(unsafe.Pointer(info)),
		uintptr(unsafe.Pointer(&optlen)),
	)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// SetAssocInfo sets association parameters (SCTP_ASSOCINFO). Fields left zero
// are unchanged.
//
// Setting AsocMaxRxt bounds how many unacknowledged retransmissions the stack
// tolerates before declaring the association failed, which is what converts a
// peer that has silently gone away into an error the application can see.
func (c *SCTPConn) SetAssocInfo(info *AssocInfo) error {
	optlen := unsafe.Sizeof(*info)
	_, _, err := setsockopt(c.fd(), SCTP_ASSOCINFO, uintptr(unsafe.Pointer(info)), optlen)
	return err
}

// GetAssocInfo reports association parameters, including the peer's last
// advertised receive window.
func (c *SCTPConn) GetAssocInfo() (*AssocInfo, error) {
	info := &AssocInfo{}
	optlen := unsafe.Sizeof(*info)
	_, _, err := getsockopt(
		c.fd(),
		SCTP_ASSOCINFO,
		uintptr(unsafe.Pointer(info)),
		uintptr(unsafe.Pointer(&optlen)),
	)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// SetMaxSegSize sets the maximum fragment size the association will use
// (SCTP_MAXSEG, RFC 6458 8.1.16). Messages larger than this are fragmented
// across multiple DATA chunks rather than being sent as one.
//
// A value of zero restores the default, which is derived from the path MTU.
// The kernel clamps the request to what the path can carry, so read it back
// with GetMaxSegSize if the effective value matters.
func (c *SCTPConn) SetMaxSegSize(size int) error {
	if size < 0 || int64(size) > int64(^uint32(0)) {
		return errors.New("sctp: max segment size out of range")
	}
	val := AssocValue{AssocVal: uint32(size)}
	optlen := unsafe.Sizeof(val)
	_, _, err := setsockopt(
		c.fd(),
		SCTP_MAXSEG,
		uintptr(unsafe.Pointer(&val)),
		optlen,
	)
	return err
}

// GetMaxSegSize reports the association's current maximum fragment size.
func (c *SCTPConn) GetMaxSegSize() (int, error) {
	val := AssocValue{}
	optlen := unsafe.Sizeof(val)
	_, _, err := getsockopt(
		c.fd(),
		SCTP_MAXSEG,
		uintptr(unsafe.Pointer(&val)),
		uintptr(unsafe.Pointer(&optlen)),
	)
	if err != nil {
		return 0, err
	}
	return int(val.AssocVal), nil
}

// SetFragmentInterleave controls whether a partial delivery on one stream
// blocks delivery of messages on the others (RFC 6458 §8.1.20).
//
// level must be one of SCTPFragmentInterleaveNone, ...Other or ...Streams.
// Linux keeps a flag rather than a level, so it accepts anything and stores
// !=0 as 1: setting 2 and setting 3 both read back as 1, measured against a
// live kernel. An out-of-range value is therefore neither refused nor honoured,
// and the check here is what turns that into an error the caller can see.
//
// The default is SCTPFragmentInterleaveNone, which blocks every other message
// while a partial delivery is in progress. ...Other is the highest level that
// reads back. To get what RFC 6458 §8.1.20 describes for ...Streams, negotiate
// the I-DATA chunk with SetInterleavingSupported, which requires this to be
// non-zero first.
func (c *SCTPConn) SetFragmentInterleave(level int) error {
	switch level {
	case SCTPFragmentInterleaveNone, SCTPFragmentInterleaveOther,
		SCTPFragmentInterleaveStreams:
	default:
		return fmt.Errorf("sctp: fragment interleave level %d is not one of 0, 1 or 2", level)
	}
	return setsockoptInt32(c.fd(), SCTP_FRAGMENT_INTERLEAVE, int32(level))
}

// GetFragmentInterleave reports the current fragmented interleave level.
func (c *SCTPConn) GetFragmentInterleave() (int, error) {
	v, err := getsockoptInt32(c.fd(), SCTP_FRAGMENT_INTERLEAVE)
	return int(v), err
}

// SetPartialDeliveryPoint sets the message size, in bytes, at which the kernel
// starts delivering a message piecewise to free receive window for the peer
// (RFC 6458 §8.1.21).
//
// A lower value makes partial delivery happen more often. RFC 6458 notes the
// call fails if the value exceeds the socket receive buffer, so a caller raising
// this should raise SO_RCVBUF first.
//
// The negative check below is for the message, not for safety: a negative value
// reaches the kernel as a large unsigned number, which it already rejects with
// EINVAL for exceeding the receive buffer. Removing the check therefore keeps
// the tests green — it changes "partial delivery point -1 is negative" into
// "invalid argument", which is correct but says less.
func (c *SCTPConn) SetPartialDeliveryPoint(bytes int) error {
	if bytes < 0 {
		return fmt.Errorf("sctp: partial delivery point %d is negative", bytes)
	}
	return setsockoptInt32(c.fd(), SCTP_PARTIAL_DELIVERY_POINT, int32(bytes))
}

// GetPartialDeliveryPoint reports the current partial delivery point in bytes.
func (c *SCTPConn) GetPartialDeliveryPoint() (int, error) {
	v, err := getsockoptInt32(c.fd(), SCTP_PARTIAL_DELIVERY_POINT)
	return int(v), err
}

// SetMaxBurst bounds how many packets the association may emit back to back
// (RFC 6458 §8.1.24).
//
// Zero disables burst mitigation. The kernel default is 4, which was read back
// rather than taken from the specification.
func (c *SCTPConn) SetMaxBurst(burst int) error {
	if burst < 0 || int64(burst) > int64(^uint32(0)) {
		return fmt.Errorf("sctp: max burst %d out of range", burst)
	}
	return setAssocValue(c.fd(), SCTP_MAX_BURST, uint32(burst))
}

// GetMaxBurst reports the current maximum burst.
func (c *SCTPConn) GetMaxBurst() (int, error) {
	v, err := getAssocValue(c.fd(), SCTP_MAX_BURST)
	return int(v), err
}

// SetContext sets the context value reported with messages received from the
// peer (RFC 6458 §8.1.25).
//
// Per the RFC this affects received messages only; it does not change the
// context saved with outbound messages, which SCTPWrite carries per message in
// SndRcvInfo.Context.
func (c *SCTPConn) SetContext(context uint32) error {
	return setAssocValue(c.fd(), SCTP_CONTEXT, context)
}

// GetContext reports the current default context.
func (c *SCTPConn) GetContext() (uint32, error) {
	return getAssocValue(c.fd(), SCTP_CONTEXT)
}

// SetReusePort enables or disables binding several endpoints to one port
// (RFC 6458 §8.1.27).
//
// RFC 6458 restricts this to one-to-one style sockets, which is the only style
// this package creates, and says it has to be set before bind.
//
// Linux enforces that strictly: on a socket that is already bound or connected
// the call fails with EFAULT rather than being ignored, which was measured. A
// connection returned by DialSCTP or AcceptSCTP is therefore always too late —
// the option is only useful on a descriptor obtained before bind, for example
// inside the Control hook of a SocketConfig.
func (c *SCTPConn) SetReusePort(on bool) error {
	return setsockoptInt(c.fd(), SCTP_REUSE_PORT, on)
}

// SetDefaultSndInfo sets the send parameters applied to messages written without
// their own (RFC 6458 §8.1.31).
//
// This is the replacement for SetDefaultSentParam: RFC 6458 §8.1.31 deprecates
// SCTP_DEFAULT_SEND_PARAM along with the struct sctp_sndrcvinfo it carries.
// Prefer this for new code; the two write the same underlying defaults.
//
// PPID is passed to the kernel exactly as given. The kernel does not byte-swap
// it, and neither does this call, so a caller wanting the wire value that
// SCTPWrite produces should pass htonl of it — SCTPWrite converts per message,
// which is a difference worth noting when the two are mixed.
//
// The kernel rejects a short option, so this is one of the places where the Go
// struct size has to be right; TestStructLayoutsMatchKernel pins it.
func (c *SCTPConn) SetDefaultSndInfo(info *SndInfo) error {
	optlen := unsafe.Sizeof(*info)
	_, _, err := setsockopt(c.fd(), SCTP_DEFAULT_SNDINFO,
		uintptr(unsafe.Pointer(info)), optlen)
	return err
}

// GetDefaultSndInfo reports the current default send parameters.
func (c *SCTPConn) GetDefaultSndInfo() (*SndInfo, error) {
	info := &SndInfo{}
	optlen := unsafe.Sizeof(*info)
	_, _, err := getsockopt(c.fd(), SCTP_DEFAULT_SNDINFO,
		uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return info, nil
}

// SetAutoAsconf enables or disables announcing local address changes to the peer
// with ASCONF chunks (RFC 6458 §8.1.21).
//
// The option needs a bound socket: on a fresh unbound descriptor the kernel
// rejects it with EINVAL, which was measured. That is the opposite of
// SetReusePort, which must be set *before* bind — so a connection from DialSCTP
// or AcceptSCTP is the right place for this one and the wrong place for that
// one.
func (c *SCTPConn) SetAutoAsconf(on bool) error {
	return setsockoptInt(c.fd(), SCTP_AUTO_ASCONF, on)
}

// AutoAsconf reports whether ASCONF announcement is enabled.
func (c *SCTPConn) AutoAsconf() (bool, error) {
	v, err := getsockoptInt32(c.fd(), SCTP_AUTO_ASCONF)
	return v != 0, err
}

// SetPrSupported enables or disables the PR-SCTP partial reliability extension
// (RFC 7496 §4.5).
//
// Set it before connecting: the extension is negotiated in the INIT handshake,
// so a later call cannot add it to a live association.
//
// On a stock kernel this option changes nothing, because net.sctp.prsctp_enable
// defaults to 1 and the extension is therefore offered whether or not it is set
// here. PrSupported consequently reports true on an association where neither
// end touched the option — measured across all four enable combinations. The
// call is still worth making for a caller that cannot assume the sysctl, and
// setting it to false is the only way to opt an individual socket out.
//
// Despite RFC 7496 describing this as an on/off value, Linux carries it in a
// struct sctp_assoc_value and rejects a plain int with EINVAL — measured, not
// inferred from the header, which declares no struct for it.
func (c *SCTPConn) SetPrSupported(on bool) error {
	var v uint32
	if on {
		v = 1
	}
	return setAssocValue(c.fd(), SCTP_PR_SUPPORTED, v)
}

// PrSupported reports whether partial reliability is available on this
// association.
//
// It reports the negotiated outcome, not what SetPrSupported requested. With
// net.sctp.prsctp_enable at its default of 1 that outcome is true regardless of
// the socket option, so a true result here does not imply anyone asked for it.
// Compare ReconfigSupported, whose sysctl defaults to 0 and which therefore does
// track the option.
func (c *SCTPConn) PrSupported() (bool, error) {
	v, err := getAssocValue(c.fd(), SCTP_PR_SUPPORTED)
	return v != 0, err
}

// SetDefaultPrInfo sets the partial reliability policy applied to messages sent
// without their own (RFC 7496 §4.1).
//
// The meaning of Value depends on Policy; see the SCTPPrPolicy constants. A
// policy outside that set is rejected by the kernel with EINVAL.
//
// This is accepted on a socket where PrSupported reports false — the policy is
// recorded and simply never takes effect, because abandoning a message requires
// the FORWARD-TSN the extension negotiates. Enable SetPrSupported before
// connecting if the policy is meant to do anything.
func (c *SCTPConn) SetDefaultPrInfo(info *DefaultPrInfo) error {
	optlen := unsafe.Sizeof(*info)
	_, _, err := setsockopt(c.fd(), SCTP_DEFAULT_PRINFO,
		uintptr(unsafe.Pointer(info)), optlen)
	return err
}

// GetDefaultPrInfo reports the current default partial reliability policy.
func (c *SCTPConn) GetDefaultPrInfo() (*DefaultPrInfo, error) {
	info := &DefaultPrInfo{}
	optlen := unsafe.Sizeof(*info)
	_, _, err := getsockopt(c.fd(), SCTP_DEFAULT_PRINFO,
		uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return info, nil
}

// GetPrStreamStatus reports how many messages were abandoned on one stream under
// the given partial reliability policy (RFC 7496 §4.4).
//
// It needs an established association; on a socket without one the kernel
// returns EINVAL.
func (c *SCTPConn) GetPrStreamStatus(sid uint16, policy uint16) (*PrStatus, error) {
	st := &PrStatus{SID: sid, Policy: policy}
	optlen := unsafe.Sizeof(*st)
	_, _, err := getsockopt(c.fd(), SCTP_PR_STREAM_STATUS,
		uintptr(unsafe.Pointer(st)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return st, nil
}

// GetPrAssocStatus reports how many messages were abandoned across the whole
// association under the given partial reliability policy (RFC 7496 §4.3).
//
// This is the association-wide total; GetPrStreamStatus reports one stream. Both
// need an established association.
//
// The returned PrStatus.SID is not meaningful here — the option ignores it.
func (c *SCTPConn) GetPrAssocStatus(policy uint16) (*PrStatus, error) {
	st := &PrStatus{Policy: policy}
	optlen := unsafe.Sizeof(*st)
	_, _, err := getsockopt(c.fd(), SCTP_PR_ASSOC_STATUS,
		uintptr(unsafe.Pointer(st)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return st, nil
}

// SetReconfigSupported enables or disables the stream reconfiguration extension
// (RFC 6525 §6.1).
//
// Set it before connecting. Like SetPrSupported it is carried in a struct
// sctp_assoc_value rather than the plain int RFC 6525 describes.
func (c *SCTPConn) SetReconfigSupported(on bool) error {
	var v uint32
	if on {
		v = 1
	}
	return setAssocValue(c.fd(), SCTP_RECONFIG_SUPPORTED, v)
}

// ReconfigSupported reports whether stream reconfiguration is available.
//
// The value is negotiated, and the getter changes meaning once an association
// exists — which is easy to misread as the setter having failed:
//
//   - Before connecting it echoes what SetReconfigSupported wrote.
//   - After connecting it reports whether *both* ends enabled it. Setting it on
//     only one end reads back false there, and a set issued after connect never
//     changes the answer even though it returns success.
//
// That was measured across all three combinations rather than inferred. So a
// false result on a live association means the peer did not offer the extension,
// not that the local call was rejected.
func (c *SCTPConn) ReconfigSupported() (bool, error) {
	v, err := getAssocValue(c.fd(), SCTP_RECONFIG_SUPPORTED)
	return v != 0, err
}

// SetEnableStreamReset selects which stream reconfiguration requests this
// endpoint permits (RFC 6525 §6.3). mask is a combination of the
// SCTPEnableReset constants; zero permits none.
//
// This governs what the endpoint will accept and initiate, and is independent of
// SetReconfigSupported, which decides whether the extension is negotiated at
// all. Both are needed for reconfiguration to work.
func (c *SCTPConn) SetEnableStreamReset(mask uint32) error {
	if mask&^uint32(SCTPEnableResetStreamReq|SCTPEnableResetAssocReq|
		SCTPEnableChangeAssocReq) != 0 {
		return fmt.Errorf("sctp: stream reset mask %#x has unknown bits", mask)
	}
	return setAssocValue(c.fd(), SCTP_ENABLE_STREAM_RESET, mask)
}

// EnableStreamReset reports which stream reconfiguration requests are permitted.
func (c *SCTPConn) EnableStreamReset() (uint32, error) {
	return getAssocValue(c.fd(), SCTP_ENABLE_STREAM_RESET)
}

// AddStreams asks the peer to widen the association, adding inStreams inbound
// and outStreams outbound streams (RFC 6525 §6.5).
//
// This needs the reconfiguration extension negotiated — SetReconfigSupported on
// both ends before connecting — and SCTPEnableChangeAssocReq present in the mask
// SetEnableStreamReset installed. Without both the kernel refuses with
// ENOPROTOOPT, which is easy to misread as the option not existing.
//
// The request goes to the peer, so success here means it was sent and accepted,
// not that the streams are usable yet. GetStatus reports the counts once the
// peer has answered.
func (c *SCTPConn) AddStreams(inStreams, outStreams uint16) error {
	as := AddStreamsReq{InStreams: inStreams, OutStreams: outStreams}
	optlen := unsafe.Sizeof(as)
	_, _, err := setsockopt(c.fd(), SCTP_ADD_STREAMS,
		uintptr(unsafe.Pointer(&as)), optlen)
	return err
}

// ResetStreams restarts the sequence numbering of the named streams, or of every
// stream when streams is empty (RFC 6525 §6.3.2).
//
// direction is a combination of SCTPStreamResetIncoming and
// SCTPStreamResetOutgoing; at least one is required, since the kernel rejects a
// request with neither.
//
// Like AddStreams this needs the reconfiguration extension negotiated —
// SetReconfigSupported on both ends before connecting — plus
// SCTPEnableResetStreamReq in the SetEnableStreamReset mask. Without them the
// kernel answers ENOPROTOOPT, which reads like the option not existing.
//
// The option length has to cover the stream list, not just the fixed header:
// naming one stream while passing the bare struct length is rejected with
// EINVAL. That is handled here, and is the reason this takes a slice rather than
// exposing the raw struct.
func (c *SCTPConn) ResetStreams(direction uint16, streams ...uint16) error {
	if direction&^uint16(SCTPStreamResetIncoming|SCTPStreamResetOutgoing) != 0 {
		return fmt.Errorf("sctp: stream reset direction %#x has unknown bits",
			direction)
	}
	if direction == 0 {
		return fmt.Errorf("sctp: stream reset needs at least one of " +
			"SCTPStreamResetIncoming or SCTPStreamResetOutgoing")
	}
	if len(streams) > int(^uint16(0)) {
		return fmt.Errorf("sctp: %d streams exceeds the %d the request can "+
			"name", len(streams), int(^uint16(0)))
	}

	buf := buildResetStreams(direction, streams)
	_, _, err := setsockopt(c.fd(), SCTP_RESET_STREAMS,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return err
}

// buildResetStreams lays out struct sctp_reset_streams: an association id, the
// direction flags, the stream count, then the stream ids.
//
// Built as bytes rather than from a Go struct because the C struct ends in a
// flexible array, and the list has to be contiguous with the header in one
// allocation. Split out from ResetStreams so the offsets can be asserted
// directly — flags and count are adjacent uint16s, so a transposition is
// invisible to any length check.
func buildResetStreams(direction uint16, streams []uint16) []byte {
	const hdr = 8
	buf := make([]byte, hdr+2*len(streams))
	// AssocID at [0:4] stays zero: one-to-one sockets ignore it.
	nativeEndian.PutUint16(buf[4:6], direction)
	nativeEndian.PutUint16(buf[6:8], uint16(len(streams)))
	for i, sid := range streams {
		nativeEndian.PutUint16(buf[hdr+2*i:], sid)
	}
	return buf
}

// ResetAssoc restarts the association's sequence numbering as a whole
// (RFC 6525 §6.3.3).
//
// This needs the reconfiguration extension negotiated and
// SCTPEnableResetAssocReq in the SetEnableStreamReset mask.
func (c *SCTPConn) ResetAssoc() error {
	var id SCTPAssocID
	_, _, err := setsockopt(c.fd(), SCTP_RESET_ASSOC,
		uintptr(unsafe.Pointer(&id)), unsafe.Sizeof(id))
	return err
}

// SetAuthChunk adds one chunk type to the set this endpoint requires the peer to
// authenticate (RFC 4895 §6.1).
//
// The option is additive and set-only: each call adds a type, and there is no
// way to remove one or to read the set back other than LocalAuthChunks.
//
// RFC 4895 §6.1 says this must be set before the association is established. The
// kernel does not enforce that — a call on a connected socket succeeds — but the
// requirement stands, because the set is advertised in the INIT and a later
// addition cannot be communicated to the peer.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) SetAuthChunk(chunkType uint8) error {
	// struct sctp_authchunk is a single __u8, so the option is one byte and
	// setsockoptInt's 32-bit value would be rejected.
	_, _, err := setsockopt(c.fd(), SCTP_AUTH_CHUNK,
		uintptr(unsafe.Pointer(&chunkType)), unsafe.Sizeof(chunkType))
	return err
}

// SetAuthKey installs a shared key for authenticating chunks (RFC 4895 §6.3).
//
// keyNumber names the key for SetAuthActiveKey, DeleteAuthKey and
// DeactivateAuthKey. Key 0 is the null key every association starts with;
// overwriting it is permitted.
//
// The key may not be empty: the kernel rejects a zero-length key with EINVAL
// rather than treating it as a deletion. The upper bound measured here is 8192
// bytes, and the kernel validates the length against the option size, so a
// mismatch cannot make it read past the buffer.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) SetAuthKey(keyNumber uint16, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("sctp: auth key %d is empty; the kernel rejects a "+
			"zero-length key rather than treating it as a deletion, so use "+
			"DeleteAuthKey instead", keyNumber)
	}
	if len(key) > int(^uint16(0)) {
		return fmt.Errorf("sctp: auth key of %d bytes exceeds the %d the "+
			"length field can express", len(key), int(^uint16(0)))
	}

	buf := buildAuthKey(keyNumber, key)
	_, _, err := setsockopt(c.fd(), SCTP_AUTH_KEY,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return err
}

// buildAuthKey lays out struct sctp_authkey: an association id, the key number,
// the key length, then the key bytes.
//
// Split out from SetAuthKey for the same reason as buildResetStreams — the two
// uint16s are adjacent, so swapping them produces a buffer the kernel may still
// accept while installing a key of the wrong length under the wrong number.
func buildAuthKey(keyNumber uint16, key []byte) []byte {
	const hdr = 8
	buf := make([]byte, hdr+len(key))
	nativeEndian.PutUint16(buf[4:6], keyNumber)
	nativeEndian.PutUint16(buf[6:8], uint16(len(key)))
	copy(buf[hdr:], key)
	return buf
}

// DeleteAuthKey removes a shared key (RFC 4895 §6.8).
//
// The active key cannot be deleted — the kernel reports EINVAL — so select
// another with SetAuthActiveKey first, or deactivate this one. A key still needed
// to verify packets in flight should be deactivated rather than deleted.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) DeleteAuthKey(keyNumber uint16) error {
	return c.authKeyOp(SCTP_AUTH_DELETE_KEY, keyNumber)
}

// DeactivateAuthKey stops a shared key being used for new packets while leaving
// it able to verify packets already in flight (RFC 4895 §6.9).
//
// This is the safe half of key rollover: deactivate, let the peer's in-flight
// packets drain, then delete.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) DeactivateAuthKey(keyNumber uint16) error {
	return c.authKeyOp(SCTP_AUTH_DEACTIVATE_KEY, keyNumber)
}

// authKeyOp issues one of the set-only options taking a struct sctp_authkeyid.
func (c *SCTPConn) authKeyOp(optname uintptr, keyNumber uint16) error {
	id := AuthKeyID{KeyNumber: keyNumber}
	_, _, err := setsockopt(c.fd(), optname,
		uintptr(unsafe.Pointer(&id)), unsafe.Sizeof(id))
	return err
}

// SetHmacIdent sets the HMAC algorithms this endpoint offers, most preferred
// first (RFC 4895 §6.2).
//
// The kernel validates the identifiers and reports EOPNOTSUPP for one it does not
// implement — identifier 2 is unassigned in the IANA registry and is refused,
// which was measured. Use the SCTPAuthHmacID constants.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) SetHmacIdent(idents ...uint16) error {
	if len(idents) == 0 {
		return fmt.Errorf("sctp: SetHmacIdent needs at least one algorithm")
	}

	buf := buildHmacAlgo(idents)
	_, _, err := setsockopt(c.fd(), SCTP_HMAC_IDENT,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return err
}

// buildHmacAlgo lays out struct sctp_hmacalgo: a __u32 count followed by that
// many __u16 identifiers.
//
// Split out from SetHmacIdent so the byte layout can be asserted without a
// kernel. That matters because the count is 32 bits: writing it as a uint16
// leaves the correct bytes on a little-endian host and the wrong ones on a
// big-endian one, so no test on amd64 can catch the mistake through behaviour.
func buildHmacAlgo(idents []uint16) []byte {
	const hdr = 4
	buf := make([]byte, hdr+2*len(idents))
	nativeEndian.PutUint32(buf[:4], uint32(len(idents)))
	for i, id := range idents {
		nativeEndian.PutUint16(buf[hdr+2*i:], id)
	}
	return buf
}

// SetPeerAddrThlds sets the per-path retransmission thresholds that drive
// failure detection (RFC 7829 §7.2).
//
// A zeroed Address applies the thresholds to every path of the association,
// which is the form to use on the single-homed sockets this package usually
// creates.
func (c *SCTPConn) SetPeerAddrThlds(th *PeerAddrThlds) error {
	optlen := unsafe.Sizeof(*th)
	_, _, err := setsockopt(c.fd(), SCTP_PEER_ADDR_THLDS,
		uintptr(unsafe.Pointer(th)), optlen)
	return err
}

// GetPeerAddrThlds reports the current per-path retransmission thresholds.
func (c *SCTPConn) GetPeerAddrThlds() (*PeerAddrThlds, error) {
	th := &PeerAddrThlds{}
	optlen := unsafe.Sizeof(*th)
	_, _, err := getsockopt(c.fd(), SCTP_PEER_ADDR_THLDS,
		uintptr(unsafe.Pointer(th)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return th, nil
}

// SetPeerAddrThldsV2 sets the per-path thresholds including the probe cutoff that
// SetPeerAddrThlds cannot reach.
//
// This is a Linux extension of the RFC 7829 option: PathCpThld bounds how long a
// path in the Potentially Failed state keeps being probed. The kernel default is
// 0xffff, which means indefinitely.
func (c *SCTPConn) SetPeerAddrThldsV2(th *PeerAddrThldsV2) error {
	optlen := unsafe.Sizeof(*th)
	_, _, err := setsockopt(c.fd(), SCTP_PEER_ADDR_THLDS_V2,
		uintptr(unsafe.Pointer(th)), optlen)
	return err
}

// GetPeerAddrThldsV2 reports the per-path thresholds including the probe cutoff.
func (c *SCTPConn) GetPeerAddrThldsV2() (*PeerAddrThldsV2, error) {
	th := &PeerAddrThldsV2{}
	optlen := unsafe.Sizeof(*th)
	_, _, err := getsockopt(c.fd(), SCTP_PEER_ADDR_THLDS_V2,
		uintptr(unsafe.Pointer(th)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return th, nil
}

// GetAssocStats reads the per-association counters (SCTP_GET_ASSOC_STATS).
//
// This is a Linux extension with no RFC 6458 equivalent. It needs an established
// association; on a socket without one the kernel returns EINVAL.
//
// Reading resets AssocStats.MaxRto, so the value is the maximum observed since
// the previous call rather than since the association began.
func (c *SCTPConn) GetAssocStats() (*AssocStats, error) {
	st := &AssocStats{}
	optlen := unsafe.Sizeof(*st)
	_, _, err := getsockopt(c.fd(), SCTP_GET_ASSOC_STATS,
		uintptr(unsafe.Pointer(st)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return st, nil
}

// SetAuthActiveKey selects which shared key signs outbound AUTH chunks
// (RFC 4895 §6.5).
//
// The whole SCTP_AUTH_* family depends on the net.sctp.auth_enable sysctl, which
// is 0 on a stock kernel. With it off every one of these calls fails with
// EACCES — not EOPNOTSUPP, which is what makes it look like a permissions
// problem rather than a disabled feature. That was measured; enabling the sysctl
// makes them all work.
func (c *SCTPConn) SetAuthActiveKey(keyNumber uint16) error {
	id := AuthKeyID{KeyNumber: keyNumber}
	optlen := unsafe.Sizeof(id)
	_, _, err := setsockopt(c.fd(), SCTP_AUTH_ACTIVE_KEY,
		uintptr(unsafe.Pointer(&id)), optlen)
	return err
}

// AuthActiveKey reports which shared key currently signs outbound AUTH chunks.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) AuthActiveKey() (uint16, error) {
	id := AuthKeyID{}
	optlen := unsafe.Sizeof(id)
	_, _, err := getsockopt(c.fd(), SCTP_AUTH_ACTIVE_KEY,
		uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return 0, err
	}
	return id.KeyNumber, nil
}

// HmacIdent reports the HMAC algorithms this endpoint offers, in preference
// order (RFC 4895 §6.2).
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) HmacIdent() ([]uint16, error) {
	// struct sctp_hmacalgo is a __u32 count followed by a flexible array of
	// __u16. The kernel writes as many identifiers as fit and reduces the
	// option length to what it used, so the buffer only has to be large
	// enough; maxHmacIdents is well past the two algorithms RFC 4895 defines.
	const maxHmacIdents = 32
	var buf [4 + 2*maxHmacIdents]byte
	optlen := uintptr(len(buf))
	_, _, err := getsockopt(c.fd(), SCTP_HMAC_IDENT,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return parseHmacIdents(buf[:], int(optlen))
}

// parseHmacIdents decodes a struct sctp_hmacalgo: a __u32 count followed by that
// many __u16 identifiers.
//
// Split out from HmacIdent so the bounds handling can be tested without a
// kernel, since a real one will not produce the count/length disagreement this
// has to survive.
func parseHmacIdents(buf []byte, optlen int) ([]uint16, error) {
	if optlen < 4 || optlen > len(buf) {
		return nil, fmt.Errorf("sctp: SCTP_HMAC_IDENT returned %d bytes, "+
			"which is not a struct sctp_hmacalgo in a %d byte buffer",
			optlen, len(buf))
	}
	n := nativeEndian.Uint32(buf[:4])
	// Trust the returned length over the count: the count is what the kernel
	// says it wrote, the length is what it actually wrote, and a disagreement
	// must not become a read past the buffer.
	if avail := uint32(optlen-4) / 2; n > avail {
		n = avail
	}
	idents := make([]uint16, n)
	for i := range idents {
		idents[i] = nativeEndian.Uint16(buf[4+2*i : 6+2*i])
	}
	return idents, nil
}

// LocalAuthChunks reports the chunk types this endpoint requires the peer to
// authenticate (RFC 4895 §6.7).
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) LocalAuthChunks() ([]uint8, error) {
	return c.authChunks(SCTP_LOCAL_AUTH_CHUNKS)
}

// PeerAuthChunks reports the chunk types the peer requires this endpoint to
// authenticate (RFC 4895 §6.6).
//
// It needs an established association: without one the kernel returns EINVAL,
// since there is no peer to have told us anything. See SetAuthActiveKey about
// net.sctp.auth_enable.
func (c *SCTPConn) PeerAuthChunks() ([]uint8, error) {
	return c.authChunks(SCTP_PEER_AUTH_CHUNKS)
}

// authChunks reads one of the two SCTP_*_AUTH_CHUNKS options. struct
// sctp_authchunks is an assoc id followed by a flexible array of chunk types,
// and as with SCTP_HMAC_IDENT the kernel reduces the option length to what it
// wrote.
func (c *SCTPConn) authChunks(optname uintptr) ([]uint8, error) {
	const maxAuthChunks = 256
	var buf [4 + maxAuthChunks]byte
	optlen := uintptr(len(buf))
	_, _, err := getsockopt(c.fd(), optname,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return parseAuthChunks(buf[:], int(optlen))
}

// parseAuthChunks decodes a struct sctp_authchunks: an association id followed by
// the chunk types, with the option length bounding how many were written.
//
// The association id is not part of the list, so dropping the leading four bytes
// is the whole job — and getting that wrong would prepend four zero bytes, which
// read as four DATA chunk types (type 0) and would be indistinguishable from a
// peer genuinely requiring DATA to be authenticated.
func parseAuthChunks(buf []byte, optlen int) ([]uint8, error) {
	if optlen < 4 || optlen > len(buf) {
		return nil, fmt.Errorf("sctp: auth chunks option returned %d bytes, "+
			"which is not a struct sctp_authchunks in a %d byte buffer",
			optlen, len(buf))
	}
	chunks := make([]uint8, optlen-4)
	copy(chunks, buf[4:optlen])
	return chunks, nil
}

// GetReusePort reports whether port reuse is enabled.
func (c *SCTPConn) GetReusePort() (bool, error) {
	v, err := getsockoptInt32(c.fd(), SCTP_REUSE_PORT)
	return v != 0, err
}

// setsockoptInt32 sets one of the plain integer-valued SCTP options. RFC 6458
// specifies these as taking an integer, and the kernel reports a 4 byte option
// length for each of them.
func setsockoptInt32(fd int, optname uintptr, val int32) error {
	_, _, err := setsockopt(fd, optname, uintptr(unsafe.Pointer(&val)),
		unsafe.Sizeof(val))
	return err
}

// getsockoptInt32 reads one of the plain integer-valued SCTP options.
func getsockoptInt32(fd int, optname uintptr) (int32, error) {
	var val int32
	optlen := unsafe.Sizeof(val)
	_, _, err := getsockopt(fd, optname, uintptr(unsafe.Pointer(&val)),
		uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return 0, err
	}
	return val, nil
}

// setAssocValue sets one of the options carrying struct sctp_assoc_value. The
// association id is left zero, which one-to-one sockets ignore.
func setAssocValue(fd int, optname uintptr, val uint32) error {
	av := AssocValue{AssocVal: val}
	_, _, err := setsockopt(fd, optname, uintptr(unsafe.Pointer(&av)),
		unsafe.Sizeof(av))
	return err
}

// PeerAddrParams mirrors struct sctp_paddrparams (RFC 6458 §8.1.12), the
// per-path timers.
//
// Flags decides which of the other fields are read: each value has an
// ENABLE/DISABLE pair in the SPP_ constants, and a value with neither bit set is
// ignored. So this cannot be used to clear a setting by passing zero, and a
// caller who wants to change one thing should read the current parameters,
// modify them, and write them back.
//
// HBInterval is the one that usually matters. On an idle association nothing
// but the heartbeat detects that a path has gone silent, and its default of 30
// seconds was unreachable from this package before.
//
// Address selects the path. Leaving it zeroed addresses the association as a
// whole, which is what a one-to-one socket normally wants; to name one path,
// copy a raw sockaddr in — GetPeerAddrs returns them decoded, and
// SCTPAddr.ToRawSockAddrBuf encodes one back.
//
// This is the one struct in the package that cannot simply mirror the kernel's
// field by field. sctp_paddrparams is declared packed and aligned(4), and the
// 128-byte address leaves spp_pathmtu at offset 138 — a uint32 on a two-byte
// boundary, which Go will not lay out at any cost. So the exported form is an
// ordinary Go struct and the packed form is built on the way in and out.
// TestPeerAddrParamsLayoutMatchesKernel pins every offset.
type PeerAddrParams struct {
	AssocID SCTPAssocID
	// Address selects the path. Leaving it zeroed addresses the association as
	// a whole, which is what a one-to-one socket normally wants; to name one
	// path, copy in the bytes SCTPAddr.ToRawSockAddrBuf produces.
	Address [128]byte
	// HBInterval is the heartbeat period in milliseconds. Needs SPP_HB_ENABLE.
	HBInterval uint32
	// PathMaxRxt is the retransmission count after which this path is
	// considered inactive.
	PathMaxRxt uint16
	// PathMTU overrides path MTU discovery. Needs SPP_PMTUD_DISABLE.
	PathMTU uint32
	// SackDelay is the delayed acknowledgement timer in milliseconds. Needs
	// SPP_SACKDELAY_ENABLE.
	SackDelay uint32
	Flags     uint32
	// IPv6FlowLabel needs SPP_IPV6_FLOWLABEL.
	IPv6FlowLabel uint32
	// DSCP needs SPP_DSCP.
	DSCP uint8
}

// paddrparamsSize is sizeof(struct sctp_paddrparams): 155 bytes of fields
// rounded up to the struct's declared 4-byte alignment.
const paddrparamsSize = 156

// Field offsets within the packed struct, named so the marshalling below reads
// as the layout rather than as arithmetic.
const (
	pppAssocID    = 0
	pppAddress    = 4
	pppHBInterval = 132
	pppPathMaxRxt = 136
	pppPathMTU    = 138
	pppSackDelay  = 142
	pppFlags      = 146
	pppFlowLabel  = 150
	pppDSCP       = 154
)

func (p *PeerAddrParams) marshal() []byte {
	b := make([]byte, paddrparamsSize)
	nativeEndian.PutUint32(b[pppAssocID:], uint32(p.AssocID))
	copy(b[pppAddress:pppAddress+128], p.Address[:])
	nativeEndian.PutUint32(b[pppHBInterval:], p.HBInterval)
	nativeEndian.PutUint16(b[pppPathMaxRxt:], p.PathMaxRxt)
	nativeEndian.PutUint32(b[pppPathMTU:], p.PathMTU)
	nativeEndian.PutUint32(b[pppSackDelay:], p.SackDelay)
	nativeEndian.PutUint32(b[pppFlags:], p.Flags)
	nativeEndian.PutUint32(b[pppFlowLabel:], p.IPv6FlowLabel)
	b[pppDSCP] = p.DSCP
	return b
}

func (p *PeerAddrParams) unmarshal(b []byte) {
	p.AssocID = SCTPAssocID(nativeEndian.Uint32(b[pppAssocID:]))
	copy(p.Address[:], b[pppAddress:pppAddress+128])
	p.HBInterval = nativeEndian.Uint32(b[pppHBInterval:])
	p.PathMaxRxt = nativeEndian.Uint16(b[pppPathMaxRxt:])
	p.PathMTU = nativeEndian.Uint32(b[pppPathMTU:])
	p.SackDelay = nativeEndian.Uint32(b[pppSackDelay:])
	p.Flags = nativeEndian.Uint32(b[pppFlags:])
	p.IPv6FlowLabel = nativeEndian.Uint32(b[pppFlowLabel:])
	p.DSCP = b[pppDSCP]
}

// SetPeerAddrParams writes the per-path parameters (SCTP_PEER_ADDR_PARAMS).
//
// Set the matching SPP_ flag for each field that should take effect; see
// PeerAddrParams.
func (c *SCTPConn) SetPeerAddrParams(p *PeerAddrParams) error {
	b := p.marshal()
	_, _, err := setsockopt(c.fd(), SCTP_PEER_ADDR_PARAMS,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	return err
}

// GetPeerAddrParams reads the per-path parameters (SCTP_PEER_ADDR_PARAMS).
//
// Zero the Address of the value passed in to ask about the association rather
// than one path.
func (c *SCTPConn) GetPeerAddrParams(p *PeerAddrParams) error {
	// Only the association id and the address go in — they are the lookup key.
	// Marshalling the whole value would send the caller's own HBInterval,
	// Flags, DSCP and flow label down as well, and any field the kernel does
	// not overwrite would come back looking like a reading when it is just the
	// caller's input echoed.
	req := PeerAddrParams{AssocID: p.AssocID, Address: p.Address}
	b := req.marshal()
	optlen := uintptr(len(b))
	_, _, err := getsockopt(c.fd(), SCTP_PEER_ADDR_PARAMS,
		uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return err
	}
	p.unmarshal(b)
	return nil
}

// GetPeerAddrInfo reads one peer address's state (SCTP_GET_PEER_ADDR_INFO,
// RFC 6458 §8.2.2).
//
// This is the only way to see a secondary path. GetStatus reports the primary
// only, so on the multi-homed associations this package exists to support,
// nothing else says whether the other paths are active, what their round-trip
// time is, or what congestion window they have.
//
// Set Address on the value passed in to name the path; the rest is filled in.
func (c *SCTPConn) GetPeerAddrInfo(info *PeerAddrinfo) error {
	optlen := unsafe.Sizeof(*info)
	_, _, err := getsockopt(c.fd(), SCTP_GET_PEER_ADDR_INFO,
		uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&optlen)))
	return err
}

// SetAdaptationLayer announces an adaptation layer indication to the peer
// (SCTP_ADAPTATION_LAYER, RFC 6458 §8.1.11).
//
// The value is opaque to SCTP and is carried in the INIT, so it must be set
// before the association is established to reach the peer. The other direction
// has always been available: the peer's indication arrives as an
// AdaptationIndication notification.
func (c *SCTPConn) SetAdaptationLayer(ind uint32) error {
	v := struct{ AdaptationInd uint32 }{ind}
	_, _, err := setsockopt(c.fd(), SCTP_ADAPTATION_LAYER,
		uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v))
	return err
}

// GetAdaptationLayer reports the adaptation layer indication this endpoint
// announces.
func (c *SCTPConn) GetAdaptationLayer() (uint32, error) {
	v := struct{ AdaptationInd uint32 }{}
	optlen := unsafe.Sizeof(v)
	_, _, err := getsockopt(c.fd(), SCTP_ADAPTATION_LAYER,
		uintptr(unsafe.Pointer(&v)), uintptr(unsafe.Pointer(&optlen)))
	return v.AdaptationInd, err
}

// SetDisableFragments controls whether a message larger than the path MTU is
// fragmented (SCTP_DISABLE_FRAGMENTS, RFC 6458 §8.1.5).
//
// With fragmentation off, a message that does not fit is refused with
// EMSGSIZE rather than split. That is what a caller wants when the peer is a
// device that cannot reassemble, and it turns a silent behaviour change into an
// error they can see.
func (c *SCTPConn) SetDisableFragments(on bool) error {
	return setSockoptBool(c.fd(), SCTP_DISABLE_FRAGMENTS, on)
}

// DisableFragments reports whether message fragmentation is disabled.
func (c *SCTPConn) DisableFragments() (bool, error) {
	return getSockoptBool(c.fd(), SCTP_DISABLE_FRAGMENTS)
}

// SetMappedV4Addr controls whether IPv4 addresses are reported to the caller in
// IPv4-mapped IPv6 form on an AF_INET6 socket (SCTP_I_WANT_MAPPED_V4_ADDR,
// RFC 6458 §8.1.15).
func (c *SCTPConn) SetMappedV4Addr(on bool) error {
	return setSockoptBool(c.fd(), SCTP_I_WANT_MAPPED_V4_ADDR, on)
}

// MappedV4Addr reports whether IPv4-mapped addresses are in use.
func (c *SCTPConn) MappedV4Addr() (bool, error) {
	return getSockoptBool(c.fd(), SCTP_I_WANT_MAPPED_V4_ADDR)
}

// SetAsconfSupported negotiates dynamic address reconfiguration, RFC 5061, for
// this socket.
//
// This is what makes SetAutoAsconf mean anything. net.sctp.addip_enable
// defaults to 0, and with it off the endpoint never negotiates ASCONF, so
// SetAutoAsconf succeeds and then adding a local address mid-association puts
// nothing on the wire — measured as zero ASCONF chunks, against two ASCONF and
// two ASCONF-ACK once this is on.
//
// It must be set before the socket is bound: the capability goes in the INIT.
// The kernel also requires AUTH for ASCONF, so SetAuthSupported belongs with it.
func (c *SCTPConn) SetAsconfSupported(on bool) error {
	return setAssocValueBool(c.fd(), SCTP_ASCONF_SUPPORTED, on)
}

// AsconfSupported reports the negotiated outcome for ASCONF.
func (c *SCTPConn) AsconfSupported() (bool, error) {
	v, err := getAssocValue(c.fd(), SCTP_ASCONF_SUPPORTED)
	return v != 0, err
}

// SetAuthSupported negotiates AUTH, RFC 4895, for this socket.
//
// The AUTH accessors on this type are documented as needing
// net.sctp.auth_enable, which is a system-wide sysctl only root can set. That
// is the older half of the story: this option turns AUTH on for one socket with
// the sysctl still at its default of 0, which was measured rather than assumed.
//
// Set it before binding — the capability is announced in the INIT.
func (c *SCTPConn) SetAuthSupported(on bool) error {
	return setAssocValueBool(c.fd(), SCTP_AUTH_SUPPORTED, on)
}

// AuthSupported reports the negotiated outcome for AUTH.
func (c *SCTPConn) AuthSupported() (bool, error) {
	v, err := getAssocValue(c.fd(), SCTP_AUTH_SUPPORTED)
	return v != 0, err
}

// SetEcnSupported negotiates explicit congestion notification for this socket.
func (c *SCTPConn) SetEcnSupported(on bool) error {
	return setAssocValueBool(c.fd(), SCTP_ECN_SUPPORTED, on)
}

// EcnSupported reports the negotiated outcome for ECN.
func (c *SCTPConn) EcnSupported() (bool, error) {
	v, err := getAssocValue(c.fd(), SCTP_ECN_SUPPORTED)
	return v != 0, err
}

// SetInterleavingSupported negotiates user message interleaving, the I-DATA
// chunk of RFC 8260.
//
// The kernel refuses this with EPERM unless net.sctp.intl_enable is on and
// SetFragmentInterleave has been given a non-zero level, because interleaving
// without that would deliver fragments of different messages to a caller not
// expecting them.
func (c *SCTPConn) SetInterleavingSupported(on bool) error {
	return setAssocValueBool(c.fd(), SCTP_INTERLEAVING_SUPPORTED, on)
}

// InterleavingSupported reports the negotiated outcome for message
// interleaving.
func (c *SCTPConn) InterleavingSupported() (bool, error) {
	v, err := getAssocValue(c.fd(), SCTP_INTERLEAVING_SUPPORTED)
	return v != 0, err
}

// SetExposePotentiallyFailed controls whether the PF state of RFC 7829 is
// reported (SCTP_EXPOSE_POTENTIALLY_FAILED_STATE).
//
// PF is the early warning that a path has missed retransmissions but has not
// yet been declared unreachable, and it is the reason RFC 7829 exists: without
// it a caller learns about a dead path only when the retransmission budget runs
// out, which on the defaults is minutes. The kernel hides it unless asked,
// following net.sctp.pf_expose, so a caller who correctly subscribes to
// SCTP_PEER_ADDR_CHANGE and never sees SCTP_ADDR_POTENTIALLY_FAILED concludes
// the state does not exist.
//
// level is one of the SCTPPFState constants. SCTPPFStateHiddenNoOverride locks
// the setting, after which this returns EACCES.
func (c *SCTPConn) SetExposePotentiallyFailed(level uint32) error {
	return setAssocValue(c.fd(), SCTP_EXPOSE_POTENTIALLY_FAILED_STATE, level)
}

// ExposePotentiallyFailed reports the current PF exposure level.
func (c *SCTPConn) ExposePotentiallyFailed() (uint32, error) {
	return getAssocValue(c.fd(), SCTP_EXPOSE_POTENTIALLY_FAILED_STATE)
}

// SetStreamScheduler selects the order outbound streams are served in
// (SCTP_STREAM_SCHEDULER, RFC 8260 §4).
//
// sched is one of the SCTPSched constants. The default, SCTPSchedFCFS, ignores
// streams entirely and sends in the order messages were handed over, so a
// caller who separates traffic by stream and expects that to affect scheduling
// gets nothing until this is set.
func (c *SCTPConn) SetStreamScheduler(sched uint32) error {
	return setAssocValue(c.fd(), SCTP_STREAM_SCHEDULER, sched)
}

// StreamScheduler reports the scheduler in force.
func (c *SCTPConn) StreamScheduler() (uint32, error) {
	return getAssocValue(c.fd(), SCTP_STREAM_SCHEDULER)
}

// streamValue mirrors struct sctp_stream_value.
type streamValue struct {
	AssocID     SCTPAssocID
	StreamID    uint16
	StreamValue uint16
}

// SetStreamSchedulerValue sets a per-stream parameter for the scheduler in
// force (SCTP_STREAM_SCHEDULER_VALUE).
//
// Under SCTPSchedPrio the value is the stream's priority, lowest served first.
// Under the other schedulers it is ignored.
func (c *SCTPConn) SetStreamSchedulerValue(streamID, value uint16) error {
	sv := streamValue{StreamID: streamID, StreamValue: value}
	_, _, err := setsockopt(c.fd(), SCTP_STREAM_SCHEDULER_VALUE,
		uintptr(unsafe.Pointer(&sv)), unsafe.Sizeof(sv))
	return err
}

// GetStreamSchedulerValue reads the scheduler parameter for one stream.
func (c *SCTPConn) GetStreamSchedulerValue(streamID uint16) (uint16, error) {
	sv := streamValue{StreamID: streamID}
	optlen := unsafe.Sizeof(sv)
	_, _, err := getsockopt(c.fd(), SCTP_STREAM_SCHEDULER_VALUE,
		uintptr(unsafe.Pointer(&sv)), uintptr(unsafe.Pointer(&optlen)))
	return sv.StreamValue, err
}

// GetInitMsg reads the association initialisation parameters (SCTP_INITMSG).
//
// SetInitMsg has always been available; this is the direction that was missing,
// which meant a caller could not check what the kernel actually recorded — the
// zero fields of an InitMsg mean "leave the default", so what was set and what
// is in force are different things.
func (c *SCTPConn) GetInitMsg() (*InitMsg, error) {
	options := &InitMsg{}
	optlen := unsafe.Sizeof(*options)
	_, _, err := getsockopt(c.fd(), SCTP_INITMSG,
		uintptr(unsafe.Pointer(options)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return options, nil
}

// setSockoptBool writes one of the options carrying a bare int used as a
// boolean.
func setSockoptBool(fd int, optname uintptr, on bool) error {
	var v int32
	if on {
		v = 1
	}
	_, _, err := setsockopt(fd, optname, uintptr(unsafe.Pointer(&v)),
		unsafe.Sizeof(v))
	return err
}

// getSockoptBool reads one of the options carrying a bare int used as a
// boolean.
func getSockoptBool(fd int, optname uintptr) (bool, error) {
	var v int32
	optlen := unsafe.Sizeof(v)
	_, _, err := getsockopt(fd, optname, uintptr(unsafe.Pointer(&v)),
		uintptr(unsafe.Pointer(&optlen)))
	return v != 0, err
}

// setAssocValueBool writes a struct sctp_assoc_value option used as a boolean.
func setAssocValueBool(fd int, optname uintptr, on bool) error {
	var v uint32
	if on {
		v = 1
	}
	return setAssocValue(fd, optname, v)
}

// getAssocValue reads one of the options carrying struct sctp_assoc_value.
func getAssocValue(fd int, optname uintptr) (uint32, error) {
	av := AssocValue{}
	optlen := unsafe.Sizeof(av)
	_, _, err := getsockopt(fd, optname, uintptr(unsafe.Pointer(&av)),
		uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return 0, err
	}
	return av.AssocVal, nil
}

func (c *SCTPConn) GetStatus() (*Status, error) { // Status
	sctpStatus := &Status{}
	optlen := unsafe.Sizeof(*sctpStatus)
	_, _, err := getsockopt(
		c.fd(),
		SCTP_STATUS,
		uintptr(unsafe.Pointer(sctpStatus)),
		uintptr(unsafe.Pointer(&optlen)),
	)
	return sctpStatus, err
}

func (c *SCTPConn) Getsockopt(optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return getsockopt(c.fd(), optname, optval, optlen)
}

func (c *SCTPConn) Setsockopt(optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return setsockopt(c.fd(), optname, optval, optlen)
}

// resolveFromRawAddr decodes the packed sockaddr array the kernel returns for
// SCTP_GET_LOCAL_ADDRS, SCTP_GET_PEER_ADDRS and SCTP_PRIMARY_ADDR.
//
// Each entry is sized by its own family: 16 bytes for AF_INET, 28 for
// AF_INET6. The family is read per entry and the offset advanced by what that
// entry occupies, rather than reading the first entry's family and striding
// the whole array by it.
//
// On Linux the two are equivalent today. The kernel answers an AF_INET socket
// with all AF_INET entries and an AF_INET6 socket with all AF_INET6 entries,
// v4-mapping any IPv4 addresses bound to it, so the reply is uniform even for
// an association multi-homed across both families. That was measured against
// the kernel rather than assumed, including a socket explicitly bound to ::1
// and 127.0.0.1 via sctp_bindx.
//
// The per-entry walk is kept because nothing in the interface guarantees that.
// The reply is a packed array of variable-size sockaddrs, and a fixed stride
// is only correct while every entry happens to be the same size: if any kernel
// or any other platform returns a mixed reply, striding by the first family
// silently decodes every subsequent address from the wrong offset and returns
// it with no error. The cost of reading the family per entry is a load and a
// branch.
//
// limit bounds the walk to the buffer the caller actually owns. n arrives
// from the kernel and is trusted for the size of the result slice, but never
// for how far to read.
func resolveFromRawAddr(ptr unsafe.Pointer, n int) (*SCTPAddr, error) {
	return resolveFromRawAddrBuf(ptr, n, 0)
}

// resolveFromRawAddrBuf is resolveFromRawAddr with an explicit bound on the
// readable region.
//
// A limit of 0 disables the bounds checks, which is what resolveFromRawAddr
// passes. Every caller inside this package supplies a real bound; the
// unbounded form remains only because the tests exercise the decode path
// without one. Prefer this function with the size of the buffer the kernel
// filled: without it, a count that disagrees with the data walks off the end.
func resolveFromRawAddrBuf(ptr unsafe.Pointer, n int, limit uintptr) (*SCTPAddr, error) {
	if n < 0 {
		return nil, fmt.Errorf("negative address count: %d", n)
	}
	addr := &SCTPAddr{
		IPAddrs: make([]net.IPAddr, 0, n),
	}

	var offset uintptr
	for i := 0; i < n; i++ {
		// Reading the family needs the first two bytes of this entry to be
		// inside the buffer before anything is dereferenced.
		//
		// The per-family size checks below reject the same inputs one step
		// later, so removing this one keeps every test green. It is kept
		// regardless: those checks run after the family has been read, and
		// reading the family of an entry that starts past the end is itself
		// the out-of-bounds access being guarded against.
		if limit != 0 && offset+2 > limit {
			return nil, fmt.Errorf(
				"address %d starts past the end of the %d byte reply", i, limit)
		}
		entry := unsafe.Pointer(uintptr(ptr) + offset)

		// Read the family as the two bytes it is, rather than through
		// RawSockaddrAny. That struct is 112 bytes, so converting to it to
		// reach a field in its first two claims the whole span: for the last
		// entry of a tightly sized reply that runs past the allocation, and
		// -race rejects it as a pointer straddling multiple allocations even
		// though only the family is ever read. sa_family_t is uint16 and sits
		// at offset 0 of every sockaddr.
		switch family := *(*uint16)(entry); family {
		case syscall.AF_INET:
			size := unsafe.Sizeof(syscall.RawSockaddrInet4{})
			if limit != 0 && offset+size > limit {
				return nil, fmt.Errorf(
					"IPv4 address %d extends past the end of the %d byte reply",
					i, limit)
			}
			a := (*syscall.RawSockaddrInet4)(entry)
			if i == 0 {
				addr.Port = int(ntohs(a.Port))
			}
			// Copy out of the kernel buffer: a.Addr[:] aliases memory the
			// caller is free to reuse once this returns.
			ip := make(net.IP, net.IPv4len)
			copy(ip, a.Addr[:])
			addr.IPAddrs = append(addr.IPAddrs, net.IPAddr{IP: ip})
			offset += size
		case syscall.AF_INET6:
			size := unsafe.Sizeof(syscall.RawSockaddrInet6{})
			if limit != 0 && offset+size > limit {
				return nil, fmt.Errorf(
					"IPv6 address %d extends past the end of the %d byte reply",
					i, limit)
			}
			a := (*syscall.RawSockaddrInet6)(entry)
			if i == 0 {
				addr.Port = int(ntohs(a.Port))
			}
			var zone string
			if ifi, err := net.InterfaceByIndex(int(a.Scope_id)); err == nil {
				zone = ifi.Name
			}
			ip := make(net.IP, net.IPv6len)
			copy(ip, a.Addr[:])
			addr.IPAddrs = append(addr.IPAddrs, net.IPAddr{IP: ip, Zone: zone})
			offset += size
		default:
			return nil, fmt.Errorf("unknown address family: %d", family)
		}
	}
	return addr, nil
}

func sctpGetAddrs(fd, id, optname int) (*SCTPAddr, error) {

	type getaddrs struct {
		assocId int32
		addrNum uint32
		addrs   [4096]byte
	}
	param := getaddrs{
		assocId: int32(id),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(fd, uintptr(optname), uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	// addrNum comes from the kernel. Bound the walk by the buffer that was
	// actually provided rather than trusting it to describe what fits.
	return resolveFromRawAddrBuf(unsafe.Pointer(&param.addrs), int(param.addrNum),
		unsafe.Sizeof(param.addrs))
}

func (c *SCTPConn) SCTPGetPrimaryPeerAddr() (*SCTPAddr, error) {

	type sctpGetSetPrim struct {
		assocId int32
		addrs   [128]byte
	}
	param := sctpGetSetPrim{
		assocId: int32(0),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(c.fd(), SCTP_PRIMARY_ADDR, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return resolveFromRawAddrBuf(unsafe.Pointer(&param.addrs), 1,
		unsafe.Sizeof(param.addrs))
}

func (c *SCTPConn) SCTPLocalAddr(id int) (*SCTPAddr, error) {
	return sctpGetAddrs(c.fd(), id, SCTP_GET_LOCAL_ADDRS)
}

func (c *SCTPConn) SCTPRemoteAddr(id int) (*SCTPAddr, error) {
	return sctpGetAddrs(c.fd(), id, SCTP_GET_PEER_ADDRS)
}

func (c *SCTPConn) LocalAddr() net.Addr {
	addr, err := sctpGetAddrs(c.fd(), 0, SCTP_GET_LOCAL_ADDRS)
	if err != nil {
		return nil
	}
	return addr
}

func (c *SCTPConn) RemoteAddr() net.Addr {
	addr, err := sctpGetAddrs(c.fd(), 0, SCTP_GET_PEER_ADDRS)
	if err != nil {
		return nil
	}
	return addr
}

// SetDeadline sets both the read and write deadlines.
//
// A zero time.Time clears the deadline, as with net.Conn.
func (c *SCTPConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the absolute time after which reads fail.
//
// A read that exceeds the deadline returns an error satisfying
// errors.Is(err, os.ErrDeadlineExceeded). The deadline applies to each read
// as a whole: ReadMsg, which may need several recvmsg calls to reassemble a
// message, is bounded by the deadline overall rather than per call.
//
// Unlike net.Conn, setting a deadline does not interrupt a read that is
// already blocked; it takes effect from the next read. The deadline is
// realised with SO_RCVTIMEO, which the kernel only consults when a call
// begins.
func (c *SCTPConn) SetReadDeadline(t time.Time) error {
	atomic.StoreInt64(&c.readDeadline, timeToUnixNano(t))
	return nil
}

// SetWriteDeadline sets the absolute time after which writes fail. The
// caveats on SetReadDeadline apply equally.
func (c *SCTPConn) SetWriteDeadline(t time.Time) error {
	atomic.StoreInt64(&c.writeDeadline, timeToUnixNano(t))
	return nil
}

func timeToUnixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// toDeadlineErr maps the kernel's timeout errno onto os.ErrDeadlineExceeded,
// so callers can use errors.Is regardless of which syscall reported it.
func toDeadlineErr(err error) error {
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
		return os.ErrDeadlineExceeded
	}
	return err
}

type SCTPListener struct {
	// _fd is accessed atomically and set to -1 by Close, so a second Close
	// cannot release a descriptor number the kernel has since handed to
	// another socket. Use fd() to read it.
	_fd int32

	// pad keeps acceptDeadline 8-byte aligned on 32-bit targets, where Go only
	// guarantees 64-bit alignment for the first word of an allocated struct and
	// atomic.LoadInt64 panics on a misaligned address. Placing it after
	// notificationHandler, which is one word, would put it at offset 12 there.
	_ int32

	// acceptDeadline is absolute, in UnixNano; 0 means none. Accessed
	// atomically so it may be set while an Accept is in flight.
	acceptDeadline int64

	// rcvTimeoSet tracks whether a non-zero SO_RCVTIMEO is programmed, so the
	// no-deadline path does not issue a setsockopt on every accept.
	rcvTimeoSet int32

	notificationHandler NotificationHandler
}

// SetDeadline sets the absolute time after which Accept fails.
//
// An Accept that exceeds the deadline returns an error satisfying
// errors.Is(err, os.ErrDeadlineExceeded). A zero time.Time clears it, as with
// net.Conn. This mirrors net.TCPListener.SetDeadline, which net.Listener itself
// does not require.
//
// The same caveat as SetReadDeadline applies: the deadline is realised with
// SO_RCVTIMEO, which the kernel consults when a call begins, so setting one does
// not interrupt an Accept that is already blocked. It takes effect from the next
// Accept. To unblock one already in flight, close the listener.
func (ln *SCTPListener) SetDeadline(t time.Time) error {
	if ln.fd() < 0 {
		return syscall.EBADF
	}
	atomic.StoreInt64(&ln.acceptDeadline, timeToUnixNano(t))
	return nil
}

func (ln *SCTPListener) fd() int {
	return int(atomic.LoadInt32(&ln._fd))
}

func (ln *SCTPListener) Addr() net.Addr {
	laddr, err := sctpGetAddrs(ln.fd(), 0, SCTP_GET_LOCAL_ADDRS)
	if err != nil {
		return nil
	}
	return laddr
}

type SCTPSndRcvInfoWrappedConn struct {
	conn *SCTPConn
	// subErr records a failure to subscribe to SCTP_EVENT_DATA_IO. Reads
	// report it rather than returning messages with no ancillary data.
	subErr error
}

// NewSCTPSndRcvInfoWrappedConn wraps conn so that Read and Write carry a
// SndRcvInfo header inline, ahead of the payload.
//
// The whole type depends on SCTP_EVENT_DATA_IO being subscribed, since that is
// what makes the kernel return the ancillary data the header is built from.
// The subscription used to be attempted and its error discarded, which fails
// quietly in the worst way: every Read then finds no ancillary data and writes
// a zeroed header, so the caller reads a well-formed SndRcvInfo reporting
// stream 0 and PPID 0 for every message regardless of which stream it arrived
// on.
//
// This signature cannot return an error without breaking callers, so the
// failure is kept and returned from the first Read or Write instead.
func NewSCTPSndRcvInfoWrappedConn(conn *SCTPConn) *SCTPSndRcvInfoWrappedConn {
	c := &SCTPSndRcvInfoWrappedConn{conn: conn}
	if err := conn.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		c.subErr = fmt.Errorf(
			"sctp: subscribing to SCTP_EVENT_DATA_IO failed, so no message can "+
				"carry its SndRcvInfo: %w", err)
	}
	return c
}

func (c *SCTPSndRcvInfoWrappedConn) Write(b []byte) (int, error) {
	if c.subErr != nil {
		return 0, c.subErr
	}
	if len(b) < int(sndRcvInfoSize) {
		return 0, syscall.EINVAL
	}
	info := (*SndRcvInfo)(unsafe.Pointer(&b[0]))
	n, err := c.conn.SCTPWrite(b[sndRcvInfoSize:], info)
	return n + int(sndRcvInfoSize), err
}

func (c *SCTPSndRcvInfoWrappedConn) Read(b []byte) (int, error) {
	if c.subErr != nil {
		return 0, c.subErr
	}
	if len(b) < int(sndRcvInfoSize) {
		return 0, syscall.EINVAL
	}
	n, info, err := c.conn.SCTPRead(b[sndRcvInfoSize:])
	if err != nil {
		return n, err
	}
	if info != nil {
		copy(b, toBuf(info))
	} else {
		// No ancillary data came back, so there is nothing to describe the
		// message. Zero the header rather than leaving whatever the caller
		// had in b, which would otherwise be read as a valid SndRcvInfo.
		hdr := b[:sndRcvInfoSize]
		for i := range hdr {
			hdr[i] = 0
		}
	}
	return n + int(sndRcvInfoSize), err
}

func (c *SCTPSndRcvInfoWrappedConn) Close() error {
	return c.conn.Close()
}

func (c *SCTPSndRcvInfoWrappedConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *SCTPSndRcvInfoWrappedConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *SCTPSndRcvInfoWrappedConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *SCTPSndRcvInfoWrappedConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *SCTPSndRcvInfoWrappedConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *SCTPSndRcvInfoWrappedConn) SetWriteBuffer(bytes int) error {
	return c.conn.SetWriteBuffer(bytes)
}

func (c *SCTPSndRcvInfoWrappedConn) GetWriteBuffer() (int, error) {
	return c.conn.GetWriteBuffer()
}

func (c *SCTPSndRcvInfoWrappedConn) SetReadBuffer(bytes int) error {
	return c.conn.SetReadBuffer(bytes)
}

func (c *SCTPSndRcvInfoWrappedConn) GetReadBuffer() (int, error) {
	return c.conn.GetReadBuffer()
}

// SocketConfig contains options for the SCTP socket.
type SocketConfig struct {
	// If Control is not nil it is called after the socket is created but before
	// it is bound or connected.
	Control func(network, address string, c syscall.RawConn) error
	// NotificationHandler defines actions taken on received notifications when MSG_NOTIFICATION flag is set.
	NotificationHandler NotificationHandler
	// InitMsg is the options to send in the initial SCTP message
	InitMsg InitMsg
}

func (cfg *SocketConfig) Listen(net string, laddr *SCTPAddr) (*SCTPListener, error) {
	return listenSCTPExtConfig(net, laddr, cfg.InitMsg, cfg.Control, cfg.NotificationHandler)
}

func (cfg *SocketConfig) Dial(net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	return dialSCTPExtConfig(net, laddr, raddr, cfg.InitMsg, cfg.Control, cfg.NotificationHandler)
}

// DialContext is Dial with a context; see DialSCTPContext for what the context
// bounds and why Dial cannot offer it.
func (cfg *SocketConfig) DialContext(ctx context.Context, net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	return dialSCTPExtConfigContext(ctx, net, laddr, raddr, cfg.InitMsg, cfg.Control, cfg.NotificationHandler)
}
