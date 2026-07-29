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
	SCTP_GET_PEER_ADDRS    = 108
	SCTP_GET_LOCAL_ADDRS   = 109
	SCTP_SOCKOPT_CONNECTX  = 110
	SCTP_SOCKOPT_CONNECTX3 = 111

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
)

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
type Event struct {
	// AssocID is ignored on the one-to-one style sockets this package creates.
	AssocID SCTPAssocID
	// Type is a notification type, e.g. SCTP_ASSOC_CHANGE.
	Type uint16
	// On is 1 to subscribe and 0 to unsubscribe.
	On uint8
	_  uint8
}

const (
	SCTP_CMSG_INIT = iota
	SCTP_CMSG_SNDRCV
	SCTP_CMSG_SNDINFO
	SCTP_CMSG_RCVINFO
	SCTP_CMSG_NXTINFO
)

const (
	SCTP_UNORDERED = 1 << iota
	SCTP_ADDR_OVER
	SCTP_ABORT
	SCTP_SACK_IMMEDIATELY
	SCTP_EOF
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
// is Association.Max.Retrans from RFC 9260 section 8.2 (which obsoleted RFC
// 4960). Once that many
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
	// Path.Max.Retrans without a response. See RFC 9260 section 8.2, which
	// obsoleted RFC 4960.
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

type SndInfo struct {
	SID     uint16
	Flags   uint16
	PPID    uint32
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
// see https://tools.ietf.org/html/rfc4960#page-25
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

func ResolveSCTPAddr(network, addrs string) (*SCTPAddr, error) {
	tcpnet := ""
	switch network {
	case "", "sctp":
		tcpnet = "tcp"
	case "sctp4":
		tcpnet = "tcp4"
	case "sctp6":
		tcpnet = "tcp6"
	default:
		return nil, fmt.Errorf("invalid net: %s", network)
	}
	elems := strings.Split(addrs, "/")
	if len(elems) == 0 {
		return nil, fmt.Errorf("invalid input: %s", addrs)
	}
	ipaddrs := make([]net.IPAddr, 0, len(elems))
	for _, e := range elems[:len(elems)-1] {
		tcpa, err := net.ResolveTCPAddr(tcpnet, e+":")
		if err != nil {
			return nil, err
		}
		ipaddrs = append(ipaddrs, net.IPAddr{IP: tcpa.IP, Zone: tcpa.Zone})
	}
	tcpa, err := net.ResolveTCPAddr(tcpnet, elems[len(elems)-1])
	if err != nil {
		return nil, err
	}
	if tcpa.IP != nil {
		ipaddrs = append(ipaddrs, net.IPAddr{IP: tcpa.IP, Zone: tcpa.Zone})
	} else {
		ipaddrs = nil
	}
	return &SCTPAddr{
		IPAddrs: ipaddrs,
		Port:    tcpa.Port,
	}, nil
}

func SCTPConnect(fd int, addr *SCTPAddr) (int, error) {
	buf := addr.ToRawSockAddrBuf()
	param := GetAddrsOld{
		AddrNum: int32(len(buf)),
		Addrs:   uintptr(uintptr(unsafe.Pointer(&buf[0]))),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(fd, SCTP_SOCKOPT_CONNECTX3, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err == nil {
		return int(param.AssocID), nil
	} else if err == syscall.EISCONN {
		// The association is already up. CONNECTX3 reports EISCONN once the
		// handshake has completed, which under load can happen before it
		// returns: the socket is established and writable, so reporting a
		// failure here throws away a working connection. AssocID is not filled
		// in on this path; callers that need it read it back from the socket.
		return 0, nil
	} else if err != syscall.ENOPROTOOPT {
		return 0, err
	}
	r0, _, err := setsockopt(fd, SCTP_SOCKOPT_CONNECTX, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if err == syscall.EISCONN {
		return int(r0), nil
	}
	return int(r0), err
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

func (c *SCTPConn) SetInitMsg(numOstreams, maxInstreams, maxAttempts, maxInitTimeout int) error {
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

func (c *SCTPConn) PeelOff(id int) (*SCTPConn, error) {
	type peeloffArg struct {
		assocId int32
		sd      int
	}
	param := peeloffArg{
		assocId: int32(id),
	}
	optlen := unsafe.Sizeof(param)
	_, _, err := getsockopt(c.fd(), SCTP_SOCKOPT_PEELOFF, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	return &SCTPConn{_fd: int32(param.sd)}, nil
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

// applyTimeout programs optname (SO_RCVTIMEO or SO_SNDTIMEO) from an absolute
// deadline. It reports ErrDeadlineExceeded when the deadline has already
// passed, since a zero timeval means "block forever" rather than "expire
// immediately" and would otherwise hang.
func applyTimeout(fd int, optname int, deadline int64) error {
	if deadline == 0 {
		// No deadline: clear any timeout left by a previous call. Callers
		// that track whether one is programmed skip this entirely.
		return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, optname,
			&syscall.Timeval{})
	}

	d := time.Until(time.Unix(0, deadline))
	if d <= 0 {
		return os.ErrDeadlineExceeded
	}

	// Round up so a sub-microsecond remainder does not truncate to zero,
	// which the kernel would read as "no timeout".
	usec := (d.Nanoseconds() + 999) / 1000

	// Timeval field widths differ by platform (int64 on linux/amd64, int32 on
	// linux/386 and darwin). syscall.NsecToTimeval builds the right shape for
	// the target, so convert back to nanoseconds rather than assigning the
	// fields directly.
	tv := syscall.NsecToTimeval(usec * 1000)
	if tv.Sec == 0 && tv.Usec == 0 {
		tv.Usec = 1
	}
	return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, optname, &tv)
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
	_fd                 int32
	notificationHandler NotificationHandler
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
