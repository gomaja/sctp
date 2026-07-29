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
	"sync"
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
// is Association.Max.Retrans from RFC 4960 section 8.2. Once that many
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
	// Path.Max.Retrans without a response. See RFC 4960 section 8.2.
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
	Address [128]byte // if needed from here, retrieve using resolveFromRawAddr(unsafe.Pointer(&PeerAddrinfo.Address), 1), or get it from *SCTPConn.SCTPGetPrimaryPeerAddr()
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
	info := SndRcvInfo{}
	sndRcvInfoSize = unsafe.Sizeof(info)
}

func toBuf(v interface{}) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, nativeEndian, v)
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

func setNumOstreams(fd, num int) error {
	return setInitOpts(fd, InitMsg{NumOstreams: uint16(num)})
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

func resolveFromRawAddr(ptr unsafe.Pointer, n int) (*SCTPAddr, error) {
	addr := &SCTPAddr{
		IPAddrs: make([]net.IPAddr, n),
	}

	switch family := (*(*syscall.RawSockaddrAny)(ptr)).Addr.Family; family {
	case syscall.AF_INET:
		addr.Port = int(ntohs(uint16((*(*syscall.RawSockaddrInet4)(ptr)).Port)))
		tmp := syscall.RawSockaddrInet4{}
		size := unsafe.Sizeof(tmp)
		for i := 0; i < n; i++ {
			a := *(*syscall.RawSockaddrInet4)(unsafe.Pointer(
				uintptr(ptr) + size*uintptr(i)))
			addr.IPAddrs[i] = net.IPAddr{IP: a.Addr[:]}
		}
	case syscall.AF_INET6:
		addr.Port = int(ntohs(uint16((*(*syscall.RawSockaddrInet4)(ptr)).Port)))
		tmp := syscall.RawSockaddrInet6{}
		size := unsafe.Sizeof(tmp)
		for i := 0; i < n; i++ {
			a := *(*syscall.RawSockaddrInet6)(unsafe.Pointer(
				uintptr(ptr) + size*uintptr(i)))
			var zone string
			ifi, err := net.InterfaceByIndex(int(a.Scope_id))
			if err == nil {
				zone = ifi.Name
			}
			addr.IPAddrs[i] = net.IPAddr{IP: a.Addr[:], Zone: zone}
		}
	default:
		return nil, fmt.Errorf("unknown address family: %d", family)
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
	return resolveFromRawAddr(unsafe.Pointer(&param.addrs), int(param.addrNum))
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
	return resolveFromRawAddr(unsafe.Pointer(&param.addrs), 1)
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
	m                   sync.Mutex
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
}

func NewSCTPSndRcvInfoWrappedConn(conn *SCTPConn) *SCTPSndRcvInfoWrappedConn {
	conn.SubscribeEvents(SCTP_EVENT_DATA_IO)
	return &SCTPSndRcvInfoWrappedConn{conn}
}

func (c *SCTPSndRcvInfoWrappedConn) Write(b []byte) (int, error) {
	if len(b) < int(sndRcvInfoSize) {
		return 0, syscall.EINVAL
	}
	info := (*SndRcvInfo)(unsafe.Pointer(&b[0]))
	n, err := c.conn.SCTPWrite(b[sndRcvInfoSize:], info)
	return n + int(sndRcvInfoSize), err
}

func (c *SCTPSndRcvInfoWrappedConn) Read(b []byte) (int, error) {
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
