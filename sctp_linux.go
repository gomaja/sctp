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
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

func setsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	// FIXME: syscall.SYS_SETSOCKOPT is undefined on 386
	r0, r1, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		SOL_SCTP,
		optname,
		optval,
		optlen,
		0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

func getsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	if runtime.GOARCH == "s390x" {
		optlen = uintptr(unsafe.Pointer(&optlen))
	}
	// FIXME: syscall.SYS_GETSOCKOPT is undefined on 386
	r0, r1, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		SOL_SCTP,
		optname,
		optval,
		optlen,
		0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

type rawConn struct {
	sockfd int
}

func (r rawConn) Control(f func(fd uintptr)) error {
	f(uintptr(r.sockfd))
	return nil
}

func (r rawConn) Read(f func(fd uintptr) (done bool)) error {
	panic("not implemented")
}

func (r rawConn) Write(f func(fd uintptr) (done bool)) error {
	panic("not implemented")
}

func (c *SCTPConn) SyscallConn() (syscall.RawConn, error) {
	fd := c.fd()
	if fd < 0 {
		return nil, syscall.EINVAL
	}
	return &rawConn{sockfd: int(fd)}, nil
}

func (c *SCTPConn) SCTPWrite(b []byte, info *SndRcvInfo) (int, error) {
	var cbuf []byte
	if info != nil {
		cbuf = buildSndRcvCmsg(info)
	}
	// Writes use MSG_DONTWAIT and so never block; SO_SNDTIMEO would have no
	// effect on them. Enforce the write deadline directly instead, so a
	// deadline already in the past fails rather than being ignored.
	if deadline := atomic.LoadInt64(&c.writeDeadline); deadline != 0 {
		if time.Until(time.Unix(0, deadline)) <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
	}
	return syscall.SendmsgN(c.fd(), b, cbuf, nil, syscall.MSG_DONTWAIT)
}

// buildSndRcvCmsg lays out the SCTP_SNDRCV control message for one send.
//
// This replaces two toBuf calls and an append. toBuf goes through
// binary.Write, which reflects over the struct and writes into a bytes.Buffer —
// four allocations per call, so eight per message plus the append's copy. The
// layout is fixed and TestStructLayoutsMatchKernel pins it, so writing the bytes
// directly is equivalent and needs one allocation.
//
// It also fixes a latent data race. The previous version byte-swapped
// info.PPID in place, wrote the struct, then swapped it back:
//
//	oldPPID := info.PPID
//	info.PPID = htonl(info.PPID)
//	cmsgBuf := toBuf(info)
//	info.PPID = oldPPID
//
// Two goroutines sharing one *SndRcvInfo — which callers do, since it is
// otherwise read-only — could observe the swapped value or lose the restore.
// Nothing here mutates the caller's struct.
func buildSndRcvCmsg(info *SndRcvInfo) []byte {
	// Derived from the struct rather than written as a literal, so a field added
	// to SndRcvInfo cannot leave this sending a short message.
	//
	// No test distinguishes this from a hardcoded 32 today, and that was
	// measured rather than assumed: CmsgSpace rounds to a 16-byte boundary, so
	// CmsgSpace(28) and CmsgSpace(32) are both 48 and every plausible wrong
	// constant produces an identical buffer. The derivation is defence against a
	// future change, not a fix for a present bug.
	dataLen := int(unsafe.Sizeof(SndRcvInfo{}))
	// CmsgLen(0) is the header size. CmsgSpace(0) is the same 16 bytes here, so
	// the two are interchangeable on this platform; CmsgLen is used because it is
	// the one that means "header only" rather than "header plus alignment".
	hdrLen := syscall.CmsgLen(0)
	buf := make([]byte, syscall.CmsgSpace(dataLen))

	hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&buf[0]))
	hdr.Level = syscall.IPPROTO_SCTP
	hdr.Type = SCTP_CMSG_SNDRCV
	// The bit width of Len is platform-specific, so SetLen is used rather than
	// assigning it. Note this keeps the original code's CmsgSpace rather than
	// CmsgLen: on this platform the two agree for a 32-byte payload, and
	// changing it would alter the bytes on the wire for every existing caller.
	hdr.SetLen(syscall.CmsgSpace(dataLen))

	// Field offsets from struct sctp_sndrcvinfo. PPID goes to the wire in
	// network byte order; every other field is host order.
	d := buf[hdrLen:]
	nativeEndian.PutUint16(d[0:2], info.Stream)
	nativeEndian.PutUint16(d[2:4], info.SSN)
	nativeEndian.PutUint16(d[4:6], info.Flags)
	// d[6:8] is the pad after Flags.
	nativeEndian.PutUint32(d[8:12], htonl(info.PPID))
	nativeEndian.PutUint32(d[12:16], info.Context)
	nativeEndian.PutUint32(d[16:20], info.TTL)
	nativeEndian.PutUint32(d[20:24], info.TSN)
	nativeEndian.PutUint32(d[24:28], info.CumTSN)
	nativeEndian.PutUint32(d[28:32], uint32(info.AssocID))
	return buf
}

// SCTPWriteInfo sends one message using the non-deprecated ancillary data types,
// optionally attaching a partial reliability policy and an authentication key.
//
// This is the send-side counterpart to the SCTP_RCVINFO support on the read path.
// RFC 6458 §5.3.2 titles the struct sctp_sndrcvinfo that SCTPWrite sends
// "DEPRECATED" and splits it into SCTP_SNDINFO for sending and SCTP_RCVINFO for
// receiving; this emits SCTP_SNDINFO.
//
// SCTPWrite is unchanged and still emits SCTP_SNDRCV, because switching it would
// change the bytes on every existing caller's socket. The kernel accepts either,
// and in fact accepts both in one sendmsg without complaint, so the two can be
// mixed freely on the same association — that was measured.
//
// Any of the three may be nil:
//
//   - info nil sends with the socket defaults from SetDefaultSndInfo.
//   - pr adds SCTP_CMSG_PRINFO, overriding the default policy from
//     SetDefaultPrInfo for this message only. It needs PR-SCTP negotiated;
//     see SetPrSupported.
//   - auth adds SCTP_CMSG_AUTHINFO, naming the shared key to authenticate this
//     message with. It needs net.sctp.auth_enable; see SetAuthActiveKey.
//
// Unlike SCTPWrite, this does not byte-swap PPID. SndInfo.PPID goes to the kernel
// exactly as given, matching SetDefaultSndInfo, so a caller moving between the
// two does not get a silently different value on the wire. Callers wanting the
// SCTPWrite convention should pass htonl of their identifier.
func (c *SCTPConn) SCTPWriteInfo(b []byte, info *SndInfo, pr *PrInfo, auth *AuthInfo) (int, error) {
	var cbuf []byte
	appendCmsg := func(cmsgType int32, data []byte) {
		hdr := &syscall.Cmsghdr{
			Level: syscall.IPPROTO_SCTP,
			Type:  cmsgType,
		}
		// The bit width of hdr.Len is platform-specific, so SetLen is used
		// rather than assigning Len directly.
		hdr.SetLen(syscall.CmsgLen(len(data)))
		cbuf = append(cbuf, toBuf(hdr)...)
		cbuf = append(cbuf, data...)
		// Each control message starts at a platform-aligned offset, so pad up
		// to where the next header has to begin. Without this the kernel reads
		// the second cmsg header from the wrong offset.
		if pad := syscall.CmsgSpace(len(data)) - syscall.CmsgLen(len(data)); pad > 0 {
			cbuf = append(cbuf, make([]byte, pad)...)
		}
	}

	// AUTHINFO goes first deliberately. It is a 2-byte payload, the only one of
	// the three whose CmsgSpace exceeds its CmsgLen, so it is the only cmsg
	// whose alignment padding is observable — and padding is only read when
	// another control message follows. Emitting it last would leave the padding
	// logic untestable, since the bytes after the final cmsg are never
	// inspected. The kernel does not care about the order.
	if auth != nil {
		appendCmsg(SCTP_CMSG_AUTHINFO, toBuf(auth))
	}
	if info != nil {
		appendCmsg(SCTP_CMSG_SNDINFO, toBuf(info))
	}
	if pr != nil {
		appendCmsg(SCTP_CMSG_PRINFO, toBuf(pr))
	}

	// Same deadline handling as SCTPWrite: MSG_DONTWAIT means SO_SNDTIMEO
	// would not apply, so an expired deadline has to be checked here.
	if deadline := atomic.LoadInt64(&c.writeDeadline); deadline != 0 {
		if time.Until(time.Unix(0, deadline)) <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
	}
	return syscall.SendmsgN(c.fd(), b, cbuf, nil, syscall.MSG_DONTWAIT)
}

// parseSndRcvInfo extracts the per-message information from a control message
// buffer, accepting either form the kernel may have sent.
//
// SCTP_SNDRCV is what SubscribeEvents(SCTP_EVENT_DATA_IO) asks for, and RFC 6458
// §5.3.2 titles it "DEPRECATED", directing callers to SCTP_SNDINFO for sending
// and SCTP_RCVINFO (§5.3.5) for receiving. SetRecvRcvInfo enables the latter.
//
// Both are handled here because enabling only the modern option used to lose the
// message's stream and PPID silently: the kernel sent SCTP_RCVINFO, nothing here
// recognised it, and SCTPRead returned a nil SndRcvInfo with no error. That was
// measured, and it is the reason this function does not simply prefer one type.
//
// SCTP_SNDRCV wins when both are present, so a caller that has enabled both
// keeps the exact bytes it had before. The result is always an *SndRcvInfo, which
// keeps the return type of SCTPRead unchanged; RcvInfo carries no TTL, so that
// field stays zero when the information came from SCTP_RCVINFO.
func parseSndRcvInfo(b []byte) (*SndRcvInfo, error) {
	msgs, err := syscall.ParseSocketControlMessage(b)
	if err != nil {
		return nil, err
	}
	var fromRcvInfo *SndRcvInfo
	for _, m := range msgs {
		if m.Header.Level != syscall.IPPROTO_SCTP {
			continue
		}
		switch m.Header.Type {
		case SCTP_CMSG_SNDRCV:
			if len(m.Data) < int(unsafe.Sizeof(SndRcvInfo{})) {
				// A short control message would make the cast read past the
				// buffer the kernel filled. No test covers this branch and
				// removing it keeps the suite green: reaching it needs a kernel
				// that sends a truncated cmsg, which is not reproducible from
				// here. It is kept because the cost is a length comparison and
				// the alternative is an out-of-bounds read.
				continue
			}
			// Copy out rather than returning a pointer into m.Data.
			//
			// This used to alias the caller's control-message buffer and
			// byte-swap PPID in place, which had two consequences. Parsing the
			// same bytes twice swapped twice, so the second call returned
			// 0x44332211 for an 0x11223344 payload — reachable by any caller
			// driving recvmsg itself through SyscallConn. And it made the oob
			// buffer in SCTPReadFlags impossible to reuse, since the returned
			// value outlived the read.
			info := *(*SndRcvInfo)(unsafe.Pointer(&m.Data[0]))
			info.PPID = ntohl(info.PPID)
			return &info, nil
		case SCTP_CMSG_RCVINFO:
			if len(m.Data) < int(unsafe.Sizeof(RcvInfo{})) {
				continue
			}
			ri := (*RcvInfo)(unsafe.Pointer(&m.Data[0]))
			// Copy rather than alias: the field order differs from SndRcvInfo,
			// so this is a conversion and not a reinterpretation.
			fromRcvInfo = &SndRcvInfo{
				Stream:  ri.SID,
				SSN:     ri.SSN,
				Flags:   ri.Flags,
				PPID:    ntohl(ri.PPID),
				Context: ri.Context,
				TSN:     ri.TSN,
				CumTSN:  ri.CumTSN,
				AssocID: int32(ri.AssocID),
			}
		}
	}
	return fromRcvInfo, nil
}

// SCTPRead reads one message, or as much of one message as fits in b.
//
// If the message is larger than b, the remainder is not discarded: it is
// returned by subsequent reads, which makes a truncated message
// indistinguishable from a complete one here. Callers of framed protocols
// should use SCTPReadFlags and test the returned flags for MSG_EOR, or use
// ReadMsg to have the reassembly done for them.
func (c *SCTPConn) SCTPRead(b []byte) (int, *SndRcvInfo, error) {
	n, info, _, err := c.SCTPReadFlags(b)
	return n, info, err
}

// SCTPReadFlags is SCTPRead, additionally returning the flags recvmsg
// reported for the message.
//
// The kernel sets MSG_EOR when b received the end of a message and clears it
// when more of that message remains, so flags&MSG_EOR == 0 means the message
// was truncated and the remainder will arrive on subsequent reads. Without
// checking it, an oversized message is silently split and the remainder is
// delivered as what looks like a fresh message.
func (c *SCTPConn) SCTPReadFlags(b []byte) (int, *SndRcvInfo, int, error) {
	oob := make([]byte, 254)
	for {
		// Reprogram the timeout each iteration: the deadline is absolute, so
		// a notification consuming part of the budget must shorten the next
		// wait rather than restart it.
		//
		// Only an expired deadline aborts the read. Any other setsockopt
		// failure is left to recvmsg to report, so that a socket closed
		// concurrently still surfaces its own error (EOF, EBADF) rather than
		// being masked by a failure to program the timeout.
		deadline := atomic.LoadInt64(&c.readDeadline)
		if deadline != 0 || atomic.LoadInt32(&c.rcvTimeoSet) != 0 {
			if err := applyTimeout(c.fd(), syscall.SO_RCVTIMEO, deadline); err == os.ErrDeadlineExceeded {
				return 0, nil, 0, err
			}
			if deadline != 0 {
				atomic.StoreInt32(&c.rcvTimeoSet, 1)
			} else {
				atomic.StoreInt32(&c.rcvTimeoSet, 0)
			}
		}

		n, oobn, recvflags, _, err := syscall.Recvmsg(c.fd(), b, oob, 0)
		if err != nil {
			return n, nil, recvflags, toDeadlineErr(err)
		}

		if n == 0 && oobn == 0 {
			return 0, nil, recvflags, io.EOF
		}

		if recvflags&MSG_NOTIFICATION > 0 && c.notificationHandler != nil {
			if err := c.notificationHandler(b[:n]); err != nil {
				return 0, nil, recvflags, err
			}
		} else {
			var info *SndRcvInfo
			if oobn > 0 {
				info, err = parseSndRcvInfo(oob[:oobn])
			}
			return n, info, recvflags, err
		}
	}
}

// ReadMsg reads one whole message, reassembling it across as many reads as
// the kernel needs to deliver it.
//
// It returns the complete message, so unlike SCTPRead the caller does not
// need to size a buffer against the largest message the peer might send. At
// most max bytes are accumulated; a message that exceeds max stops there and
// is returned with ErrMsgTooLong, leaving its remainder queued. The returned
// SndRcvInfo is the one reported for the message's first fragment.
func (c *SCTPConn) ReadMsg(max int) ([]byte, *SndRcvInfo, error) {
	if max <= 0 {
		return nil, nil, syscall.EINVAL
	}

	// Start well under max so a small message costs a small allocation.
	const chunk = 2048
	size := chunk
	if max < size {
		size = max
	}
	buf := make([]byte, size)
	var (
		total int
		first *SndRcvInfo
	)
	for {
		if total == len(buf) {
			if total >= max {
				return buf[:total], first, ErrMsgTooLong
			}
			grow := len(buf)
			if room := max - total; room < grow {
				grow = room
			}
			buf = append(buf, make([]byte, grow)...)
		}

		n, info, flags, err := c.SCTPReadFlags(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return buf[:total], first, err
		}
		if first == nil {
			first = info
		}
		if flags&syscall.MSG_EOR != 0 {
			return buf[:total], first, nil
		}
	}
}

// Close closes the SCTP connection gracefully with a timeout fallback.
//
// It initiates a graceful shutdown by sending a SHUTDOWN chunk to the peer
// and waits up to 3 seconds for the peer to acknowledge (SHUTDOWN-ACK).
// If the peer responds, the connection closes gracefully and resources are
// released immediately. If the peer does not respond within the timeout
// (e.g., network failure or unreachable peer), an ABORT chunk is sent to
// forcefully terminate the association and release resources.
//
// This ensures that Close always returns promptly and releases resources,
// avoiding the EADDRINUSE "Address already in use" error that can occur when the kernel
// still occupies the resource.
//
// For immediate termination without waiting, use Abort() instead.
func (c *SCTPConn) Close() error {
	return c.CloseWithTimeout(closeTimeout)
}

// closeTimeout is how long Close waits for the peer to acknowledge a
// shutdown before falling back to an ABORT. It is a compromise: long enough
// that a peer on a congested link can still complete the handshake, short
// enough that a server tearing down many associations is not held up by a
// peer that will never answer. Use CloseWithTimeout to choose another value.
const closeTimeout = 3 * time.Second

// establishTimeout bounds the same wait on the error paths of dial and
// listen. Those sockets have no established association to shut down
// gracefully, so the wait exists only to let the kernel release the address.
const establishTimeout = 1 * time.Second

// CloseWithTimeout is Close with a caller-chosen grace period.
//
// A zero or negative timeout skips the wait entirely and terminates the
// association immediately, which is equivalent to Abort.
func (c *SCTPConn) CloseWithTimeout(timeout time.Duration) error {
	if c == nil {
		return syscall.EBADF
	}
	fd := atomic.SwapInt32(&c._fd, -1)
	// Zero is a valid descriptor: a process that has closed stdin can be
	// handed fd 0 for a socket. Guarding with "fd > 0" leaked it.
	if fd < 0 {
		return syscall.EBADF
	}
	return closeSctpSocket(int(fd), timeout)
}

func closeSctpSocket(fd int, timeout time.Duration) error {
	if timeout <= 0 {
		return abortSctpSocket(fd)
	}

	// Send SHUTDOWN to initiate graceful shutdown. A failure here means no
	// graceful shutdown is possible, so skip the wait and abort instead of
	// blocking for a SHUTDOWN-ACK that cannot arrive.
	if err := syscall.Shutdown(fd, syscall.SHUT_RDWR); err != nil {
		return abortSctpSocket(fd)
	}

	// Wait for the shutdown handshake to finish. The outcome says which of the
	// two closes below is correct, so it is not discarded:
	//
	//	n == 0, err == nil  the peer completed the handshake and the read hit
	//	                    end of stream
	//	ECONNRESET          the peer aborted rather than answering
	//	EAGAIN              the timeout expired with no answer at all
	//
	// The timeout is what bounds this read, so if it cannot be programmed the
	// read would block indefinitely. Abort rather than risk that.
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&tv); err != nil {
		return abortSctpSocket(fd)
	}
	var buf [1]byte
	n, rerr := syscall.Read(fd, buf[:])
	completed := n == 0 && rerr == nil

	if completed {
		// The association is already shut down, so there is nothing for
		// linger to bound. Setting linger=0 here makes close() emit an ABORT
		// on an association that ended cleanly, and a peer still in a read
		// sees ECONNRESET instead of the end of the stream.
		return syscall.Close(fd)
	}

	// No handshake: linger=0 makes close() send ABORT rather than leave the
	// association half-open, so the address is released promptly instead of
	// being held by a peer that is not answering.
	if err := syscall.SetsockoptLinger(fd, syscall.SOL_SOCKET, syscall.SO_LINGER,
		&syscall.Linger{Onoff: 1, Linger: 0}); err != nil {
		// Without linger the close may leave the association lingering, but
		// the descriptor must still be released.
		if cerr := syscall.Close(fd); cerr != nil {
			return cerr
		}
		return err
	}
	return syscall.Close(fd)
}

// abortSctpSocket terminates the association immediately and releases fd.
func abortSctpSocket(fd int) error {
	// Setting SO_LINGER with l_onoff=1 and l_linger=0 causes the kernel to
	// send an ABORT chunk instead of SHUTDOWN when closing.
	lerr := syscall.SetsockoptLinger(fd, syscall.SOL_SOCKET, syscall.SO_LINGER,
		&syscall.Linger{Onoff: 1, Linger: 0})
	if err := syscall.Close(fd); err != nil {
		return err
	}
	return lerr
}

// Abort terminates the SCTP association immediately by sending an ABORT chunk.
// Unlike Close(), this does not perform a graceful shutdown handshake.
// Use this when you need immediate resource release without waiting for
// the peer to acknowledge the shutdown (e.g., when the peer is unreachable).
func (c *SCTPConn) Abort() error {
	if c == nil {
		return syscall.EBADF
	}
	fd := atomic.SwapInt32(&c._fd, -1)
	// See CloseWithTimeout: fd 0 is valid and must not be skipped.
	if fd < 0 {
		return syscall.EBADF
	}
	return abortSctpSocket(int(fd))
}

func (c *SCTPConn) SetWriteBuffer(bytes int) error {
	return syscall.SetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_SNDBUF, bytes)
}

func (c *SCTPConn) GetWriteBuffer() (int, error) {
	return syscall.GetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
}

func (c *SCTPConn) SetReadBuffer(bytes int) error {
	return syscall.SetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_RCVBUF, bytes)
}

func (c *SCTPConn) GetReadBuffer() (int, error) {
	return syscall.GetsockoptInt(c.fd(), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
}

// ListenSCTP - start listener on specified address/port
func ListenSCTP(net string, laddr *SCTPAddr) (*SCTPListener, error) {
	return ListenSCTPExt(net, laddr, InitMsg{NumOstreams: SCTP_MAX_STREAM})
}

// ListenSCTPExt - start listener on specified address/port with given SCTP options
func ListenSCTPExt(network string, laddr *SCTPAddr, options InitMsg) (*SCTPListener, error) {
	return listenSCTPExtConfig(network, laddr, options, nil, nil)
}

// listenSCTPExtConfig - start listener on specified address/port with given SCTP options and socket configuration
func listenSCTPExtConfig(network string, laddr *SCTPAddr, options InitMsg, control func(network, address string, c syscall.RawConn) error, notificationHandler NotificationHandler) (*SCTPListener, error) {
	af, ipv6only := favoriteAddrFamily(network, laddr, nil, "listen")
	sock, err := syscall.Socket(
		af,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC,
		syscall.IPPROTO_SCTP,
	)
	if err != nil {
		return nil, err
	}

	// close socket on error
	defer func() {
		if err != nil {
			_ = closeSctpSocket(sock, establishTimeout)
		}
	}()
	if err = setDefaultSockopts(sock, af, ipv6only); err != nil {
		return nil, err
	}
	if control != nil {
		rc := rawConn{sockfd: sock}
		var localAddressString string
		if laddr != nil {
			localAddressString = laddr.String()
		}
		if err = control(network, localAddressString, rc); err != nil {
			return nil, err
		}
	}
	err = setInitOpts(sock, options)
	if err != nil {
		return nil, err
	}

	if laddr != nil {
		// If IP address and/or port was not provided so far, let's use the unspecified IPv4 or IPv6 address
		if len(laddr.IPAddrs) == 0 {
			if af == syscall.AF_INET {
				laddr.IPAddrs = append(laddr.IPAddrs, net.IPAddr{IP: net.IPv4zero})
			} else if af == syscall.AF_INET6 {
				laddr.IPAddrs = append(laddr.IPAddrs, net.IPAddr{IP: net.IPv6zero})
			}
		}
		err = SCTPBind(sock, laddr, SCTP_BINDX_ADD_ADDR)
		if err != nil {
			return nil, err
		}
	}
	// syscall.SOMAXCONN is a compile-time constant of 128 in Go, not the
	// running kernel's net.core.somaxconn, which has defaulted to 4096 since
	// Linux 5.4. Passing 128 caps the accept backlog an order of magnitude
	// below what the system allows, and a listener that is handed more
	// simultaneous INITs than that answers the excess with ABORT: the peer
	// sees ECONNREFUSED even though the listener is healthy and accepting.
	//
	// The kernel clamps whatever is passed to its own somaxconn, so asking
	// for more than it permits is safe and gets the configured maximum.
	backlog := syscall.SOMAXCONN
	if n, err := readSomaxconn(); err == nil && n > backlog {
		backlog = n
	}
	err = syscall.Listen(sock, backlog)
	if err != nil {
		return nil, err
	}
	return &SCTPListener{
			_fd:                 int32(sock),
			notificationHandler: notificationHandler,
		},
		nil
}

// FileListener takes a file, dup's the underlying file descriptor, and returns
// a SCTPListener created from the dup'd fd.
func FileListener(file *os.File) (*SCTPListener, error) {
	r1, _, err := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if err != 0 {
		return nil, os.NewSyscallError("fcntl", err)
	}

	// Clear the non-blocking flag on the dup'd fd. This is needed to make sure
	// an SCTPListener created with FileListener will behave like other
	// listeners. Namely, its Accept methods will block until a connection is
	// available.
	if err := syscall.SetNonblock(int(r1), false); err != nil {
		return nil, os.NewSyscallError("fcntl", err)
	}

	return &SCTPListener{
		_fd:                 int32(r1),
		notificationHandler: nil,
	}, nil
}

// AcceptSCTP waits for and returns the next SCTP connection to the listener.
func (ln *SCTPListener) AcceptSCTP() (*SCTPConn, error) {
	lnfd := ln.fd()
	if lnfd < 0 {
		return nil, syscall.EBADF
	}
	fd, _, err := syscall.Accept4(lnfd, 0)
	if err != nil {
		return nil, err
	}
	return NewSCTPConn(fd, ln.notificationHandler), nil
}

// Accept waits for and returns the next connection connection to the listener.
func (ln *SCTPListener) Accept() (net.Conn, error) {
	return ln.AcceptSCTP()
}

// Close releases the listening socket.
//
// The descriptor is swapped out atomically, so concurrent or repeated calls
// report EBADF rather than closing the number a second time. That matters
// because the kernel reuses descriptor numbers: without it, a second Close
// could release a socket that had since been opened elsewhere in the process.
func (ln *SCTPListener) Close() error {
	fd := atomic.SwapInt32(&ln._fd, -1)
	// Zero is a valid descriptor, so guard against negatives only.
	if fd < 0 {
		return syscall.EBADF
	}
	// Shutdown unblocks any Accept parked on this socket. It is expected to
	// fail on a listening socket that never connected (ENOTCONN), so its
	// result is not treated as a close failure.
	_ = syscall.Shutdown(int(fd), syscall.SHUT_RDWR)
	return syscall.Close(int(fd))
}

func (ln *SCTPListener) SyscallConn() (syscall.RawConn, error) {
	fd := ln.fd()
	if fd < 0 {
		return nil, syscall.EINVAL
	}
	return &rawConn{sockfd: int(fd)}, nil
}

// DialSCTP - bind socket to laddr (if given) and connect to raddr
func DialSCTP(net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	return DialSCTPExt(net, laddr, raddr, InitMsg{NumOstreams: SCTP_MAX_STREAM})
}

// DialSCTPExt - same as DialSCTP but with given SCTP options
func DialSCTPExt(network string, laddr, raddr *SCTPAddr, options InitMsg) (*SCTPConn, error) {
	return dialSCTPExtConfig(network, laddr, raddr, options, nil, nil)
}

// dialSCTPExtConfig - same as DialSCTP but with given SCTP options and socket configuration
func dialSCTPExtConfig(network string, laddr, raddr *SCTPAddr, options InitMsg, control func(network, address string, c syscall.RawConn) error, notificationHandler NotificationHandler) (*SCTPConn, error) {
	af, ipv6only := favoriteAddrFamily(network, laddr, raddr, "dial")
	sock, err := syscall.Socket(
		af,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC,
		syscall.IPPROTO_SCTP,
	)
	if err != nil {
		return nil, err
	}

	// close socket on error
	defer func() {
		if err != nil {
			_ = closeSctpSocket(sock, establishTimeout)
		}
	}()
	if err = setDefaultSockopts(sock, af, ipv6only); err != nil {
		return nil, err
	}
	if control != nil {
		rc := rawConn{sockfd: sock}
		var localAddressString string
		if laddr != nil {
			localAddressString = laddr.String()
		}
		if err = control(network, localAddressString, rc); err != nil {
			return nil, err
		}
	}
	err = setInitOpts(sock, options)
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		// If IP address and/or port was not provided so far, let's use the unspecified IPv4 or IPv6 address
		if len(laddr.IPAddrs) == 0 {
			if af == syscall.AF_INET {
				laddr.IPAddrs = append(laddr.IPAddrs, net.IPAddr{IP: net.IPv4zero})
			} else if af == syscall.AF_INET6 {
				laddr.IPAddrs = append(laddr.IPAddrs, net.IPAddr{IP: net.IPv6zero})
			}
		}
		err = SCTPBind(sock, laddr, SCTP_BINDX_ADD_ADDR) // error EADDRINUSE "Address already in use" may occur if resource (source IP and Port) is occupied
		if err != nil {
			return nil, err
		}
	}
	_, err = SCTPConnect(sock, raddr)
	if err != nil {
		return nil, err
	}
	return NewSCTPConn(sock, notificationHandler), nil
}

// readSomaxconn reports the kernel's net.core.somaxconn, which bounds the
// accept backlog a listener may request. It is read rather than assumed
// because syscall.SOMAXCONN is a Go constant of 128 and has not tracked the
// kernel default since Linux 5.4 raised it to 4096.
func readSomaxconn() (int, error) {
	b, err := os.ReadFile("/proc/sys/net/core/somaxconn")
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, err
	}
	return n, nil
}
