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
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

// bindLocal binds laddr, supplying the wildcard address when the caller named
// only a port.
//
// The wildcard is written into a local copy rather than into the caller's
// SCTPAddr. Appending to laddr.IPAddrs was visible after the call returned and
// was a data race whenever one address value was shared between goroutines,
// which is the ordinary way to run a client and a server against a fixed
// endpoint. It also changed the caller's meaning: a *SCTPAddr that came back
// from a "sctp6" listen carried [::], so reusing it for a "sctp4" dial failed
// with EINVAL.
//
// Only the AF_INET6 arm is load-bearing. ToRawSockAddrBuf already encodes an
// empty address list as IPv4 zero, so the AF_INET arm produces the bytes it
// would have produced anyway; it is kept because relying on that coupling from
// here would be a trap for whoever edits either half next.
func bindLocal(sock int, laddr *SCTPAddr, af int) error {
	if len(laddr.IPAddrs) == 0 {
		local := SCTPAddr{Port: laddr.Port}
		switch af {
		case syscall.AF_INET:
			local.IPAddrs = []net.IPAddr{{IP: net.IPv4zero}}
		case syscall.AF_INET6:
			local.IPAddrs = []net.IPAddr{{IP: net.IPv6zero}}
		}
		laddr = &local
	}
	return SCTPBind(sock, laddr, SCTP_BINDX_ADD_ADDR)
}

// isNonblocking reports whether fd has O_NONBLOCK set. A descriptor that cannot
// be queried is treated as non-blocking, which is the conservative answer: it
// keeps EALREADY as an error rather than reporting a possibly unconnected socket
// as ready.
//
// It lives here rather than beside its caller in sctp.go because syscall.SYS_FCNTL
// exists only on the platforms that have it, and sctp.go is built for all of them.
// See isNonblocking in sctp_unsupported.go for the other half.
func isNonblocking(fd int) bool {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd),
		syscall.F_GETFL, 0)
	if errno != 0 {
		return true
	}
	return flags&syscall.O_NONBLOCK != 0
}

// applyTimeout programs optname (SO_RCVTIMEO or SO_SNDTIMEO) from an absolute
// deadline. It reports ErrDeadlineExceeded when the deadline has already
// passed, since a zero timeval means "block forever" rather than "expire
// immediately" and would otherwise hang.
//
// This is here for the same reason as isNonblocking: syscall.SetsockoptTimeval
// takes an int on Unix and a syscall.Handle on Windows, so it cannot be called
// from a file compiled for both. It has no non-Linux counterpart because nothing
// outside this file calls it.
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

// poll(2) event bits. The syscall package generates the EPOLL* constants from
// the kernel headers but no POLL* ones, and this module has no dependencies to
// borrow them from. The kernel defines both sets to the same bits for the
// events that appear in both, which is what TestPollConstantsMatchKernel checks;
// pollNval has no epoll counterpart, since epoll reports an invalid descriptor
// at registration rather than in an event.
//
// These values are uniform across every Linux architecture: asm-generic/poll.h
// defines them and the architectures that override anything override only the
// write-band and message bits, none of which are used here.
const (
	pollIn   = 0x001
	pollOut  = 0x004
	pollErr  = 0x008
	pollHup  = 0x010
	pollNval = 0x020
)

// pollFd mirrors struct pollfd from <poll.h>. TestPollFdLayoutMatchesKernel
// pins the layout.
type pollFd struct {
	Fd      int32
	Events  int16
	Revents int16
}

// pollWait blocks until fd reports one of events, timeout elapses, or a signal
// arrives. It reports the events the kernel returned; zero means the timeout
// expired first.
//
// ppoll rather than poll: arm64 and riscv64 have no SYS_POLL at all, only
// SYS_PPOLL, so poll would not build for two of the architectures this file is
// compiled for. The signal mask is left null, which makes the two equivalent
// apart from the timeout's resolution.
func pollWait(fd int, events int16, timeout time.Duration) (int16, error) {
	fds := [1]pollFd{{Fd: int32(fd), Events: events}}
	ts := syscall.NsecToTimespec(timeout.Nanoseconds())
	n, _, errno := syscall.Syscall6(syscall.SYS_PPOLL,
		uintptr(unsafe.Pointer(&fds[0])),
		1,
		uintptr(unsafe.Pointer(&ts)),
		0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	if n == 0 {
		return 0, nil
	}
	return fds[0].Revents, nil
}

const (
	// rawWaitSlice bounds a single ppoll so a concurrent Close is noticed.
	// Linux does not wake a task parked in poll when another thread closes the
	// descriptor it is waiting on, and closeSctpSocket holds the descriptor from
	// the moment Close swaps _fd to -1 until its shutdown wait finishes — a round
	// trip against a peer that answers, up to the caller's timeout against one
	// that does not. Waking on this cadence lets a waiter re-read the descriptor,
	// see -1, and return, instead of parking until its own deadline on a
	// descriptor that no longer belongs to this association.
	//
	// The graceful path has a second wakeup that does not depend on this at all:
	// closeSctpSocket calls shutdown(SHUT_RDWR) first, which wakes anything
	// parked on the descriptor. Abort does not, which is why the cadence is what
	// TestSyscallConnAbortUnblocksWait pins and the graceful close does not.
	rawWaitSlice = 50 * time.Millisecond

	// rawSpinTolerance is how many consecutive ready-but-not-done rounds are
	// allowed before the wait stops polling and starts pacing itself.
	rawSpinTolerance = 8

	// rawSpinBackoff is the pace it falls back to. It matches the interval the
	// test helper writeAll already uses for the same condition.
	rawSpinBackoff = time.Millisecond
)

// readyWaiter waits for a descriptor to become ready, bounded by a deadline,
// and guards against the busy loop a level-triggered wait invites.
//
// ppoll is level-triggered where the runtime's own poller is edge-triggered, and
// syscall.RawConn explicitly permits f to report "not done" for a descriptor
// that is ready. The two combine badly. POLLOUT means the send buffer has room;
// sendmsg needs room for the whole message and will not split one. So a message
// large relative to the free space can see ready, then EAGAIN, then ready again
// with nothing having changed, and a plain retry loop burns a core. That is not
// hypothetical here — it is the retry spin the benchmarks measured at 2ms per
// write before they stopped doing it, recorded in testdata/README.md.
//
// After rawSpinTolerance such rounds this stops polling and paces the retries
// instead, which is the only thing that can be done: the kernel has no readiness
// event for "enough room for a message of my size".
type readyWaiter struct {
	c       *SCTPConn
	events  int16
	stalled int
	ready   bool
}

// wait blocks until the descriptor is ready, the deadline expires, or the
// close-detection slice elapses. A zero deadline means no deadline, in which
// case only a close or readiness ends the wait.
func (w *readyWaiter) wait(deadline int64) error {
	fd := w.c.fd()
	if fd < 0 {
		return syscall.EBADF
	}

	slice := rawWaitSlice
	if deadline != 0 {
		remaining := time.Until(time.Unix(0, deadline))
		if remaining <= 0 {
			return os.ErrDeadlineExceeded
		}
		if remaining < slice {
			slice = remaining
		}
	}

	// The descriptor was reported ready and the caller still is not done, so
	// polling again would return immediately and achieve nothing. Pace instead.
	if w.ready {
		w.stalled++
		if w.stalled >= rawSpinTolerance {
			if slice > rawSpinBackoff {
				slice = rawSpinBackoff
			}
			time.Sleep(slice)
			return nil
		}
	}

	revents, err := pollWait(fd, w.events, slice)
	if err != nil {
		// A signal interrupted the wait. The deadline is absolute and is
		// re-derived on the next round, so retrying cannot extend the budget.
		if errors.Is(err, syscall.EINTR) {
			w.ready = false
			return nil
		}
		return err
	}
	if revents&pollNval != 0 {
		// The descriptor went away underneath the wait.
		return syscall.EBADF
	}
	// POLLERR and POLLHUP are left to the caller's next attempt, which collects
	// the real errno from the syscall itself rather than having one synthesised
	// here from an event bit.
	w.ready = revents != 0
	if revents == 0 {
		// A genuine wait elapsed rather than a spin.
		w.stalled = 0
	}
	return nil
}

// rawConn is the Control-only syscall.RawConn. It backs the descriptor handed
// to a SocketConfig hook, which runs before the socket is connected or
// listening, and SCTPListener.SyscallConn.
//
// Read and Write report syscall.EINVAL rather than waiting, which is what the
// standard library does for the same case: net/rawconn.go gives a listener's
// RawConn exactly these two methods, and TCPListener.SyscallConn documents it —
// "The returned RawConn only supports calling Control. Read and Write return an
// error." Waiting for accept readiness through a RawConn is not a supported
// idiom anywhere in net, so there is nothing here to implement. What these used
// to do was panic, which is never a defensible answer to a caller using an
// interface exactly as its contract describes.
type rawConn struct {
	sockfd int
}

func (r rawConn) Control(f func(fd uintptr)) error {
	f(uintptr(r.sockfd))
	return nil
}

func (r rawConn) Read(f func(fd uintptr) (done bool)) error {
	return syscall.EINVAL
}

func (r rawConn) Write(f func(fd uintptr) (done bool)) error {
	return syscall.EINVAL
}

// connRawConn is the syscall.RawConn a connected association hands out.
//
// It keeps the *SCTPConn rather than a descriptor number so every operation
// reads the descriptor currently in force. rawConn cannot: it snapshots the
// number at SyscallConn time, and Close swaps _fd to -1 and closes the
// descriptor, so a snapshot taken beforehand can name a number the kernel has
// since handed to an unrelated socket.
//
// The remaining race is the one the standard library solves with a reference
// count in internal/poll and this package has no equivalent of: a Close landing
// between reading the descriptor and using it. Reading it afresh each round
// narrows that to the width of a single call and lets a parked wait notice the
// close; it does not remove it. A caller closing a connection while another
// goroutine is inside Read, Write or Control is responsible for that ordering,
// exactly as it is today for SCTPRead and SCTPWrite.
//
// Nor is there any mutual exclusion against the package's own IO, where
// internal/poll's RawRead and RawWrite take the same locks FD.Read and FD.Write
// take. What that costs was measured rather than assumed: 300 messages of 8000
// bytes read through a 2000-byte buffer, with two readers racing.
//
//	one reader                        0 messages split
//	two SCTPRead readers             61 messages split
//	SCTPRead + a RawConn reader      64 messages split
//
// No run lost, duplicated or corrupted anything — the kernel holds lock_sock
// across the dequeue and the requeue of the remainder, so each recvmsg is atomic
// against the other. What concurrent readers do is divide one message's
// fragments between them, and a RawConn-driven reader is not distinguishable
// from a second SCTPRead. So this adds no hazard that reading concurrently did
// not already have, and a lock here would not fix the case that actually bites:
// two goroutines calling SCTPRead. One reader per association, as before.
type connRawConn struct {
	c *SCTPConn
}

func (r *connRawConn) Control(f func(fd uintptr)) error {
	fd := r.c.fd()
	if fd < 0 {
		return syscall.EBADF
	}
	f(uintptr(fd))
	return nil
}

func (r *connRawConn) Read(f func(fd uintptr) (done bool)) error {
	return r.c.rawWait(f, pollIn, &r.c.readDeadline)
}

func (r *connRawConn) Write(f func(fd uintptr) (done bool)) error {
	return r.c.rawWait(f, pollOut, &r.c.writeDeadline)
}

// rawWait implements the syscall.RawConn contract for Read and Write: call f,
// and while it reports it is not done, wait for the descriptor to become ready
// and call it again.
//
// The waiting is done here rather than by the runtime poller. Reaching the
// poller would mean putting the descriptor in non-blocking mode, and the read
// path depends on it being blocking: SCTPReadFlags realises its deadline with
// SO_RCVTIMEO and maps the resulting EAGAIN onto os.ErrDeadlineExceeded, so on a
// non-blocking descriptor every read that found the socket empty would report a
// deadline that had not expired. That is a rewrite of the read path, not a
// change to SyscallConn.
//
// Polling here instead is sound because the contract puts the I/O in the
// caller's f and only the waiting in the implementation, so f decides for itself
// whether to block — a caller passing MSG_DONTWAIT, which is what any caller of
// a readiness API is doing, never does. A caller whose f blocks blocks, exactly
// as it would have on the descriptor it got from Control.
func (c *SCTPConn) rawWait(f func(fd uintptr) (done bool), events int16, deadline *int64) error {
	w := readyWaiter{c: c, events: events}
	for {
		fd := c.fd()
		if fd < 0 {
			return syscall.EBADF
		}
		if f(uintptr(fd)) {
			return nil
		}
		if err := w.wait(atomic.LoadInt64(deadline)); err != nil {
			return err
		}
	}
}

func (c *SCTPConn) SyscallConn() (syscall.RawConn, error) {
	fd := c.fd()
	if fd < 0 {
		return nil, syscall.EINVAL
	}
	return &connRawConn{c: c}, nil
}

func (c *SCTPConn) SCTPWrite(b []byte, info *SndRcvInfo) (int, error) {
	var cbuf []byte
	if info != nil {
		cbuf = buildSndRcvCmsg(info)
	}
	return c.sendmsg(b, cbuf)
}

// sendmsg sends one message, waiting for send-buffer space when — and only
// when — a write deadline is in force.
//
// Sends pass MSG_DONTWAIT, so a full send buffer reports EAGAIN rather than
// blocking. That is deliberate and stays: a blocking sendmsg to a peer that has
// stopped reading does not come back for many minutes — bounded in the limit by
// the retransmission backoff and the shutdown-guard timer, not by anything the
// caller can set — and there is no way to interrupt it. Reporting EAGAIN keeps
// the descriptor under the caller's control.
//
// What it also did was leave SetWriteDeadline with nothing to do. SO_SNDTIMEO
// only bounds a wait the socket never performs, so a deadline in the future
// changed no behaviour whatsoever and only an already-elapsed one was
// observable. A caller asking for what net.Conn.SetWriteDeadline offers — carry
// on until this is accepted or until the deadline — got neither half of it, and
// a burst larger than the send buffer surfaced as a write failure rather than as
// backpressure.
//
// So the wait happens here, bounded by the deadline the caller set. Two
// properties matter. With no deadline the behaviour is exactly what it was,
// EAGAIN on the first refusal, so nothing changes for a caller that never sets
// one. And the unbounded wait stays unreachable: every wait this performs ends
// at a time the caller chose.
//
// The deadline is read once, at entry. Moving it from another goroutine takes
// effect from the next write, which is what SetReadDeadline already documents
// for reads.
//
// The whole buffer is retried, never b[n:]. sctp_sendmsg queues a message in
// full or queues nothing, so a refused send leaves nothing behind to resume
// from; resuming at an offset would split one application message into two on
// the wire.
// sendFlags is what both send paths pass to sendmsg.
//
// MSG_NOSIGNAL suppresses the SIGPIPE the kernel otherwise raises when a send
// finds the association gone; the errno is EPIPE either way, which is what a
// caller can actually act on. Both halves were measured: without the flag the
// signal is delivered and the send returns EPIPE, with it the signal is not
// delivered and the send still returns EPIPE.
//
// It matters more since sends grew a retry loop. Go's runtime ignores SIGPIPE
// for descriptors other than 1 and 2, so the default behaviour was survivable,
// but a caller that had asked for it with signal.Notify would see one spurious
// signal per refused send rather than one per write.
const sendFlags = syscall.MSG_DONTWAIT | syscall.MSG_NOSIGNAL

func (c *SCTPConn) sendmsg(b, cbuf []byte) (int, error) {
	if c.fd() < 0 {
		return 0, errClosed("write")
	}
	deadline := atomic.LoadInt64(&c.writeDeadline)
	if deadline == 0 {
		return syscall.SendmsgN(c.fd(), b, cbuf, nil, sendFlags)
	}

	w := readyWaiter{c: c, events: pollOut}
	for {
		// Checked before the first send as well as before each retry, so a
		// deadline already in the past fails rather than being ignored.
		if time.Until(time.Unix(0, deadline)) <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		n, err := syscall.SendmsgN(c.fd(), b, cbuf, nil, sendFlags)
		if !errors.Is(err, syscall.EAGAIN) {
			// EAGAIN is the only condition worth retrying, and it is the only
			// one a full send buffer produces. A send on an association that is
			// still connecting reports EPROTO or EPIPE, not EAGAIN, so this
			// loop cannot spin against a handshake in progress — measured.
			return n, err
		}
		if err := w.wait(deadline); err != nil {
			return 0, err
		}
	}
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

	// Same deadline handling as SCTPWrite, and for the same reason: MSG_DONTWAIT
	// means SO_SNDTIMEO does not apply, so the deadline is enforced here.
	return c.sendmsg(b, cbuf)
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

// parseNxtInfo extracts SCTP_NXTINFO from a control message buffer, if it is
// there.
//
// It is a separate walk rather than another case in parseSndRcvInfo because
// this describes a different message: SndRcvInfo is about the bytes just read,
// NxtInfo about the one behind them. Folding them together would mean changing
// the return type of every read.
//
// A nil result with a nil error means the kernel sent no such cmsg, which is
// what happens when SetRecvNxtInfo is off or the receive queue is empty. That is
// not a failure, so it is not reported as one.
func parseNxtInfo(b []byte) (*NxtInfo, error) {
	msgs, err := syscall.ParseSocketControlMessage(b)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if m.Header.Level != SOL_SCTP || m.Header.Type != SCTP_CMSG_NXTINFO {
			continue
		}
		if len(m.Data) < int(unsafe.Sizeof(NxtInfo{})) {
			continue
		}
		// Copy rather than alias: m.Data points into the pooled control
		// buffer, which the next read reuses. Aliasing it is the bug already
		// fixed once for SndRcvInfo.
		ni := *(*NxtInfo)(unsafe.Pointer(&m.Data[0]))
		ni.PPID = ntohl(ni.PPID)
		return &ni, nil
	}
	return nil, nil
}

// SCTPReadNextInfo is SCTPReadFlags, additionally returning what the kernel
// said about the message queued behind this one.
//
// nxt is nil when SetRecvNxtInfo has not been enabled or when nothing else is
// queued; neither is an error. Its Length is the whole size of the next
// message, so a caller can size the next buffer exactly rather than reading
// into a guess and reassembling.
func (c *SCTPConn) SCTPReadNextInfo(b []byte) (int, *SndRcvInfo, *NxtInfo, int, error) {
	var nxt *NxtInfo
	n, info, flags, err := c.readFlags(b, &nxt)
	return n, info, nxt, flags, err
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
	return c.readFlags(b, nil)
}

// readFlags is SCTPReadFlags, additionally filling *nxt from SCTP_NXTINFO when
// nxt is non-nil.
//
// The two share one body because they share one recvmsg: the next-message
// information arrives as ancillary data on the same call, so parsing it
// afterwards would mean either a second read or stashing the result on the
// connection, and the second is a race as soon as two goroutines read.
// Passing nil keeps the ordinary path from walking the control buffer twice.
func (c *SCTPConn) readFlags(b []byte, nxt **NxtInfo) (int, *SndRcvInfo, int, error) {
	// An empty buffer must not touch the stream. recvmsg substitutes a
	// one-byte scratch iovec when the data buffer is empty and the control
	// buffer is not — correct for a genuine control-only receive, and the
	// control buffer here is never empty. So without this the kernel dequeued a
	// payload byte into a package-local variable and reported n=1: Read
	// returned more than len(b), which io.Reader forbids, and the byte was
	// gone. Measured with eight bytes queued, Read(nil) returned 1 and the next
	// read returned "BCDEFGH".
	//
	// It is not only Read(nil) that gets here. The ordinary framing loop reads
	// into b[total:], which is empty the moment the buffer fills, so the next
	// line — b[:total] — panicked on a slice grown past its own capacity.
	if len(b) == 0 {
		return 0, nil, 0, nil
	}

	if c.fd() < 0 {
		return 0, nil, 0, errClosed("read")
	}

	// The control buffer is pooled rather than allocated per call. This is only
	// safe because parseSndRcvInfo copies: it used to return a pointer into
	// this buffer and byte-swap PPID in place, so reusing the buffer would have
	// been a use-after-free. See TestParseSndRcvInfoDoesNotAliasInput.
	oobp := oobPool.Get().(*[]byte)
	oob := *oobp
	defer oobPool.Put(oobp)

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

		n, oobn, recvflags, err := recvmsg(c.fd(), b, oob, 0)
		if err != nil {
			// A signal delivered while recvmsg was blocked interrupts it. The
			// Go runtime signals its own threads to preempt goroutines, so
			// this happens on a healthy association purely as a function of
			// how busy the process is: it was first seen as a handful of
			// failed reads per run with a thousand simultaneous peers, and
			// never with a hundred.
			//
			// POSIX leaves the retry to the caller, so reporting EINTR here
			// would make a server drop messages under load. Retrying re-enters
			// the loop, which reprograms the timeout from the absolute
			// deadline, so an interrupted read cannot extend its own budget.
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			// Only a programmed deadline can turn a blocking recvmsg into
			// EAGAIN, so only then does EAGAIN mean the deadline expired. A
			// descriptor that is non-blocking for some other reason — one
			// handed to NewSCTPConn, or one a Control hook set O_NONBLOCK on —
			// gets its EAGAIN back unchanged, rather than a phantom timeout a
			// caller would retry forever on. AcceptSCTP already draws the same
			// distinction.
			if deadline != 0 {
				err = toDeadlineErr(err)
			}
			return n, nil, recvflags, err
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
				if nxt != nil && err == nil {
					// A malformed SCTP_NXTINFO is not worth failing the read
					// for: the message itself is fine, and the caller's
					// fallback is to size the next buffer as they did before.
					*nxt, _ = parseNxtInfo(oob[:oobn])
				}
			}
			return n, info, recvflags, err
		}
	}
}

// errClosed is the error for an operation on a connection or listener whose
// descriptor this package has already released.
//
// net documents errors.Is(err, net.ErrClosed) as the way to recognise this, and
// the ordinary shutdown loop is written around it. Returning the kernel's bare
// EBADF meant that test was always false, so the loop never matched and logged
// the errno as an unexpected failure instead of exiting.
//
// It is reported from the descriptor being -1, which only this package's own
// Close does. A descriptor closed by someone else between the check and the
// syscall still surfaces as EBADF, which is the truthful answer for a socket
// this package did not close.
func errClosed(op string) error {
	return &net.OpError{Op: op, Net: "sctp", Err: net.ErrClosed}
}

// oobPool holds the per-read control-message buffers.
//
// 254 bytes is what the read path has always asked for. It is enough, but not
// for the reason it looks like: the cmsgs are not delivered one at a time. With
// every info option this package can enable turned on and a message queued
// behind the one being read, one recvmsg carries three, measured on 6.12 as
// SCTP_NXTINFO (CMSG_SPACE 32), SCTP_RCVINFO (48) and SCTP_SNDRCV (48) — 128
// bytes in that order.
//
// The order is what makes an undersized buffer quiet. SCTP_SNDRCV is written
// last, so a buffer too small for all three loses the description of the
// message in the caller's hand while still delivering the prediction of the
// next one, and the read itself succeeds; the kernel says so only through
// MSG_CTRUNC, which nothing here inspects. Shrinking this to 48 — exactly
// CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)) — left the entire suite green
// until TestPooledOobHoldsEveryInfoCmsgAtOnce existed.
//
// Pointers to slices are pooled rather than slices, so putting one back does
// not allocate a header on the heap to hold it.
var oobPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 254)
		return &b
	},
}

// recvmsg receives one message into b with its control data into oob.
//
// It exists because syscall.Recvmsg allocates twice per call for a peer address
// this package discards: it fills a RawSockaddrAny, which escapes to the heap,
// and then converts it with anyToSockaddr, which allocates the Sockaddr. A
// memory profile of the read path attributed two thirds of its allocations to
// that conversion alone.
//
// Passing a nil msg.Name asks the kernel not to report the source address at
// all, which is what SCTP wants: the socket is connected, so the peer is not in
// question, and SCTPReadFlags never looked at the value.
//
// The Msghdr and Iovec stay on the stack.
func recvmsg(fd int, b, oob []byte, flags int) (n, oobn, recvflags int, err error) {
	var msg syscall.Msghdr
	var iov syscall.Iovec

	if len(b) > 0 {
		iov.Base = &b[0]
		iov.SetLen(len(b))
	}
	// A control-only receive still needs somewhere for the kernel to put the
	// single byte a SOCK_STREAM read must return, mirroring what
	// syscall.recvmsgRaw does for the same case.
	var dummy byte
	if len(oob) > 0 {
		if len(b) == 0 {
			iov.Base = &dummy
			iov.SetLen(1)
		}
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	msg.Iov = &iov
	msg.Iovlen = 1

	r0, _, errno := syscall.Syscall(syscall.SYS_RECVMSG, uintptr(fd),
		uintptr(unsafe.Pointer(&msg)), uintptr(flags))
	if errno != 0 {
		return 0, 0, 0, errno
	}
	return int(r0), int(msg.Controllen), int(msg.Flags), nil
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
		if flags&MSG_NOTIFICATION != 0 {
			// A notification is not a message. It arrives interleaved on the
			// same stream and is distinguished only by this flag, so returning
			// it here would hand the caller a struct sctp_assoc_change as if
			// the peer had sent it — with MSG_EOR set, since the kernel marks
			// notifications complete, so it would look like a finished message.
			//
			// SCTPReadFlags has already offered it to the NotificationHandler
			// if one is installed. Either way it is dropped rather than
			// returned: this is the whole-message API, and a caller that wants
			// events subscribes to them and reads with SCTPReadFlags.
			if err != nil {
				return buf[:total], first, err
			}
			continue
		}
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

	// Take a control reading before the shutdown, while the association is
	// certainly still there. If the query already reports it gone, it is not
	// answering usefully on this platform and its verdict afterwards would be
	// meaningless — see waitAssocGone for what would go wrong silently.
	queryWorks := !assocGone(fd)

	// Send SHUTDOWN to initiate graceful shutdown. A failure here means no
	// graceful shutdown is possible, so skip the wait and abort instead of
	// blocking for a SHUTDOWN-ACK that cannot arrive.
	if err := syscall.Shutdown(fd, syscall.SHUT_RDWR); err != nil {
		return abortSctpSocket(fd)
	}

	// Wait for the shutdown handshake to finish, by watching the association
	// itself rather than by reading from the socket.
	//
	// A read cannot answer this question. shutdown(SHUT_RDWR) sets RCV_SHUTDOWN
	// on the socket before the SCTP layer sees it, and sctp_skb_recv_datagram
	// tests RCV_SHUTDOWN — returning end of stream — before both the EAGAIN path
	// and the SO_RCVTIMEO wait. So the read that used to be here returned
	// (0, nil) the instant the receive queue was empty, whatever the peer had
	// done. Three consequences, all measured:
	//
	//   - "the peer completed the handshake" was true for every peer that had
	//     simply gone silent, which is the one case the wait exists for.
	//   - the EAGAIN outcome the old comment documented was unreachable.
	//   - SO_RCVTIMEO never bound anything, so timeout was inert:
	//     CloseWithTimeout(1ms) and CloseWithTimeout(1h) were the same call.
	//
	// The visible cost was a silent one. Against a peer that had vanished, Close
	// decided the handshake had completed, skipped the ABORT, and left the
	// association and its bound port in the kernel until the retransmissions
	// gave up — up to 5 x RTO.max, 300s at defaults. That is precisely the
	// EADDRINUSE window this function's own doc claims to prevent.
	//
	// SCTP_STATUS is the query that survives the shutdown: sctp_id2assoc admits
	// SCTP_SS_CLOSING as well as SCTP_SS_ESTABLISHED, so it keeps resolving the
	// association across the handshake and only fails once the association is
	// freed. Measured: still answering SHUTDOWN_PENDING 3s after the shutdown
	// for a stalled peer; EINVAL 1.9us after it for one that answers.
	//
	// This is a real wait where the old one was not, so a graceful close now
	// costs about a round trip instead of returning immediately with the wrong
	// answer. It is bounded by the caller's timeout, which now means what it
	// says.
	//
	// If the control reading above showed the query does not work here, fall
	// back to the previous behaviour rather than trusting it. That is the safe
	// direction: assuming the handshake completed is wrong only for a peer that
	// never answered, whereas assuming it did not would abort every healthy
	// association and give each peer ECONNRESET in place of the end of the
	// stream.
	completed := true
	if queryWorks {
		completed = waitAssocGone(fd, timeout)
	}

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

const (
	// shutdownPollMin and shutdownPollMax bound the backoff waitAssocGone uses.
	// It starts short because the common case — a peer on the same host that
	// answers at once — completes in microseconds, and grows so that waiting out
	// a peer that never answers costs a handful of syscalls rather than
	// thousands.
	shutdownPollMin = 200 * time.Microsecond
	shutdownPollMax = 20 * time.Millisecond
)

// assocGone reports whether the association behind fd has been freed.
//
// The zero AssocID is correct for a one-to-one socket: sctp_id2assoc resolves
// the socket's single association and ignores the identifier.
//
// It cannot distinguish "the association is gone" from "this getsockopt did not
// work", because both surface as EINVAL. That is why closeSctpSocket takes a
// control reading before the shutdown instead of trusting this on its own: an
// option that always fails would report the association gone on the first call,
// which is exactly the always-completed answer the read this replaced used to
// give. A fix whose failure mode is the bug it fixes has to be able to tell.
//
// The concrete way that could happen is not hypothetical. Every getsockopt here
// passes the option length as a uintptr, and the kernel reads it as a 4-byte
// socklen_t; on a little-endian target those four bytes are the value, and on a
// big-endian 64-bit target they are the zero half, which the kernel rejects.
// That would break far more of this package than the close path, so it is not
// worked around here — but this one caller cannot afford to fail open.
func assocGone(fd int) bool {
	status := &Status{}
	optlen := unsafe.Sizeof(*status)
	_, _, err := getsockopt(fd, SCTP_STATUS,
		uintptr(unsafe.Pointer(status)), uintptr(unsafe.Pointer(&optlen)))
	return err != nil
}

// waitAssocGone waits up to timeout for the shutdown handshake to finish,
// reporting whether it did.
//
// False means the association was still there when the budget ran out, which is
// what tells closeSctpSocket to abort rather than leave it lingering.
func waitAssocGone(fd int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for delay := shutdownPollMin; ; {
		if assocGone(fd) {
			return true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		if delay > remaining {
			delay = remaining
		}
		time.Sleep(delay)
		if delay < shutdownPollMax {
			delay *= 2
		}
	}
}

// abortSctpSocket terminates the association immediately and releases fd.
func abortSctpSocket(fd int) error {
	// Setting SO_LINGER with l_onoff=1 and l_linger=0 causes the kernel to
	// send an ABORT chunk instead of SHUTDOWN when closing.
	lerr := syscall.SetsockoptLinger(fd, syscall.SOL_SOCKET, syscall.SO_LINGER,
		&syscall.Linger{Onoff: 1, Linger: 0})

	// Closing the descriptor is not enough to end the association while another
	// goroutine is parked in recvmsg. The blocked call holds a reference to the
	// struct file, so close only unhooks the descriptor number and defers the
	// final release; sctp_close never runs, the SO_LINGER ABORT is never put on
	// the wire, and the association stays up — with Abort having returned nil
	// in tens of microseconds. Measured: no ABORT chunk in seven seconds of
	// capture, both ends still listed in /proc/net/sctp/assocs, and the parked
	// reader still blocked. The graceful path never had this problem because it
	// calls shutdown first.
	//
	// SHUT_RD rather than SHUT_RDWR: it sets RCV_SHUTDOWN and wakes the waiter
	// without asking for a graceful teardown, so the ABORT is still what
	// reaches the peer. sctp_shutdown only emits a SHUTDOWN chunk for
	// SEND_SHUTDOWN.
	//
	// The error is deliberately dropped. A descriptor with no association —
	// which is every socket this is called on that never connected — answers
	// ENOTCONN, and that is not a reason to skip the close.
	_ = syscall.Shutdown(fd, syscall.SHUT_RD)

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
	network, _, err := canonicalNetwork(network)
	if err != nil {
		return nil, err
	}

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
		if err = bindLocal(sock, laddr, af); err != nil {
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
		// The dup succeeded, so this owns r1 and must release it before
		// reporting the failure. Returning without the close leaks a
		// descriptor on the one path here that can fail after the dup.
		_ = syscall.Close(int(r1))
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
	for {
		// accept4 honours SO_RCVTIMEO — sctp_accept takes its wait budget from
		// sock_rcvtimeo — so the deadline is programmed the same way the read
		// path programs its own, from the absolute time, immediately before the
		// call. Reprogramming on each iteration means an interrupted accept
		// cannot extend its own budget.
		deadline := atomic.LoadInt64(&ln.acceptDeadline)
		if deadline != 0 || atomic.LoadInt32(&ln.rcvTimeoSet) != 0 {
			if err := applyTimeout(lnfd, syscall.SO_RCVTIMEO, deadline); err == os.ErrDeadlineExceeded {
				return nil, err
			}
			if deadline != 0 {
				atomic.StoreInt32(&ln.rcvTimeoSet, 1)
			} else {
				atomic.StoreInt32(&ln.rcvTimeoSet, 0)
			}
		}
		// SOCK_CLOEXEC matters as much here as on the sockets this package
		// creates itself, and for longer: an accepted descriptor is a live
		// association. Without it a child process forked while the server is
		// running inherits every connection open at that moment — it can read
		// and write them, and because it holds the descriptor open, closing
		// this side neither frees the port nor sends the peer a reset.
		fd, _, err := syscall.Accept4(lnfd, syscall.SOCK_CLOEXEC)
		if err != nil {
			// A timed-out accept surfaces as EAGAIN, which is the same errno a
			// non-blocking accept would give. Only a programmed deadline can
			// produce it here, since this descriptor is blocking.
			if deadline != 0 && (errors.Is(err, syscall.EAGAIN) ||
				errors.Is(err, syscall.EWOULDBLOCK)) {
				return nil, os.ErrDeadlineExceeded
			}
			// As in SCTPReadFlags: a signal arriving while accept4 is blocked
			// interrupts it, and a server spends most of its life blocked
			// here. Reporting EINTR would look like an accept failure and a
			// caller that treats one as fatal would stop serving entirely.
			//
			// The listener descriptor is re-read each iteration so that a
			// concurrent Close, which swaps it to -1, ends the loop with EBADF
			// rather than retrying forever against a closed socket.
			if errors.Is(err, syscall.EINTR) {
				if lnfd = ln.fd(); lnfd < 0 {
					return nil, syscall.EBADF
				}
				continue
			}
			return nil, err
		}
		// The accepted socket inherits the listener's receive timeout, which is
		// how the accept deadline is implemented: sctp_copy_sock copies
		// sk_rcvtimeo onto the socket the kernel creates for the association.
		// So a listener polled with a short deadline — the ordinary idiom for
		// noticing a shutdown flag between accepts — hands out connections that
		// are already armed to time out, and the SCTPConn wrapping this
		// descriptor records no deadline, so the read path's corrective
		// applyTimeout never runs and the caller gets a bare EAGAIN rather than
		// os.ErrDeadlineExceeded. Measured at 309ms against a 300ms accept
		// window on a connection that never had a deadline of its own.
		//
		// Cleared unconditionally rather than only when a deadline is currently
		// programmed: a concurrent SetDeadline can arm the listener between the
		// check above and accept4 returning, and one setsockopt is not worth a
		// race against the association setup that just completed.
		if err := applyTimeout(fd, syscall.SO_RCVTIMEO, 0); err != nil {
			_ = syscall.Close(fd)
			return nil, err
		}
		return NewSCTPConn(fd, ln.notificationHandler), nil
	}
}

// Accept waits for and returns the next connection to the listener.
func (ln *SCTPListener) Accept() (net.Conn, error) {
	// Converted explicitly rather than returned straight through. A nil
	// *SCTPConn assigned to a net.Conn keeps its type word, so the result
	// compares unequal to nil and the idiomatic `if conn != nil` on an accept
	// failure is true — after which any use of it panics in (*SCTPConn).fd.
	// net.TCPListener.Accept does the same for the same reason, and an accept
	// deadline expiring is enough to reach it.
	c, err := ln.AcceptSCTP()
	if err != nil {
		return nil, err
	}
	return c, nil
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
	// Shutdown unblocks any Accept parked on this socket, and on a listening
	// SCTP socket it succeeds rather than failing: inet_shutdown routes a
	// listening socket through its TCP_LISTEN branch to sk_prot->disconnect,
	// and sctp_disconnect sets RCV_SHUTDOWN and returns 0 for a one-to-one
	// socket — every socket this package creates is SOCK_STREAM. RCV_SHUTDOWN
	// is one of the conditions sctp_wait_for_accept breaks on, and
	// inet_shutdown's trailing sk_state_change wakes the waiter to re-check it,
	// so the parked accept returns EINVAL. Measured at 135us.
	//
	// The result is still ignored, because a descriptor that was never
	// listening reports ENOTCONN or EOPNOTSUPP here and neither is a close
	// failure. The previous version of this comment gave ENOTCONN as the
	// expected outcome, which is the errno for a socket that is not listening
	// at all rather than for this path.
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
	network, _, err := canonicalNetwork(network)
	if err != nil {
		return nil, err
	}

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
		// EADDRINUSE here means the source address and port are already taken.
		if err = bindLocal(sock, laddr, af); err != nil {
			return nil, err
		}
	}
	var viaEALREADY bool
	_, viaEALREADY, err = sctpConnect(sock, raddr)
	if err != nil {
		return nil, err
	}
	// A connect that completed normally needs nothing further: the kernel
	// waited for the handshake before returning, so the association is there.
	//
	// EALREADY is the exception. It is an early return that skips the kernel's
	// own wait, so it says the endpoint holds the association but not that the
	// handshake finished — and measured under signal load, one such dial in two
	// never established. This function owns the socket and returns a *SCTPConn,
	// so handing back one with nothing behind it would surface as a dial that
	// reported success and a first write that failed with EPIPE. Only this
	// branch is confirmed, and only it can pay the wait.
	if viaEALREADY && !waitEstablished(sock, connectSettleTimeout) {
		err = syscall.ETIMEDOUT
		return nil, err
	}
	return NewSCTPConn(sock, notificationHandler), nil
}

// dialSCTPExtConfigContext is dialSCTPExtConfig with the wait under this
// function's control instead of the kernel's.
//
// The difference is SOCK_NONBLOCK. A blocking connect does not return until the
// kernel either completes the handshake or exhausts its own retransmission
// budget, so a caller that gives up at its own deadline can stop waiting but
// cannot stop the attempt: the association stays in COOKIE-WAIT, the scheduled
// INIT retransmission still goes out, and the descriptor is held until the
// kernel abandons it. A dial abandoned after one second was measured still
// emitting an INIT thirty seconds later.
//
// SCTP_INITMSG cannot express "send one INIT" either. MaxAttempts counts
// retransmissions rather than attempts and zero selects the kernel default, so
// the smallest usable value still puts a second INIT on the wire at
// net.sctp.rto_initial; MaxInitTimeout caps each RTO without bounding the total.
// So the bound has to come from here.
func dialSCTPExtConfigContext(ctx context.Context, network string, laddr, raddr *SCTPAddr, options InitMsg, control func(network, address string, c syscall.RawConn) error, notificationHandler NotificationHandler) (*SCTPConn, error) {
	network, _, err := canonicalNetwork(network)
	if err != nil {
		return nil, err
	}

	// A context that is already done must not open a socket at all.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	af, ipv6only := favoriteAddrFamily(network, laddr, raddr, "dial")
	sock, err := syscall.Socket(
		af,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK,
		syscall.IPPROTO_SCTP,
	)
	if err != nil {
		return nil, err
	}

	// Abort rather than close on every failure path. Nothing is established, so
	// there is no shutdown to negotiate, and an abort releases the association
	// at once instead of leaving the kernel retransmitting an INIT on a socket
	// the caller has already given up on. That is the whole point of this
	// variant, so it is a defer rather than a branch: no early return may skip
	// it.
	established := false
	defer func() {
		if !established {
			_ = abortSctpSocket(sock)
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
	if err = setInitOpts(sock, options); err != nil {
		return nil, err
	}
	if laddr != nil {
		if err = bindLocal(sock, laddr, af); err != nil {
			return nil, err
		}
	}

	// On a non-blocking socket the handshake is started and EINPROGRESS comes
	// straight back; EALREADY would mean one is already under way. Neither is a
	// failure. The EALREADY settle the blocking path needs does not apply here,
	// because the wait below confirms establishment in every case rather than
	// trusting what connect returned.
	//
	// Tolerating EALREADY is defensive rather than load-bearing. This is the
	// first connect on a socket this function created, so the kernel has no
	// earlier attempt to find: 200 of 200 measured attempts against a
	// blackholed address returned EINPROGRESS and none returned EALREADY. What
	// keeps it here is the control hook above, which is handed the descriptor
	// and could have connected it. A mutation dropping the tolerance survives
	// the suite for the same reason the branch is unreachable.
	if _, _, err = sctpConnect(sock, raddr); err != nil &&
		!errors.Is(err, syscall.EINPROGRESS) && !errors.Is(err, syscall.EALREADY) {
		return nil, err
	}

	if err = awaitEstablished(ctx, sock); err != nil {
		return nil, err
	}

	// Back to blocking before the socket is handed over. SCTPRead, ReadMsg and
	// the deadline handling all assume a blocking descriptor — SO_RCVTIMEO only
	// bounds a call that waits — and on a non-blocking one an idle read returns
	// EAGAIN, which this package maps onto os.ErrDeadlineExceeded and a caller
	// reads as a timeout that never happened.
	if err = syscall.SetNonblock(sock, false); err != nil {
		return nil, err
	}

	established = true
	return NewSCTPConn(sock, notificationHandler), nil
}

// awaitEstablished waits for the handshake to finish or for ctx to be done,
// whichever comes first. It is waitEstablished with a context in place of a
// fixed timeout, and polls at the same interval.
func awaitEstablished(ctx context.Context, fd int) error {
	const interval = 2 * time.Millisecond

	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		// A refused or aborted association surfaces through SO_ERROR rather
		// than through the connect, which returned before the peer answered.
		if errno, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET,
			syscall.SO_ERROR); err == nil && errno != 0 {
			return syscall.Errno(errno)
		}
		// Checked before ctx so that a handshake which completed in the same
		// instant the deadline expired is not thrown away.
		if hasEstablishedAssoc(fd) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// DialSCTPContext is DialSCTPExt with a context.
//
// The attempt is abandoned as soon as ctx is done: the association is aborted
// and the socket released before this returns, so nothing further goes on the
// wire and no descriptor is left behind. A caller expresses a bounded attempt
// with context.WithTimeout and retries on its own schedule.
//
// DialSCTP, DialSCTPExt and SocketConfig.Dial are unchanged and still block for
// as long as the kernel's own retransmission budget.
func DialSCTPContext(ctx context.Context, network string, laddr, raddr *SCTPAddr, options InitMsg) (*SCTPConn, error) {
	return dialSCTPExtConfigContext(ctx, network, laddr, raddr, options, nil, nil)
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

// peeloffArg mirrors sctp_peeloff_arg_t.
//
// Both members are 32 bits in the kernel — sctp_assoc_t is __s32 and sd is an
// int — so the struct is 8 bytes with sd at offset 4. The Go version used to
// declare sd as int, which is 64 bits on every target anyone runs this on. That
// made the struct 16 bytes with sd at offset 8, so the kernel wrote the new
// descriptor at offset 4 and PeelOff read offset 8, which nothing had written:
// it returned an SCTPConn wrapping descriptor 0, and leaked the real one.
//
// It went unnoticed because it is right on 32-bit, where Go's int is 32 bits,
// and because nothing tested it.
type peeloffArg struct {
	assocID int32
	sd      int32
}

// PeelOff detaches association id onto its own socket (RFC 6458 §9.2).
//
// This only works on a one-to-many (SOCK_SEQPACKET) socket, which is what
// peeling off is for: it turns one association out of many into a socket of its
// own. Every socket this package creates is one-to-one, so calling this on one
// of them returns EINVAL from the kernel — sctp_do_peeloff rejects any other
// style. It is usable through NewSCTPConn on a one-to-many descriptor the
// caller made themselves.
//
// Close on the result does not shut the association down gracefully. A peeled
// socket looks one-to-one from userspace but is not one internally:
// sctp_do_peeloff builds it with sctp_clone_sock(..., SCTP_SOCKET_UDP_HIGH_BANDWIDTH),
// and sctp_shutdown opens with "if (!sctp_style(sk, TCP)) return", so shutdown(2)
// on it succeeds and does nothing. Measured, with a capture on both sides:
//
//	                    ordinary conn   peeled conn
//	Close returned in   21.7us          3.005s
//	SHUTDOWN on wire    1               0
//	ABORT on wire       0               1
//
// So Close waits out its whole grace period — SCTP_STATUS keeps reporting
// SCTP_ESTABLISHED, so nothing tells it the handshake finished — and then falls
// back to the abort. The peer sees an ABORT rather than a SHUTDOWN.
//
// Use CloseWithTimeout with a short budget, or Abort, if that outcome is
// acceptable and the delay is not. This is kernel behaviour rather than a defect
// here, and TestClosingAPeeledConnectionAbortsRatherThanShuttingDown is written
// to fail if a later kernel starts honouring shutdown on these sockets.
func (c *SCTPConn) PeelOff(id int) (*SCTPConn, error) {
	// SCTP_SOCKOPT_PEELOFF gives no way to ask for close-on-exec, so the
	// peeled descriptor would leak into any child forked afterwards — the same
	// defect accept4 had here. SCTP_SOCKOPT_PEELOFF_FLAGS exists for exactly
	// this and takes the same struct with a flags word appended. It is the
	// newer of the two, so an older kernel answering ENOPROTOOPT falls back
	// rather than failing the call.
	flagged := struct {
		arg   peeloffArg
		flags uint32
	}{arg: peeloffArg{assocID: int32(id)}, flags: syscall.SOCK_CLOEXEC}
	optlen := unsafe.Sizeof(flagged)
	_, _, err := getsockopt(c.fd(), SCTP_SOCKOPT_PEELOFF_FLAGS,
		uintptr(unsafe.Pointer(&flagged)), uintptr(unsafe.Pointer(&optlen)))
	if err == nil {
		if flagged.arg.sd < 0 {
			return nil, syscall.EINVAL
		}
		return &SCTPConn{_fd: flagged.arg.sd}, nil
	}
	if !errors.Is(err, syscall.ENOPROTOOPT) {
		return nil, err
	}

	param := peeloffArg{assocID: int32(id)}
	optlen = unsafe.Sizeof(param)
	_, _, err = getsockopt(c.fd(), SCTP_SOCKOPT_PEELOFF, uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil {
		return nil, err
	}
	if param.sd < 0 {
		// Defensive: the kernel returns the descriptor in the struct rather
		// than as the syscall result, so a negative value here would otherwise
		// become an SCTPConn that fails every call with EBADF.
		return nil, syscall.EINVAL
	}
	return &SCTPConn{_fd: param.sd}, nil
}
