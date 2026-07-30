//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestPollConstantsMatchKernel pins the hand-written poll(2) bits against the
// epoll ones, which the syscall package generates from the kernel headers. The
// kernel defines both sets to the same values, so a typo in the constants above
// shows up here rather than as a wait that never fires.
//
// pollNval has no epoll counterpart — epoll rejects an invalid descriptor at
// registration rather than reporting it as an event — so it is pinned to its
// asm-generic/poll.h value directly.
func TestPollConstantsMatchKernel(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"POLLIN", pollIn, syscall.EPOLLIN},
		{"POLLOUT", pollOut, syscall.EPOLLOUT},
		{"POLLERR", pollErr, syscall.EPOLLERR},
		{"POLLHUP", pollHup, syscall.EPOLLHUP},
		{"POLLNVAL", pollNval, 0x020},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, want %#x", tc.name, tc.got, tc.want)
		}
	}
}

// TestPollFdLayoutMatchesKernel pins struct pollfd. Getting this wrong would not
// fail to compile — it would hand the kernel a descriptor read from the wrong
// offset, which reads as a wait that never becomes ready.
func TestPollFdLayoutMatchesKernel(t *testing.T) {
	var p pollFd
	if got, want := unsafe.Sizeof(p), uintptr(8); got != want {
		t.Errorf("sizeof(pollFd) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(p.Fd), uintptr(0); got != want {
		t.Errorf("offsetof(Fd) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(p.Events), uintptr(4); got != want {
		t.Errorf("offsetof(Events) = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(p.Revents), uintptr(6); got != want {
		t.Errorf("offsetof(Revents) = %d, want %d", got, want)
	}
}

// TestPollWaitReportsTimeout checks the helper's own contract: no events and no
// error when nothing becomes ready in time. Every wait in the package treats a
// zero return as "the slice elapsed", so a helper that reported readiness on
// timeout would turn each of them into a spin.
func TestPollWaitReportsTimeout(t *testing.T) {
	client, _ := eorPair(t)

	start := time.Now()
	revents, err := pollWait(client.fd(), pollIn, 200*time.Millisecond)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("pollWait: %v", err)
	}
	if revents != 0 {
		t.Errorf("revents = %#x, want 0; nothing was sent, so the socket "+
			"cannot have become readable", revents)
	}
	if elapsed < 150*time.Millisecond {
		t.Errorf("returned after %v, well before its timeout", elapsed)
	}
}

// TestPollWaitReportsWritable is the positive case, so that a helper which
// always reported "timed out" could not pass the test above.
func TestPollWaitReportsWritable(t *testing.T) {
	client, _ := eorPair(t)

	revents, err := pollWait(client.fd(), pollOut, 5*time.Second)
	if err != nil {
		t.Fatalf("pollWait: %v", err)
	}
	if revents&pollOut == 0 {
		t.Errorf("revents = %#x, want POLLOUT set on an empty send buffer", revents)
	}
}

// fillSendBuffer writes payload until the socket refuses more, and reports how
// many messages were accepted. The peer must not be reading, or this never
// returns.
//
// The bound is a message count rather than a byte count because the send buffer
// size is not something this package controls: the kernel sizes it from
// net.core.wmem_default (or net.sctp.sctp_wmem), and a caller may have changed
// it with SetWriteBuffer. A million messages is far past any plausible buffer
// and turns a stuck test into a named failure rather than a suite timeout.
func fillSendBuffer(t *testing.T, c *SCTPConn, payload []byte) int {
	t.Helper()
	for i := 0; i < 1<<20; i++ {
		if _, err := c.SCTPWrite(payload, nil); err != nil {
			if errors.Is(err, syscall.EAGAIN) {
				return i
			}
			t.Fatalf("write %d: %v", i, err)
		}
	}
	t.Fatalf("send buffer never filled after 1048576 messages of %d bytes",
		len(payload))
	return 0
}

// drainAfter reads sent messages from c, but not before begin is closed. The
// caller controls when draining starts, so a test can guarantee the send buffer
// is still full at the moment it wants it to be.
func drainAfter(c *SCTPConn, begin <-chan struct{}, sent int) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-begin
		buf := make([]byte, 1<<16)
		for i := 0; i < sent; i++ {
			if _, _, err := c.SCTPRead(buf); err != nil {
				return
			}
		}
	}()
	return done
}

// TestSyscallConnWriteWaitsForWritability is the reported defect.
//
// Once the send buffer fills, SCTPWrite reports EAGAIN. The ordinary way to
// wait for the socket to drain is SyscallConn().Write, which invokes f and,
// when f reports it is not done, waits for the descriptor to become writable
// and calls it again. Before the fix that method panicked with "not
// implemented", so a caller had no supported way to wait at all.
//
// The drain is deliberately not started until f has been called once and has
// reported EAGAIN. Without that ordering the peer could empty the buffer before
// the first attempt, the write would succeed immediately, and the test would
// pass without ever exercising the wait.
func TestSyscallConnWriteWaitsForWritability(t *testing.T) {
	client, server := eorPair(t)

	payload := fill(512)
	sent := fillSendBuffer(t, client, payload)
	t.Logf("send buffer accepted %d messages of %d bytes", sent, len(payload))

	begin := make(chan struct{})
	drained := drainAfter(server, begin, sent)

	rc, err := client.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := client.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	var (
		start sync.Once
		n     int
		werr  error
		calls int
	)
	if err := rc.Write(func(fd uintptr) bool {
		calls++
		n, werr = syscall.SendmsgN(int(fd), payload, nil, nil, syscall.MSG_DONTWAIT)
		if errors.Is(werr, syscall.EAGAIN) {
			// The buffer really is full. Release the reader and wait.
			start.Do(func() { close(begin) })
			return false
		}
		return true
	}); err != nil {
		t.Fatalf("rc.Write: %v", err)
	}

	if werr != nil {
		t.Fatalf("sendmsg through RawConn: %v", werr)
	}
	if n != len(payload) {
		t.Errorf("sendmsg wrote %d bytes, want %d", n, len(payload))
	}
	if calls < 2 {
		t.Errorf("f was called %d time(s); the send buffer was full on entry, "+
			"so the write had to wait and retry at least once", calls)
	}
	<-drained
}

// TestSyscallConnReadWaitsForData is the read-side counterpart: f reports it is
// not done, and Read waits for the descriptor to become readable rather than
// spinning or panicking.
func TestSyscallConnReadWaitsForData(t *testing.T) {
	client, server := eorPair(t)

	rc, err := server.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	want := []byte("through the raw conn")
	var start sync.Once
	buf := make([]byte, 128)
	var (
		n     int
		rerr  error
		calls int
	)
	if err := rc.Read(func(fd uintptr) bool {
		calls++
		n, _, rerr = syscall.Recvfrom(int(fd), buf, syscall.MSG_DONTWAIT)
		if errors.Is(rerr, syscall.EAGAIN) {
			// Nothing queued yet. Ask for the write only now, so the first
			// attempt is guaranteed to have found the socket empty.
			start.Do(func() {
				go func() {
					_, _ = client.SCTPWrite(want, nil)
				}()
			})
			return false
		}
		return true
	}); err != nil {
		t.Fatalf("rc.Read: %v", err)
	}

	if rerr != nil {
		t.Fatalf("recvfrom through RawConn: %v", rerr)
	}
	if got := string(buf[:n]); got != string(want) {
		t.Errorf("read %q, want %q", got, want)
	}
	if calls < 2 {
		t.Errorf("f was called %d time(s); the socket was empty on entry, so "+
			"the read had to wait and retry at least once", calls)
	}
}

// TestSyscallConnStopsWhenDone checks the other half of the contract: when f
// reports it is done on the first call, the method returns without waiting.
func TestSyscallConnStopsWhenDone(t *testing.T) {
	client, _ := eorPair(t)

	rc, err := client.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	for _, tc := range []struct {
		name string
		call func(func(uintptr) bool) error
	}{
		{"Read", rc.Read},
		{"Write", rc.Write},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			done := make(chan error, 1)
			go func() {
				done <- tc.call(func(uintptr) bool {
					calls++
					return true
				})
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s did not return although f reported done", tc.name)
			}
			if calls != 1 {
				t.Errorf("f called %d times, want exactly 1", calls)
			}
		})
	}
}

// TestSyscallConnHonoursDeadline checks that a wait is bounded by the deadline
// already on the connection, and reports the expiry the way the rest of the
// package does.
//
// f never reports done, so the only way out is the deadline.
func TestSyscallConnHonoursDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, c *SCTPConn, payload []byte)
		setDl   func(c *SCTPConn, t time.Time) error
		call    func(rc syscall.RawConn, f func(uintptr) bool) error
	}{
		{
			name:    "Read",
			prepare: func(*testing.T, *SCTPConn, []byte) {},
			setDl:   (*SCTPConn).SetReadDeadline,
			call:    func(rc syscall.RawConn, f func(uintptr) bool) error { return rc.Read(f) },
		},
		{
			name: "Write",
			prepare: func(t *testing.T, c *SCTPConn, payload []byte) {
				fillSendBuffer(t, c, payload)
			},
			setDl: (*SCTPConn).SetWriteDeadline,
			call:  func(rc syscall.RawConn, f func(uintptr) bool) error { return rc.Write(f) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := eorPair(t)
			payload := fill(512)
			tc.prepare(t, client, payload)

			rc, err := client.SyscallConn()
			if err != nil {
				t.Fatalf("SyscallConn: %v", err)
			}
			if err := tc.setDl(client, time.Now().Add(300*time.Millisecond)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}

			start := time.Now()
			err = tc.call(rc, func(uintptr) bool { return false })
			elapsed := time.Since(start)

			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
			}
			if elapsed < 250*time.Millisecond {
				t.Errorf("returned after %v, before the deadline it was given", elapsed)
			}
			if elapsed > 10*time.Second {
				t.Errorf("returned after %v, far past its deadline", elapsed)
			}
		})
	}
}

// TestSyscallConnAfterCloseReturnsEBADF checks that a RawConn outliving its
// connection reports a closed descriptor rather than operating on a number the
// kernel may already have handed to an unrelated socket.
func TestSyscallConnAfterCloseReturnsEBADF(t *testing.T) {
	client, _ := eorPairNoCleanup(t)

	rc, err := client.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := client.CloseWithTimeout(200 * time.Millisecond); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, name := range []string{"Control", "Read", "Write"} {
		t.Run(name, func(t *testing.T) {
			called := false
			var err error
			switch name {
			case "Control":
				err = rc.Control(func(uintptr) { called = true })
			case "Read":
				err = rc.Read(func(uintptr) bool { called = true; return true })
			case "Write":
				err = rc.Write(func(uintptr) bool { called = true; return true })
			}
			if !errors.Is(err, syscall.EBADF) {
				t.Errorf("err = %v, want syscall.EBADF", err)
			}
			if called {
				t.Error("f was invoked on a descriptor belonging to a closed connection")
			}
		})
	}
}

// TestListenerSyscallConnReadWriteReturnEINVAL pins the listener to what the
// standard library does. net/rawconn.go gives a listener's RawConn Read and
// Write methods that return syscall.EINVAL, and TCPListener.SyscallConn
// documents it: "The returned RawConn only supports calling Control. Read and
// Write return an error." Waiting for accept readiness through RawConn is not a
// supported idiom anywhere in net, so matching that is the whole fix here —
// what must not survive is the panic.
func TestListenerSyscallConnReadWriteReturnEINVAL(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	rc, err := ln.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	// Control stays useful — it is what SocketConfig hooks are given.
	var fd uintptr
	if err := rc.Control(func(f uintptr) { fd = f }); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if fd == 0 {
		t.Error("Control did not hand out a descriptor")
	}

	if err := rc.Read(func(uintptr) bool { return true }); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Read err = %v, want syscall.EINVAL", err)
	}
	if err := rc.Write(func(uintptr) bool { return true }); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Write err = %v, want syscall.EINVAL", err)
	}
}

// TestSCTPWriteWithoutDeadlineReturnsEAGAIN pins the behaviour commit 2cd8759
// introduced, which nothing in the suite asserted before.
//
// MSG_DONTWAIT is there so a send to a peer that has stopped reading fails
// instead of parking for minutes with no way to interrupt it. A change that made
// writes block unconditionally would be a regression, and until this test
// existed the only thing standing in its way was that one unrelated test would
// have hung — a suite timeout rather than a named failure.
func TestSCTPWriteWithoutDeadlineReturnsEAGAIN(t *testing.T) {
	client, _ := eorPair(t)

	payload := fill(512)
	fillSendBuffer(t, client, payload)

	// Nothing is draining, so the buffer stays full. With no write deadline the
	// send has to refuse at once rather than wait for space that is not coming.
	start := time.Now()
	_, err := client.SCTPWrite(payload, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("err = %v, want syscall.EAGAIN", err)
	}
	if elapsed > time.Second {
		t.Errorf("refused after %v; a write with no deadline must not wait", elapsed)
	}
}

// TestSCTPWriteWithDeadlineWaitsForSpace is the other half: once a deadline is
// set, a full send buffer is backpressure to be waited out rather than an error
// to be reported.
//
// The drain starts only after a delay, so the write is guaranteed to find the
// buffer full and to have to wait for it.
func TestSCTPWriteWithDeadlineWaitsForSpace(t *testing.T) {
	client, server := eorPair(t)

	payload := fill(512)
	sent := fillSendBuffer(t, client, payload)

	begin := make(chan struct{})
	drained := drainAfter(server, begin, sent)
	go func() {
		time.Sleep(250 * time.Millisecond)
		close(begin)
	}()

	if err := client.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	start := time.Now()
	n, err := client.SCTPWrite(payload, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("SCTPWrite: %v", err)
	}
	if n != len(payload) {
		t.Errorf("wrote %d bytes, want %d", n, len(payload))
	}
	if elapsed < 200*time.Millisecond {
		t.Errorf("returned after %v, before the drain that made room started; "+
			"the send buffer cannot have been full", elapsed)
	}
	<-drained
}

// TestSCTPWriteDeadlineExpiresWhileSendBufferFull checks the expiry path, and
// that the caller can tell it apart from the flow-control condition.
//
// Before the fix this returned syscall.EAGAIN, which reports Timeout() true and
// so read as a deadline expiry to anything using the net.Error idiom, while a
// deadline that had genuinely expired was indistinguishable from a buffer that
// was merely full. Now the deadline expiry is os.ErrDeadlineExceeded, which is
// what net.Conn documents, and EAGAIN means only what it says.
func TestSCTPWriteDeadlineExpiresWhileSendBufferFull(t *testing.T) {
	client, _ := eorPair(t)

	payload := fill(512)
	fillSendBuffer(t, client, payload)

	if err := client.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	start := time.Now()
	_, err := client.SCTPWrite(payload, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	if errors.Is(err, syscall.EAGAIN) {
		t.Error("the expiry is still reported as EAGAIN, so a caller cannot " +
			"tell a deadline that expired from a buffer that is merely full")
	}
	if elapsed < 250*time.Millisecond {
		t.Errorf("gave up after %v, before the deadline it was given", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Errorf("returned after %v, far past its deadline", elapsed)
	}
}

// TestSCTPWriteDeadlineInThePastDoesNotWait keeps the pre-existing contract:
// a deadline already elapsed fails immediately rather than being ignored, and
// rather than entering the new wait.
func TestSCTPWriteDeadlineInThePastDoesNotWait(t *testing.T) {
	client, _ := eorPair(t)

	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	start := time.Now()
	_, err := client.SCTPWrite([]byte("should not be sent"), nil)
	elapsed := time.Since(start)

	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed > time.Second {
		t.Errorf("took %v; an elapsed deadline must not wait at all", elapsed)
	}
}

// TestSyscallConnDoesNotSpinWhenReadyButNotDone covers the failure mode that
// separates a level-triggered wait from the runtime's edge-triggered one.
//
// The send buffer is empty, so POLLOUT is asserted immediately and stays
// asserted; f never reports done, which syscall.RawConn explicitly permits.
// Every ppoll therefore returns at once, and a loop that simply retried would
// burn a core until the deadline. The guard paces the retries instead, so the
// call count over a fixed window stays small.
func TestSyscallConnDoesNotSpinWhenReadyButNotDone(t *testing.T) {
	client, _ := eorPair(t)

	rc, err := client.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := client.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	calls := 0
	err = rc.Write(func(uintptr) bool {
		calls++
		return false
	})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}

	t.Logf("f was called %d times over 300ms", calls)
	// Paced at rawSpinBackoff the ceiling is a few hundred. An unguarded loop
	// reaches six figures.
	if calls > 5000 {
		t.Errorf("f was called %d times over 300ms; the wait is spinning on a "+
			"descriptor that is ready rather than pacing itself", calls)
	}
	// A guard that never called f again would also stay under the ceiling, so
	// pin the other side too.
	if calls < 2 {
		t.Errorf("f was called %d time(s); the wait stopped retrying entirely", calls)
	}
}

// TestSyscallConnCloseUnblocksWait checks that a parked wait notices a graceful
// Close.
//
// The wakeup here comes from the kernel, not from the polling cadence:
// closeSctpSocket calls shutdown(SHUT_RDWR) before it closes, and that wakes
// anything parked on the descriptor. Making rawWaitSlice ten minutes leaves this
// test green, which is how that was established rather than assumed — see
// TestSyscallConnAbortUnblocksWait for the path where no such wakeup exists and
// the cadence is the only thing that ends the wait.
func TestSyscallConnCloseUnblocksWait(t *testing.T) {
	client, _ := eorPairNoCleanup(t)

	rc, err := client.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	// No deadline: the close is the only thing that can end this wait.
	done := make(chan error, 1)
	parked := make(chan struct{})
	go func() {
		done <- rc.Read(func(uintptr) bool {
			select {
			case <-parked:
			default:
				close(parked)
			}
			return false
		})
	}()

	<-parked
	time.Sleep(100 * time.Millisecond)
	if err := client.CloseWithTimeout(200 * time.Millisecond); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, syscall.EBADF) {
			t.Errorf("err = %v, want syscall.EBADF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the parked wait never returned after Close")
	}
}

// TestSyscallConnAbortUnblocksWait is the case that has no kernel wakeup at all.
//
// Abort sets SO_LINGER to zero and closes the descriptor outright — there is no
// shutdown, so nothing wakes a task already parked in ppoll on it, and Linux
// does not wake pollers when another thread closes the descriptor they are
// waiting on. The only thing that ends this wait is the wait coming up for air
// on its own and re-reading the descriptor. Without that bound a caller with no
// deadline set would park until the process exited.
func TestSyscallConnAbortUnblocksWait(t *testing.T) {
	client, _ := eorPairNoCleanup(t)

	rc, err := client.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	// No deadline: the abort is the only thing that can end this wait.
	done := make(chan error, 1)
	parked := make(chan struct{})
	var once sync.Once
	go func() {
		done <- rc.Read(func(uintptr) bool {
			once.Do(func() { close(parked) })
			return false
		})
	}()

	<-parked
	// Long enough that the wait is genuinely inside ppoll rather than between
	// rounds, so the abort has to interrupt a parked wait rather than being
	// noticed by a loop that happened to be turning over.
	time.Sleep(150 * time.Millisecond)
	if err := client.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}

	start := time.Now()
	select {
	case err := <-done:
		if !errors.Is(err, syscall.EBADF) {
			t.Errorf("err = %v, want syscall.EBADF", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("returned %v after the abort", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the parked wait never returned after Abort; nothing wakes a " +
			"poller on this path, so only the bounded wait can end it")
	}
}

// TestSocketConfigRawConnReadWriteReturnEINVAL covers the other place a RawConn
// is handed out: the SocketConfig hook, which runs on a socket that is neither
// connected nor listening. It used to panic there too.
func TestSocketConfigRawConnReadWriteReturnEINVAL(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	var (
		sawControl bool
		readErr    error
		writeErr   error
	)
	cfg := SocketConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if err := c.Control(func(uintptr) { sawControl = true }); err != nil {
				return err
			}
			readErr = c.Read(func(uintptr) bool { return true })
			writeErr = c.Write(func(uintptr) bool { return true })
			return nil
		},
	}
	ln, err := cfg.Listen("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if !sawControl {
		t.Error("the Control hook never ran, so this proves nothing")
	}
	if !errors.Is(readErr, syscall.EINVAL) {
		t.Errorf("Read err = %v, want syscall.EINVAL", readErr)
	}
	if !errors.Is(writeErr, syscall.EINVAL) {
		t.Errorf("Write err = %v, want syscall.EINVAL", writeErr)
	}
}

// TestSyscallConnConcurrent runs several RawConn writers and a reader against
// one association, so that -race sees the descriptor and deadline accesses
// under actual contention rather than in a single-goroutine walk-through.
func TestSyscallConnConcurrent(t *testing.T) {
	client, server := eorPair(t)

	rc, err := client.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := client.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	const writers, each = 4, 50
	var delivered int64

	stop := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 1<<16)
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Bounded per read. A deadline set after a read has already blocked
			// does not interrupt it — SetReadDeadline documents that — so the
			// bound has to be in force before each call rather than applied from
			// outside once the test is finished.
			if err := server.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				return
			}
			if _, _, err := server.SCTPRead(buf); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				return
			}
			atomic.AddInt64(&delivered, 1)
		}
	}()

	payload := fill(1024)
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				var werr error
				if err := rc.Write(func(fd uintptr) bool {
					_, werr = syscall.SendmsgN(int(fd), payload, nil, nil,
						syscall.MSG_DONTWAIT)
					return !errors.Is(werr, syscall.EAGAIN)
				}); err != nil {
					errs <- err
					return
				}
				if werr != nil {
					errs <- werr
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent RawConn write: %v", err)
	}

	// Let the reader catch up, then stop it. The count is a liveness check, not
	// an exact assertion: the reader races the writers by construction.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) &&
		atomic.LoadInt64(&delivered) < int64(writers*each) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&delivered); got != int64(writers*each) {
		t.Errorf("delivered %d of %d messages", got, writers*each)
	}
	close(stop)
	<-drained
}
