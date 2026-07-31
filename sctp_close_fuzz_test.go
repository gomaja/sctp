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
	"errors"
	"io"
	"sync"
	"syscall"
	"testing"
	"time"
)

// FuzzCloseWithTimeout varies the grace period, including the negative and
// zero values that select the immediate-abort path, and the sub-microsecond
// values where the timeval conversion could round down to "no timeout" and
// block forever.
//
// The invariant: CloseWithTimeout always returns, always releases the
// descriptor, and a second call always reports EBADF.
func FuzzCloseWithTimeout(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(-1))
	f.Add(int64(1))                // 1ns: rounds up to 1us
	f.Add(int64(999))              // sub-microsecond
	f.Add(int64(time.Millisecond)) //nolint:gosec
	f.Add(int64(3 * time.Second))  //nolint:gosec
	f.Add(int64(time.Hour))        //nolint:gosec

	f.Fuzz(func(t *testing.T, ns int64) {
		// Keep the wait bounded: this exercises the conversion arithmetic and
		// the branch selection, not real multi-second waits.
		if ns > int64(2*time.Second) {
			ns = int64(2 * time.Second)
		}
		timeout := time.Duration(ns)

		// Rapid dial churn can hit EISCONN from SCTPConnect (see
		// TestDialUnderChurnReportsEISCONN); that is a dial-side limitation,
		// not a close-path failure, so skip rather than fail this iteration.
		client, server, ok := eorPairMaybe(t)
		if !ok {
			t.Skip("association could not be established this iteration")
		}
		defer func() { _ = server.Close() }()

		fd := client.fd()

		done := make(chan error, 1)
		go func() { done <- client.CloseWithTimeout(timeout) }()

		select {
		case err := <-done:
			if err != nil && !errors.Is(err, syscall.EBADF) {
				t.Fatalf("timeout=%v: CloseWithTimeout = %v", timeout, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("timeout=%v: CloseWithTimeout never returned", timeout)
		}

		if fd >= 0 && fdIsOpen(fd) {
			t.Fatalf("timeout=%v: descriptor %d still open after close", timeout, fd)
		}
		if err := client.Close(); !errors.Is(err, syscall.EBADF) {
			t.Fatalf("timeout=%v: second Close = %v, want EBADF", timeout, err)
		}
	})
}

// TestCloseTimeoutZeroIsImmediate pins the documented equivalence between a
// non-positive timeout and Abort.
func TestCloseTimeoutZeroIsImmediate(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		client, server := eorPairNoCleanup(t)

		start := time.Now()
		if err := client.CloseWithTimeout(timeout); err != nil {
			t.Fatalf("timeout=%v: %v", timeout, err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("timeout=%v: took %v, expected an immediate abort", timeout, d)
		}
		_ = server.Close()
	}
}

// TestCloseSubMicrosecondTimeout guards the timeval conversion: a timeout
// under one microsecond must not truncate to zero, which the kernel reads as
// "block forever".
func TestCloseSubMicrosecondTimeout(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	defer func() { _ = server.Close() }()

	done := make(chan error, 1)
	go func() { done <- client.CloseWithTimeout(1 * time.Nanosecond) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CloseWithTimeout(1ns) = %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("CloseWithTimeout(1ns) blocked; the timeval likely truncated to zero")
	}
}

// TestCloseChurnUnderLoad is the industry case: a signalling node cycling many
// associations must not accumulate descriptors or wedge on teardown.
func TestCloseChurnUnderLoad(t *testing.T) {
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			c, err := ln.AcceptSCTP()
			if err != nil {
				return
			}
			go func(c *SCTPConn) {
				buf := make([]byte, 512)
				for {
					if _, _, err := c.SCTPRead(buf); err != nil {
						// The client has already gone; abort rather than run
						// a graceful shutdown that has no peer to answer it
						// and would serialise the whole test.
						_ = c.Abort()
						return
					}
				}
			}(c)
		}
	}()

	before := countOpenFds(t)

	const workers, perWorker = 8, 15
	var wg sync.WaitGroup
	wg.Add(workers)
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				conn, err := dialRetry(ln.Addr().(*SCTPAddr))
				if err != nil {
					// Rapid reconnects can fail with EISCONN or EALREADY from
					// SCTPConnect; see TestDialUnderChurnReportsEISCONN. That
					// is a dial-side limitation, not a teardown failure, so it
					// must not be counted as one here.
					continue
				}
				// Send something so the association is real before teardown.
				_, _ = conn.SCTPWrite([]byte("churn"), nil)

				// Alternate graceful and immediate teardown. The graceful path
				// uses a short grace period deliberately: the server aborts its
				// side as soon as its read fails, so a SHUTDOWN may find no
				// peer to answer it and the default period would make this loop
				// wait out the timeout each time.
				if (w+i)%2 == 0 {
					err = conn.CloseWithTimeout(200 * time.Millisecond)
				} else {
					err = conn.Abort()
				}
				if err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	var failures int
	for err := range errs {
		failures++
		if failures <= 3 {
			t.Logf("teardown error: %v", err)
		}
	}
	if failures > 0 {
		t.Errorf("%d of %d cycles failed", failures, workers*perWorker)
	}

	// Wait for the accept goroutines to reap their side. The descriptor count
	// is process-global, so other tests running concurrently in the same
	// binary can inflate it transiently; poll until it settles rather than
	// sampling once and treating a neighbour's socket as a leak here.
	const margin = 20
	var after int
	for attempt := 0; attempt < 40; attempt++ {
		time.Sleep(100 * time.Millisecond)
		after = countOpenFds(t)
		if after <= before+margin {
			break
		}
	}
	t.Logf("descriptors before=%d after=%d over %d cycles",
		before, after, workers*perWorker)
	if after > before+margin {
		t.Errorf("descriptors grew from %d to %d over %d cycles and did not settle",
			before, after, workers*perWorker)
	}
}

// TestCloseRacesWithReadAndWrite drives close against concurrent I/O, the
// shape that surfaces use-after-close on a recycled descriptor.
func TestCloseRacesWithReadAndWrite(t *testing.T) {
	for round := 0; round < 20; round++ {
		client, server := eorPairNoCleanup(t)

		var wg sync.WaitGroup
		wg.Add(3)

		go func() {
			defer wg.Done()
			buf := make([]byte, 256)
			for i := 0; i < 50; i++ {
				if _, _, err := client.SCTPRead(buf); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			payload := []byte("racing")
			for i := 0; i < 50; i++ {
				if _, err := client.SCTPWrite(payload, nil); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(round%5) * time.Millisecond)
			_ = client.Close()
		}()

		wg.Wait()
		_ = server.Close()
	}
}

// TestAbortDoesNotWait checks Abort returns promptly even when the peer is
// gone, since it performs no handshake.
func TestAbortDoesNotWait(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	if err := server.Abort(); err != nil {
		t.Fatalf("server abort: %v", err)
	}

	start := time.Now()
	if err := client.Abort(); err != nil {
		t.Fatalf("client abort: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Abort took %v against a dead peer; it must not wait", d)
	}
}

// oneToManyPair returns a bound and listening one-to-many socket wrapped as an
// SCTPConn, plus a connected client, and the association id to peel.
//
// PeelOff is only meaningful on a one-to-many socket; this package creates only
// one-to-one ones, so the socket is made here by hand exactly as
// TestPeelOffSucceedsOnAOneToManySocket does.
func oneToManyPair(t *testing.T) (server, client *SCTPConn, assocID int) {
	t.Helper()

	m2m, err := syscall.Socket(syscall.AF_INET,
		syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("cannot create a one-to-many SCTP socket: %v", err)
	}
	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], []byte{127, 0, 0, 1})
	if err := syscall.Bind(m2m, sa); err != nil {
		_ = syscall.Close(m2m)
		t.Skipf("bind: %v", err)
	}
	if err := syscall.Listen(m2m, 4); err != nil {
		_ = syscall.Close(m2m)
		t.Skipf("listen: %v", err)
	}
	bound, err := syscall.Getsockname(m2m)
	if err != nil {
		_ = syscall.Close(m2m)
		t.Fatalf("getsockname: %v", err)
	}
	port := bound.(*syscall.SockaddrInet4).Port

	server = NewSCTPConn(m2m, nil)
	if err := server.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		_ = server.Close()
		t.Skipf("SubscribeEvents: %v", err)
	}

	client, err = DialSCTP("sctp", nil, mustResolve(t, "127.0.0.1:"+itoa(port)))
	if err != nil {
		_ = server.Close()
		t.Skipf("dial: %v", err)
	}
	if _, err := client.SCTPWrite([]byte("x"), nil); err != nil {
		_ = server.Close()
		_ = client.Close()
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	if err := server.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, info, err := server.SCTPRead(buf)
	if err != nil || info == nil || info.AssocID == 0 {
		_ = server.Close()
		_ = client.Close()
		t.Skipf("no association id to peel (%v)", err)
	}
	return server, client, int(info.AssocID)
}

// TestPeelOffRacesWithClose is the one lifecycle operation that had no
// concurrency coverage.
//
// Close swaps the descriptor to -1 and closes it, while PeelOff reads the
// descriptor and then makes a syscall with it. Between those two points the
// number can be closed and handed to something else, so the invariants that
// matter are not about which of the two wins: either outcome is legitimate.
// What must hold is that PeelOff never reports success while handing back a
// descriptor it does not own, and that neither ordering leaks one.
//
// The descriptor check is the same signature the original ABI defect had — a
// peeled fd of 0, 1 or 2 means the reply was read from the wrong offset, and
// under this race it would also mean a standard stream had been adopted.
func TestPeelOffRacesWithClose(t *testing.T) {
	before := openFds(t)

	for round := 0; round < 30; round++ {
		server, client, assocID := oneToManyPair(t)

		var wg sync.WaitGroup
		wg.Add(2)

		peeled := make(chan *SCTPConn, 4)
		go func() {
			defer wg.Done()
			defer close(peeled)
			for i := 0; i < 4; i++ {
				p, err := server.PeelOff(assocID)
				if err != nil {
					continue
				}
				if p == nil {
					t.Error("PeelOff returned a nil connection and a nil error")
					return
				}
				if fd := p.fd(); fd <= 2 {
					t.Errorf("PeelOff returned descriptor %d while the parent "+
						"was closing; anything at or below 2 is a standard "+
						"stream", fd)
				}
				peeled <- p
			}
		}()
		go func() {
			defer wg.Done()
			// Vary where the close lands relative to the peel, so the window
			// between reading the descriptor and using it is hit sometimes
			// rather than never.
			time.Sleep(time.Duration(round%7) * 200 * time.Microsecond)
			// A short grace period rather than Close's default three seconds.
			// The racy part is the descriptor swap, which is identical either
			// way; the timeout only governs how long the teardown waits for a
			// peer that is not going to answer, and thirty rounds of that is
			// seventy-five seconds of the suite spent waiting.
			_ = server.CloseWithTimeout(50 * time.Millisecond)
		}()

		wg.Wait()
		for p := range peeled {
			// A peeled descriptor is the caller's to close, and closing it must
			// not be affected by the parent having gone away underneath.
			// A short budget on purpose: Close of a peeled connection always
			// runs its grace period out, because shutdown(2) does nothing on
			// these sockets. See PeelOff. Thirty rounds at the default would
			// be ninety seconds of the suite spent waiting for that.
			if err := p.CloseWithTimeout(20 * time.Millisecond); err != nil &&
				!errors.Is(err, syscall.EBADF) {
				t.Errorf("closing a peeled connection gave %v", err)
			}
		}
		_ = server.CloseWithTimeout(50 * time.Millisecond)
		_ = client.CloseWithTimeout(50 * time.Millisecond)
	}

	// Every descriptor opened above is closed above, so the count must come
	// back. A peel that succeeded and was then dropped on the floor by an error
	// path would show up here and nowhere else.
	if after := openFds(t); after > before+2 {
		t.Errorf("descriptors grew from %d to %d over 30 rounds of racing "+
			"PeelOff against Close", before, after)
	}
}

// TestClosingAPeeledConnectionShutsDownGracefully covers the one socket style
// where shutdown(2) does nothing.
//
// sctp_do_peeloff builds the new socket with SCTP_SOCKET_UDP_HIGH_BANDWIDTH and
// sctp_shutdown begins "if (!sctp_style(sk, TCP)) return", so the shutdown
// closeSctpSocket issues reports success and emits nothing. Before
// shutdownViaEOF was added, SCTP_STATUS went on reporting SCTP_ESTABLISHED, the
// wait ran its whole budget out and the close fell back to an abort: 3.005s and
// a single ABORT on the wire where an ordinary close took 21.7us and completed
// the handshake.
//
// The peer is what decides this. A fast close proves nothing on its own — an
// abort is fast too — so the assertion is that the other end sees the end of the
// stream rather than a connection reset.
func TestClosingAPeeledConnectionShutsDownGracefully(t *testing.T) {
	server, client, assocID := oneToManyPair(t)
	defer func() {
		_ = server.CloseWithTimeout(20 * time.Millisecond)
		_ = client.CloseWithTimeout(20 * time.Millisecond)
	}()

	peeled, err := server.PeelOff(assocID)
	if err != nil {
		t.Skipf("PeelOff: %v", err)
	}

	// Long enough that running it out is unambiguous, short enough not to cost
	// the suite anything when the graceful path works.
	const grace = 2 * time.Second

	start := time.Now()
	if err := peeled.CloseWithTimeout(grace); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}
	took := time.Since(start)
	t.Logf("closing the peeled connection took %v against a %v grace period",
		took, grace)

	if took >= grace {
		t.Errorf("the close ran its %v grace period out (%v), which is what it "+
			"did before shutdownViaEOF existed: shutdown(2) does nothing on a "+
			"peeled socket, so nothing reports the handshake finishing and the "+
			"close falls back to an abort", grace, took)
	}

	// The half a timing check cannot cover. An abort reaches the peer as
	// ECONNRESET; a completed shutdown reaches it as the end of the stream.
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	for {
		n, rerr := client.Read(buf)
		if rerr == nil {
			// Notifications and any straggling data; keep reading for the end.
			_ = n
			continue
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if errors.Is(rerr, syscall.ECONNRESET) {
			t.Fatalf("the peer's read gave ECONNRESET, so the association was "+
				"aborted rather than shut down; the close returned in %v, which "+
				"means it aborted promptly rather than gracefully", took)
		}
		t.Fatalf("the peer's read gave %v, want the end of the stream", rerr)
	}
}
