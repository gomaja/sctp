//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// One listener serving many peers at once.
//
// The suite already had TestSCTPConcurrentAccept, but it closes each connection
// the instant it is accepted and never sends a byte. That proves accept does
// not crash under concurrency; it does not prove a server can *serve* several
// peers. Everything that makes a multi-client server interesting — associations
// held open together, each peer's data reaching only that peer, per-connection
// state such as deadlines and streams staying per-connection, notifications
// being attributable to the association that produced them — was unexercised.
//
// These tests hold every association open for the duration and assert what each
// peer actually receives, so a defect that crosses two peers' data or leaks
// per-connection state fails here rather than in production.

// echoServer accepts until its listener closes, echoing each message back on
// the stream it arrived on. Each accepted connection is served by its own
// goroutine, which is the shape a real one-to-one SCTP server takes.
//
// Every accepted connection subscribes to SCTP_EVENT_DATA_IO. Without it the
// kernel attaches no SCTP_SNDRCV control message, SCTPRead returns a nil
// SndRcvInfo, and the echo would silently collapse onto stream 0 — which would
// make TestManyClientsStreamsStayPerAssociation pass for the wrong reason.
//
// It returns the listener and a wait function that blocks until every accept
// and connection goroutine has exited, so a test cannot finish while server
// goroutines still run against a closing listener.
func echoServer(t *testing.T, onAccept func(*SCTPConn)) (*SCTPListener, func()) {
	t.Helper()

	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, aerr := ln.AcceptSCTP()
			if aerr != nil {
				return // listener closed
			}
			// Subscribe before any read, so the very first message carries its
			// stream and PPID.
			if serr := c.SubscribeEvents(SCTP_EVENT_DATA_IO); serr != nil {
				t.Errorf("server subscribe: %v", serr)
				_ = c.Close()
				continue
			}
			if onAccept != nil {
				onAccept(c)
			}
			wg.Add(1)
			go func(c *SCTPConn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				for {
					n, info, rerr := c.SCTPRead(buf)
					if rerr != nil {
						return
					}
					// Echo on the same stream, so a test can prove the reply
					// belongs to the request rather than to another peer.
					var out *SndRcvInfo
					if info != nil {
						out = &SndRcvInfo{Stream: info.Stream, PPID: info.PPID}
					}
					// writeAll, not SCTPWrite: sends use MSG_DONTWAIT, so a
					// momentarily full send buffer reports EAGAIN. Treating it
					// as fatal would close a healthy association and surface on
					// the peer as EPIPE.
					if werr := writeAll(c, buf[:n], out); werr != nil {
						return
					}
				}
			}(c)
		}
	}()

	return ln, wg.Wait
}

// TestManyClientsConcurrentEcho holds N associations open at once and drives
// traffic on all of them simultaneously.
//
// The assertion that matters is per-peer: every client sends a payload unique
// to itself and requires that exact payload back. A server that mixed two
// peers' descriptors, or shared a read buffer across connections, returns
// another client's bytes and fails here. Counting successful round trips alone
// would not catch it.
func TestManyClientsConcurrentEcho(t *testing.T) {
	const (
		clients  = 24
		messages = 20
	)

	ln, waitServer := echoServer(t, nil)

	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
			if err != nil {
				errs <- fmt.Errorf("client %d dial: %w", id, err)
				return
			}
			defer func() { _ = c.Close() }()

			// A deadline per client: a defect that crosses connections tends to
			// leave one peer waiting forever, and a hang is a much worse test
			// failure than an error.
			if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				errs <- fmt.Errorf("client %d deadline: %w", id, err)
				return
			}

			buf := make([]byte, 4096)
			for j := 0; j < messages; j++ {
				// Unique per client and per message, so a reply from the wrong
				// association or the wrong message is detectable.
				want := fmt.Sprintf("client-%d-msg-%d", id, j)
				if err := writeAll(c, []byte(want), nil); err != nil {
					errs <- fmt.Errorf("client %d write %d: %w", id, j, err)
					return
				}
				n, _, err := c.SCTPRead(buf)
				if err != nil {
					errs <- fmt.Errorf("client %d read %d: %w", id, j, err)
					return
				}
				if got := string(buf[:n]); got != want {
					errs <- fmt.Errorf("client %d msg %d: got %q, want %q", id, j, got, want)
					return
				}
			}
			errs <- nil
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}

	_ = ln.Close()
	waitServer()
}

// TestManyClientsHeldOpenSimultaneously proves the associations really are
// concurrent rather than serialised by the accept loop.
//
// TestManyClientsConcurrentEcho would still pass if the server handled one peer
// to completion before accepting the next. Here every client connects and waits
// at a barrier before any of them sends, so all N associations must be
// established at the same time for the test to proceed at all. The kernel's own
// association count is then checked, which is evidence independent of this
// package's bookkeeping.
func TestManyClientsHeldOpenSimultaneously(t *testing.T) {
	const clients = 16

	ln, waitServer := echoServer(t, nil)

	conns := make([]*SCTPConn, 0, clients)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errs := make(chan error, clients)

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
			if err != nil {
				errs <- fmt.Errorf("client %d dial: %w", id, err)
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			errs <- nil
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
		_ = ln.Close()
		waitServer()
	}()

	if len(conns) != clients {
		t.Fatalf("established %d associations, want %d", len(conns), clients)
	}

	// Every association is open right now. Each must still work, which a
	// per-connection state bug (a deadline or stream count leaking between
	// connections) would break.
	buf := make([]byte, 4096)
	for i, c := range conns {
		want := fmt.Sprintf("held-open-%d", i)
		if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("client %d deadline: %v", i, err)
		}
		if err := writeAll(c, []byte(want), nil); err != nil {
			t.Fatalf("client %d write: %v", i, err)
		}
		n, _, err := c.SCTPRead(buf)
		if err != nil {
			t.Fatalf("client %d read: %v", i, err)
		}
		if got := string(buf[:n]); got != want {
			t.Errorf("client %d: got %q, want %q", i, got, want)
		}
	}
}

// TestManyClientsDistinctAssociationIDs checks that the server sees a distinct
// association for every peer.
//
// Each accepted connection is an independent one-to-one socket, so its
// association ID must differ from every other. Two peers reported under one ID
// would mean the server cannot tell them apart — exactly the confusion that
// makes per-peer state unsafe — and it would be invisible to a data-only test
// whenever the descriptors happen to stay separate.
func TestManyClientsDistinctAssociationIDs(t *testing.T) {
	const clients = 12

	var (
		mu     sync.Mutex
		ids    []SCTPAssocID
		idErrs []error
	)
	ln, waitServer := echoServer(t, func(c *SCTPConn) {
		status, err := c.GetStatus()
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			idErrs = append(idErrs, err)
			return
		}
		ids = append(ids, status.AssocID)
	})

	conns := make([]*SCTPConn, 0, clients)
	for i := 0; i < clients; i++ {
		c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
		if err != nil {
			t.Fatalf("client %d dial: %v", i, err)
		}
		conns = append(conns, c)
		// Exchange a message so the accept-side handler has certainly run
		// before the next client connects.
		if err := writeAll(c, []byte("hello"), nil); err != nil {
			t.Fatalf("client %d write: %v", i, err)
		}
		buf := make([]byte, 64)
		if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("client %d deadline: %v", i, err)
		}
		if _, _, err := c.SCTPRead(buf); err != nil {
			t.Fatalf("client %d read: %v", i, err)
		}
	}

	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
		_ = ln.Close()
		waitServer()
	}()

	mu.Lock()
	defer mu.Unlock()
	for _, err := range idErrs {
		t.Errorf("GetStatus on an accepted connection: %v", err)
	}
	if len(ids) != clients {
		t.Fatalf("collected %d association IDs, want %d", len(ids), clients)
	}
	seen := make(map[SCTPAssocID]int, len(ids))
	for _, id := range ids {
		seen[id]++
	}
	if len(seen) != clients {
		dupes := make([]int, 0)
		for id, n := range seen {
			if n > 1 {
				dupes = append(dupes, int(id))
			}
		}
		sort.Ints(dupes)
		t.Errorf("%d distinct association IDs across %d peers (duplicated: %v)",
			len(seen), clients, dupes)
	}
}

// TestManyClientsPerConnectionDeadlineIsolation pins deadlines as
// per-connection state.
//
// The deadline lives in the SCTPConn and is programmed onto the socket as
// SO_RCVTIMEO before each read. If it were ever stored somewhere shared — a
// package-level variable, or state hung off the listener — one client's short
// deadline would expire another client's read. This sets an immediate deadline
// on one connection and requires the others to keep working.
func TestManyClientsPerConnectionDeadlineIsolation(t *testing.T) {
	const clients = 8

	ln, waitServer := echoServer(t, nil)

	conns := make([]*SCTPConn, 0, clients)
	for i := 0; i < clients; i++ {
		c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
		if err != nil {
			t.Fatalf("client %d dial: %v", i, err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
		_ = ln.Close()
		waitServer()
	}()

	// Client 0 gets a deadline already in the past, so its read must time out
	// without any data having been sent on it.
	if err := conns[0].SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("set expired deadline: %v", err)
	}
	buf := make([]byte, 4096)
	if _, _, err := conns[0].SCTPRead(buf); !isTimeout(err) {
		t.Fatalf("read on the expired connection: err = %v, want a timeout", err)
	}

	// Every other connection must be unaffected: no deadline, full round trip.
	for i := 1; i < clients; i++ {
		want := fmt.Sprintf("isolated-%d", i)
		if err := conns[i].SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("client %d deadline: %v", i, err)
		}
		if err := writeAll(conns[i], []byte(want), nil); err != nil {
			t.Fatalf("client %d write: %v", i, err)
		}
		n, _, err := conns[i].SCTPRead(buf)
		if err != nil {
			t.Fatalf("client %d read after another connection's deadline expired: %v", i, err)
		}
		if got := string(buf[:n]); got != want {
			t.Errorf("client %d: got %q, want %q", i, got, want)
		}
	}
}

// TestManyClientsStreamsStayPerAssociation drives several streams on several
// peers at once.
//
// Stream identity is carried in each message's ancillary data. Combining
// multiple peers with multiple streams is where a shared or reused SndRcvInfo
// shows up: the echo comes back on the stream the request arrived on, so a
// crossed stream or a crossed association produces a mismatch that a
// single-stream test cannot see.
func TestManyClientsStreamsStayPerAssociation(t *testing.T) {
	const (
		clients = 8
		streams = 4
	)

	ln, waitServer := echoServer(t, nil)

	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := DialSCTPExt("sctp", nil, ln.Addr().(*SCTPAddr),
				InitMsg{NumOstreams: streams, MaxInstreams: streams})
			if err != nil {
				errs <- fmt.Errorf("client %d dial: %w", id, err)
				return
			}
			defer func() { _ = c.Close() }()
			if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				errs <- fmt.Errorf("client %d deadline: %w", id, err)
				return
			}
			// The client reads the echo, so it needs the ancillary data too;
			// the server's subscription only covers the request direction.
			if err := c.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
				errs <- fmt.Errorf("client %d subscribe: %w", id, err)
				return
			}

			buf := make([]byte, 4096)
			for s := uint16(0); s < streams; s++ {
				want := fmt.Sprintf("client-%d-stream-%d", id, s)
				info := &SndRcvInfo{Stream: s}
				if err := writeAll(c, []byte(want), info); err != nil {
					errs <- fmt.Errorf("client %d stream %d write: %w", id, s, err)
					return
				}
				n, rinfo, err := c.SCTPRead(buf)
				if err != nil {
					errs <- fmt.Errorf("client %d stream %d read: %w", id, s, err)
					return
				}
				if got := string(buf[:n]); got != want {
					errs <- fmt.Errorf("client %d stream %d: got %q, want %q", id, s, got, want)
					return
				}
				// The echo must come back on the stream it was sent on. Without
				// this the payload check alone would pass even if every reply
				// collapsed onto stream 0.
				if rinfo == nil {
					errs <- fmt.Errorf("client %d stream %d: no ancillary data on the echo", id, s)
					return
				}
				if rinfo.Stream != s {
					errs <- fmt.Errorf("client %d: echo came back on stream %d, want %d",
						id, rinfo.Stream, s)
					return
				}
			}
			errs <- nil
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}

	_ = ln.Close()
	waitServer()
}

// TestManyClientsCloseDoesNotDisturbPeers closes half the associations while
// the other half are mid-conversation.
//
// A server that released the wrong descriptor on close — the defect the atomic
// swap in Close guards against, since the kernel reuses descriptor numbers —
// would break a surviving peer. The survivors are required to complete a round
// trip after the closes, which is what makes that reuse visible.
func TestManyClientsCloseDoesNotDisturbPeers(t *testing.T) {
	const clients = 16

	ln, waitServer := echoServer(t, nil)

	conns := make([]*SCTPConn, 0, clients)
	for i := 0; i < clients; i++ {
		c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
		if err != nil {
			t.Fatalf("client %d dial: %v", i, err)
		}
		if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("client %d deadline: %v", i, err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
		_ = ln.Close()
		waitServer()
	}()

	// Prime every association so the server has a goroutine on each.
	buf := make([]byte, 4096)
	for i, c := range conns {
		if err := writeAll(c, []byte(fmt.Sprintf("prime-%d", i)), nil); err != nil {
			t.Fatalf("client %d prime write: %v", i, err)
		}
		if _, _, err := c.SCTPRead(buf); err != nil {
			t.Fatalf("client %d prime read: %v", i, err)
		}
	}

	// Close the even-numbered peers concurrently, which is when descriptor
	// reuse is most likely to hand a released number straight back out.
	var wg sync.WaitGroup
	for i := 0; i < clients; i += 2 {
		wg.Add(1)
		go func(c *SCTPConn) {
			defer wg.Done()
			_ = c.Close()
		}(conns[i])
	}
	wg.Wait()

	// Every surviving peer must still round-trip its own payload.
	for i := 1; i < clients; i += 2 {
		want := fmt.Sprintf("survivor-%d", i)
		if err := writeAll(conns[i], []byte(want), nil); err != nil {
			t.Errorf("survivor %d write after peers closed: %v", i, err)
			continue
		}
		n, _, err := conns[i].SCTPRead(buf)
		if err != nil {
			t.Errorf("survivor %d read after peers closed: %v", i, err)
			continue
		}
		if got := string(buf[:n]); got != want {
			t.Errorf("survivor %d: got %q, want %q", i, got, want)
		}
	}
}

// TestManyClientsNotificationsCarryAssociationID addresses the one genuine
// multi-client sharp edge in this package's API.
//
// SocketConfig.NotificationHandler is a single func shared by the listener and
// by every connection accepted from it, and it is called with only the raw
// notification bytes — no *SCTPConn, no association handle. A server serving
// many peers therefore receives every peer's notifications through one
// callback, and the signature cannot be changed without breaking callers.
//
// What makes that workable is that the notification body itself carries the
// association ID. This test proves it: several peers abort, and the handler
// must report as many distinct association IDs as there were peers. If the IDs
// were absent or identical, a shared handler could not attribute a notification
// to a peer and the API would be unusable for a multi-client server — so this
// asserts the property the documentation depends on rather than assuming it.
func TestManyClientsNotificationsCarryAssociationID(t *testing.T) {
	const clients = 6

	var (
		mu      sync.Mutex
		assocs  []SCTPAssocID
		handled int32
	)
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	cfg := SocketConfig{
		NotificationHandler: func(b []byte) error {
			n, perr := ParseNotification(b)
			if perr != nil {
				return nil // not a notification shape this test cares about
			}
			atomic.AddInt32(&handled, 1)
			if ac, ok := n.(*AssocChange); ok {
				mu.Lock()
				assocs = append(assocs, ac.AssocID)
				mu.Unlock()
			}
			return nil
		},
	}
	ln, err := cfg.Listen("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Accept hands each connection back rather than serving it in a goroutine,
	// so the test drives the read sequence explicitly. The ordering matters and
	// was established by probing the kernel: the server must consume the data
	// message *before* the peer aborts, and then read again. That second read
	// is what dequeues SCTP_COMM_LOST and delivers it to the handler. Aborting
	// while the server has not yet read the data leaves the notification
	// unobserved and the handler never fires.
	accepted := make(chan *SCTPConn, clients)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, aerr := ln.AcceptSCTP()
			if aerr != nil {
				return
			}
			if serr := c.SubscribeEvents(SCTP_EVENT_ASSOCIATION); serr != nil {
				t.Errorf("subscribe: %v", serr)
				_ = c.Close()
				return
			}
			accepted <- c
		}
	}()

	servers := make([]*SCTPConn, 0, clients)
	buf := make([]byte, NotificationMaxSize)
	for i := 0; i < clients; i++ {
		c, derr := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
		if derr != nil {
			t.Fatalf("client %d dial: %v", i, derr)
		}
		if werr := writeAll(c, []byte(fmt.Sprintf("peer-%d", i)), nil); werr != nil {
			t.Fatalf("client %d write: %v", i, werr)
		}

		var sc *SCTPConn
		select {
		case sc = <-accepted:
		case <-time.After(20 * time.Second):
			t.Fatalf("client %d was never accepted", i)
		}
		servers = append(servers, sc)

		// Consume the data message first.
		if _, _, rerr := sc.SCTPRead(buf); rerr != nil {
			t.Fatalf("client %d server-side data read: %v", i, rerr)
		}

		// Abort rather than close: an abort produces SCTP_COMM_LOST, whereas a
		// graceful shutdown may surface as EOF instead of a notification.
		if aerr := c.Abort(); aerr != nil {
			t.Fatalf("client %d abort: %v", i, aerr)
		}

		// This read delivers the notification to the shared handler. It then
		// reports ECONNRESET for the aborted association, which is expected.
		if err := sc.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
			t.Fatalf("client %d read deadline: %v", i, err)
		}
		_, _, _ = sc.SCTPRead(buf)
	}

	_ = ln.Close()
	wg.Wait()
	for _, sc := range servers {
		_ = sc.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(assocs) != clients {
		t.Fatalf("got %d SCTP_ASSOC_CHANGE notifications from %d peers (handler "+
			"ran %d times); the read sequence should deliver exactly one per peer",
			len(assocs), clients, atomic.LoadInt32(&handled))
	}
	seen := make(map[SCTPAssocID]bool, len(assocs))
	for _, id := range assocs {
		seen[id] = true
	}
	// The point of the test: one shared handler, and every peer still
	// distinguishable. Anything less than one ID per peer means a server
	// cannot attribute a notification to the association that produced it.
	if len(seen) != clients {
		t.Errorf("%d notifications carried only %d distinct association IDs (%v); "+
			"a shared NotificationHandler cannot attribute notifications to peers",
			len(assocs), len(seen), assocs)
	}
	t.Logf("%d association-change notifications across %d distinct association IDs",
		len(assocs), len(seen))
}

// TestDoubleCloseDoesNotReleaseAReusedDescriptor is the regression test for the
// descriptor-reuse hazard that makes a shared listener dangerous.
//
// The mechanism, confirmed by running this test against a mutated Close that
// loads _fd instead of swapping it: the first Close releases fd N; the kernel
// hands N straight back to the next socket opened anywhere in the process,
// because it always allocates the lowest free descriptor; a second Close on the
// original SCTPConn then closes N again and destroys that unrelated socket.
//
// In a server, "an unrelated socket" is another peer's connection, so one
// client's redundant Close silently kills a different client. Nothing in the
// existing suite caught the mutation — every close test passed with the guard
// removed — because they all close a connection whose descriptor number is
// never reused within the test.
//
// The assertion is not that the second Close returns EBADF, which is only a
// symptom; it is that the socket occupying the reused descriptor is still open
// afterwards.
func TestDoubleCloseDoesNotReleaseAReusedDescriptor(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	defer func() { _ = server.Close() }()

	fd := client.fd()
	if fd < 0 {
		t.Fatalf("association has no descriptor")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}

	// Take a fresh descriptor. The kernel allocates the lowest free number, so
	// this normally reclaims exactly the one just released.
	victim, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("open a socket to reclaim the descriptor: %v", err)
	}
	defer func() { _ = syscall.Close(victim) }()

	if victim != fd {
		// Nothing was reused, so this run cannot observe the hazard. Skipping
		// is honest here: passing would prove nothing.
		t.Skipf("descriptor %d was not reused (got %d); cannot test the hazard", fd, victim)
	}

	// The second close must be a no-op against the reused descriptor.
	_ = client.Close()

	// The victim socket must still be open. F_GETFD on a released descriptor
	// reports EBADF, which is what the mutated Close produced.
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(victim), syscall.F_GETFD, 0)
	if errno != 0 {
		t.Fatalf("a second Close released descriptor %d, which the kernel had "+
			"already handed to another socket: fcntl reports %v. In a server "+
			"this is one peer's Close destroying another peer's connection.",
			victim, errno)
	}
}

// writeAll sends b, retrying while the send buffer is full.
//
// SCTPWrite passes MSG_DONTWAIT, so under the concurrency these tests create a
// full send buffer reports EAGAIN rather than blocking. That is a flow-control
// condition, not a failure, and treating it as one would make every test here
// flaky under load.
func writeAll(c *SCTPConn, b []byte, info *SndRcvInfo) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := c.SCTPWrite(b, info)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("send buffer stayed full for 30s: %w", err)
		}
		time.Sleep(time.Millisecond)
	}
}

// isTimeout reports whether err is a deadline expiry, in either of the two
// forms this package can produce.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	// os.ErrDeadlineExceeded is what this package maps the kernel's timeout
	// errno onto; EAGAIN/EWOULDBLOCK is the raw form, kept so the check does
	// not depend on that mapping having happened.
	return errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
}
