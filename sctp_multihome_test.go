//go:build linux && !386
// +build linux,!386

package sctp

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"testing"
	"time"
)

// Multi-homed associations, and multi-homing combined with many peers.
//
// SCTP's defining feature over TCP is that one association spans several
// addresses on each side (RFC 9260 §6.4), and this package exposes it through
// SCTPAddr.IPAddrs, SCTPBind and the SCTP_GET_LOCAL_ADDRS / SCTP_GET_PEER_ADDRS
// readbacks. None of that had a test against a live kernel: the existing
// coverage parses address strings and decodes a kernel reply buffer built by
// hand, which proves the encoding but never that an association actually forms
// across several addresses or that the peer learns them.
//
// These need extra loopback addresses. testdata/run-tests.sh adds 127.0.0.2;
// the rest are added here if the test has the privilege, and the tests skip
// rather than pass vacuously when they are absent — a single-address run would
// exercise none of this.

// multihomeAddrs are the loopback addresses these tests bind. 127.0.0.1 is
// always present; the others are added by the harness or by addLoopbackAliases.
var multihomeAddrs = []string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"}

// availableLoopbacks reports which of multihomeAddrs the host actually has.
//
// It probes by binding rather than by parsing `ip addr`, because what matters
// is whether a socket can use the address, and because the test binary may not
// have the tools or the privilege to inspect the interface.
func availableLoopbacks(t *testing.T) []string {
	t.Helper()
	var got []string
	for _, s := range multihomeAddrs {
		addr := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP(s)}}, Port: 0}
		ln, err := ListenSCTP("sctp", addr)
		if err != nil {
			continue
		}
		_ = ln.Close()
		got = append(got, s)
	}
	return got
}

// sctpAddr builds an SCTPAddr over the given dotted-quad strings.
func sctpAddr(ips []string, port int) *SCTPAddr {
	a := &SCTPAddr{Port: port}
	for _, s := range ips {
		a.IPAddrs = append(a.IPAddrs, net.IPAddr{IP: net.ParseIP(s)})
	}
	return a
}

// ipStrings returns an SCTPAddr's addresses as sorted strings, so two address
// sets can be compared without depending on the order the kernel reports them.
func ipStrings(a *SCTPAddr) []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.IPAddrs))
	for _, ip := range a.IPAddrs {
		out = append(out, ip.IP.String())
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// requireLoopbacks skips unless at least n loopback addresses are usable.
func requireLoopbacks(t *testing.T, n int) []string {
	t.Helper()
	got := availableLoopbacks(t)
	if len(got) < n {
		t.Skipf("only %d loopback addresses usable (%v); this test needs %d. "+
			"Add them with: ip addr add 127.0.0.N/8 dev lo", len(got), got, n)
	}
	return got
}

// TestMultihomedAssociationExchangesAddresses is the base case the package had
// no live coverage for: an association whose two ends each bind several
// addresses, with both sides learning the other's full set.
//
// The address exchange happens in the INIT/INIT-ACK handshake, so a bug in
// ToRawSockAddrBuf or in SCTPBind shows up as a peer that knows fewer addresses
// than were bound — while the association still works over the primary path and
// every data-only test still passes.
func TestMultihomedAssociationExchangesAddresses(t *testing.T) {
	avail := requireLoopbacks(t, 3)

	serverIPs := avail[:2]
	clientIPs := avail[2:]
	if len(clientIPs) > 2 {
		clientIPs = clientIPs[:2]
	}

	ln, err := ListenSCTP("sctp", sctpAddr(serverIPs, 0))
	if err != nil {
		t.Fatalf("multihomed listen on %v: %v", serverIPs, err)
	}
	defer func() { _ = ln.Close() }()

	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener has no address")
	}
	// The listener must report every address it bound. Reporting one would mean
	// the bind silently dropped the rest.
	if got := ipStrings(la); !equalStrings(got, sortedCopy(serverIPs)) {
		t.Errorf("listener bound %v, want %v", got, sortedCopy(serverIPs))
	}

	accepted := make(chan *SCTPConn, 1)
	go func() {
		c, aerr := ln.AcceptSCTP()
		if aerr != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	client, err := DialSCTP("sctp", sctpAddr(clientIPs, 0), la)
	if err != nil {
		t.Fatalf("multihomed dial from %v to %v: %v", clientIPs, serverIPs, err)
	}
	defer func() { _ = client.Close() }()

	var server *SCTPConn
	select {
	case server, ok = <-accepted:
		if !ok {
			t.Fatal("accept failed")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("multihomed association was never accepted")
	}
	defer func() { _ = server.Close() }()

	// Each side must see its own addresses and all of the peer's. These four
	// readbacks are SCTP_GET_LOCAL_ADDRS and SCTP_GET_PEER_ADDRS on a real
	// association, which nothing else in the suite exercises.
	checks := []struct {
		what string
		got  func() (*SCTPAddr, error)
		want []string
	}{
		{"client local", func() (*SCTPAddr, error) { return client.SCTPLocalAddr(0) }, clientIPs},
		{"client peer", func() (*SCTPAddr, error) { return client.SCTPRemoteAddr(0) }, serverIPs},
		{"server local", func() (*SCTPAddr, error) { return server.SCTPLocalAddr(0) }, serverIPs},
		{"server peer", func() (*SCTPAddr, error) { return server.SCTPRemoteAddr(0) }, clientIPs},
	}
	for _, c := range checks {
		addr, err := c.got()
		if err != nil {
			t.Errorf("%s addresses: %v", c.what, err)
			continue
		}
		if got, want := ipStrings(addr), sortedCopy(c.want); !equalStrings(got, want) {
			t.Errorf("%s addresses = %v, want %v", c.what, got, want)
		}
	}

	// The association must also carry data, so a passing address check cannot
	// come from an association that never formed properly.
	const msg = "multihomed-payload"
	if err := writeAll(client, []byte(msg), nil); err != nil {
		t.Fatalf("write over multihomed association: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	buf := make([]byte, 256)
	n, _, err := server.SCTPRead(buf)
	if err != nil {
		t.Fatalf("read over multihomed association: %v", err)
	}
	if got := string(buf[:n]); got != msg {
		t.Errorf("got %q, want %q", got, msg)
	}
}

// TestMultihomedListenerServesManyPeers is the combination this branch's work
// is really about: one multi-homed listener, many peers, each peer also
// multi-homed, all associations live at once.
//
// It is the multi-client isolation assertion carried onto multi-homed
// associations. A peer that received another peer's payload, or that learned
// the wrong peer's address set, fails here — and neither the single-homed
// multi-client tests nor the single-association multi-homing test above would
// catch it, because each covers only one of the two dimensions.
func TestMultihomedListenerServesManyPeers(t *testing.T) {
	avail := requireLoopbacks(t, 3)

	serverIPs := avail[:2]
	clientIPs := avail[2:]

	ln, err := ListenSCTP("sctp", sctpAddr(serverIPs, 0))
	if err != nil {
		t.Fatalf("multihomed listen: %v", err)
	}
	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener has no address")
	}

	// Echo server: same shape as echoServer, but it also records the peer
	// address set each association reports, so attribution can be checked.
	type peerView struct {
		addrs []string
		err   error
	}
	var (
		mu    sync.Mutex
		views []peerView
	)
	var srvWG sync.WaitGroup
	srvWG.Add(1)
	go func() {
		defer srvWG.Done()
		for {
			c, aerr := ln.AcceptSCTP()
			if aerr != nil {
				return
			}
			if serr := c.SubscribeEvents(SCTP_EVENT_DATA_IO); serr != nil {
				_ = c.Close()
				continue
			}
			pa, perr := c.SCTPRemoteAddr(0)
			mu.Lock()
			views = append(views, peerView{ipStrings(pa), perr})
			mu.Unlock()

			srvWG.Add(1)
			go func(c *SCTPConn) {
				defer srvWG.Done()
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				for {
					n, info, rerr := c.SCTPRead(buf)
					if rerr != nil {
						return
					}
					var out *SndRcvInfo
					if info != nil {
						out = &SndRcvInfo{Stream: info.Stream, PPID: info.PPID}
					}
					if werr := writeAll(c, buf[:n], out); werr != nil {
						return
					}
				}
			}(c)
		}
	}()

	const peers = 12
	var wg sync.WaitGroup
	errs := make(chan error, peers)
	for i := 0; i < peers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Every client binds the same multi-homed local set; the kernel
			// gives each a distinct port, so the associations stay separate.
			c, derr := DialSCTP("sctp", sctpAddr(clientIPs, 0), la)
			if derr != nil {
				errs <- fmt.Errorf("peer %d dial: %w", id, derr)
				return
			}
			defer func() { _ = c.Close() }()
			if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				errs <- fmt.Errorf("peer %d deadline: %w", id, err)
				return
			}

			// This peer must see the server's whole address set, not just the
			// one it happened to connect over.
			pa, perr := c.SCTPRemoteAddr(0)
			if perr != nil {
				errs <- fmt.Errorf("peer %d remote addrs: %w", id, perr)
				return
			}
			if got, want := ipStrings(pa), sortedCopy(serverIPs); !equalStrings(got, want) {
				errs <- fmt.Errorf("peer %d sees server addresses %v, want %v", id, got, want)
				return
			}

			buf := make([]byte, 4096)
			for j := 0; j < 10; j++ {
				want := fmt.Sprintf("mh-peer-%d-msg-%d", id, j)
				if err := writeAll(c, []byte(want), nil); err != nil {
					errs <- fmt.Errorf("peer %d write %d: %w", id, j, err)
					return
				}
				n, _, rerr := c.SCTPRead(buf)
				if rerr != nil {
					errs <- fmt.Errorf("peer %d read %d: %w", id, j, rerr)
					return
				}
				if got := string(buf[:n]); got != want {
					errs <- fmt.Errorf("peer %d msg %d: got %q, want %q", id, j, got, want)
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
	srvWG.Wait()

	// Every accepted association must have reported the client's full address
	// set. One short list means the server learned only the path it was
	// contacted over.
	mu.Lock()
	defer mu.Unlock()
	if len(views) != peers {
		t.Errorf("server recorded %d peer views, want %d", len(views), peers)
	}
	want := sortedCopy(clientIPs)
	for i, v := range views {
		if v.err != nil {
			t.Errorf("server view %d: %v", i, v.err)
			continue
		}
		if !equalStrings(v.addrs, want) {
			t.Errorf("server view %d sees peer addresses %v, want %v", i, v.addrs, want)
		}
	}
}

// TestMultihomedBindRejectsAnUnusableAddress covers the failure direction.
//
// Binding a set containing an address the host does not own must fail rather
// than silently binding the subset that works. Without this, a caller
// misconfiguring one address of several would get an association that looks
// healthy and is missing a path — the kind of fault that only appears when the
// primary path goes down.
func TestMultihomedBindRejectsAnUnusableAddress(t *testing.T) {
	avail := requireLoopbacks(t, 1)

	// TEST-NET-1 (RFC 5737) is not configured on any host.
	addrs := append(sortedCopy(avail[:1]), "192.0.2.1")
	ln, err := ListenSCTP("sctp", sctpAddr(addrs, 0))
	if err == nil {
		bound := ipStrings(ln.Addr().(*SCTPAddr))
		_ = ln.Close()
		t.Fatalf("listen on %v succeeded and bound %v; an address the host does "+
			"not own must not be silently dropped", addrs, bound)
	}
	t.Logf("listen on %v correctly failed: %v", addrs, err)
}

// sortedCopy returns a sorted copy, leaving the caller's slice alone.
func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
