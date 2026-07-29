//go:build linux && !386
// +build linux,!386

package sctp

import (
	"net"
	"syscall"
	"testing"
	"unsafe"
)

// The kernel returns SCTP_GET_LOCAL_ADDRS and SCTP_GET_PEER_ADDRS as a packed
// array of sockaddrs, each sized by its own family: 16 bytes for AF_INET and
// 28 for AF_INET6.
//
// These tests build the reply by hand, including mixed-family arrays. Linux
// does not currently produce one: an AF_INET socket is answered with all
// AF_INET entries and an AF_INET6 socket with all AF_INET6 entries, v4-mapping
// any IPv4 addresses, which was confirmed against the kernel with a socket
// bound to both ::1 and 127.0.0.1 via sctp_bindx. The mixed cases below are
// therefore not reproductions of a live Linux defect; they pin the decoder to
// the layout the interface describes rather than to the uniform replies one
// kernel happens to send, so a fixed-stride walk cannot be reintroduced
// unnoticed.
//
// TestKernelAddrsRoundTrip covers what the running kernel actually returns.

// packSockaddrs lays the given entries out back to back in a single
// allocation, followed by trailing slack.
//
// The slack is what makes an over-read observable: a decoder that walks past
// the last entry lands in defined memory and produces a wrong address, which
// the test can assert on, instead of faulting on an unmapped page.
//
// One allocation matters. Building the buffer with successive appends lets the
// slice grow and move, after which a pointer taken from the first byte no
// longer covers the later bytes, and -race rejects it with "converted pointer
// straddles multiple allocations" before any decoding happens.
func packSockaddrs(entries ...[]byte) []byte {
	total := 0
	for _, e := range entries {
		total += len(e)
	}
	const slack = 128
	buf := make([]byte, total+slack)
	at := 0
	for _, e := range entries {
		copy(buf[at:], e)
		at += len(e)
	}
	return buf
}

func v4Sockaddr(ip net.IP, port uint16) []byte {
	var sa syscall.RawSockaddrInet4
	sa.Family = syscall.AF_INET
	// Port is in network byte order on the wire and in the kernel's reply.
	sa.Port = htons(port)
	copy(sa.Addr[:], ip.To4())
	b := make([]byte, unsafe.Sizeof(sa))
	copy(b, (*(*[16]byte)(unsafe.Pointer(&sa)))[:])
	return b
}

func v6Sockaddr(ip net.IP, port uint16, scope uint32) []byte {
	var sa syscall.RawSockaddrInet6
	sa.Family = syscall.AF_INET6
	sa.Port = htons(port)
	sa.Scope_id = scope
	copy(sa.Addr[:], ip.To16())
	b := make([]byte, unsafe.Sizeof(sa))
	copy(b, (*(*[28]byte)(unsafe.Pointer(&sa)))[:])
	return b
}

// TestResolveFromRawAddrMixedFamilies decodes a reply whose entries are not
// all the same family.
//
// Walking with the first entry's stride reads this at 16 bytes per entry, so
// the second read starts 12 bytes early, inside the IPv6 entry rather than at
// it, and the address that comes back is assembled from the wrong bytes. It
// decodes as 0.0.0.0 with no error, which is the failure this pins down: a
// wrong address is returned to the caller as though it were real.
//
// See the file comment: Linux does not send a reply in this shape today.
func TestResolveFromRawAddrMixedFamilies(t *testing.T) {
	v4 := net.IPv4(192, 0, 2, 10)
	v6 := net.ParseIP("2001:db8::1")

	buf := packSockaddrs(v4Sockaddr(v4, 3868), v6Sockaddr(v6, 3868, 0))

	addr, err := resolveFromRawAddr(unsafe.Pointer(&buf[0]), 2)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(addr.IPAddrs) != 2 {
		t.Fatalf("got %d addresses, want 2", len(addr.IPAddrs))
	}

	if !addr.IPAddrs[0].IP.Equal(v4) {
		t.Errorf("first address: got %v, want %v", addr.IPAddrs[0].IP, v4)
	}
	if !addr.IPAddrs[1].IP.Equal(v6) {
		t.Errorf("second address: got %v, want %v (the array was walked with "+
			"the first entry's stride, so this was read from the wrong offset)",
			addr.IPAddrs[1].IP, v6)
	}
}

// TestResolveFromRawAddrV6First is the mirror case. An IPv6 entry first makes
// the stride 28 bytes, so the IPv4 entry that follows is read from 12 bytes
// past where it starts, running off the end of the real data.
func TestResolveFromRawAddrV6First(t *testing.T) {
	v6 := net.ParseIP("2001:db8::2")
	v4 := net.IPv4(198, 51, 100, 7)

	buf := packSockaddrs(v6Sockaddr(v6, 3868, 0), v4Sockaddr(v4, 3868))

	addr, err := resolveFromRawAddr(unsafe.Pointer(&buf[0]), 2)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(addr.IPAddrs) != 2 {
		t.Fatalf("got %d addresses, want 2", len(addr.IPAddrs))
	}
	if !addr.IPAddrs[0].IP.Equal(v6) {
		t.Errorf("first address: got %v, want %v", addr.IPAddrs[0].IP, v6)
	}
	if !addr.IPAddrs[1].IP.Equal(v4) {
		t.Errorf("second address: got %v, want %v", addr.IPAddrs[1].IP, v4)
	}
}

// TestResolveFromRawAddrUnknownFamilyIsRejected checks that a family the
// kernel should never send is reported rather than walked. Without the check
// the stride would be undefined.
func TestResolveFromRawAddrUnknownFamilyIsRejected(t *testing.T) {
	buf := make([]byte, 64)
	// AF_UNIX is a valid family that is not a valid SCTP peer address.
	buf[0] = byte(syscall.AF_UNIX)

	if _, err := resolveFromRawAddr(unsafe.Pointer(&buf[0]), 1); err == nil {
		t.Error("an unrecognised address family was accepted")
	}
}

// TestResolveFromRawAddrZeroCount checks the empty reply. The kernel reports
// no addresses for an association that has none, and the walk must not read
// the buffer at all in that case.
func TestResolveFromRawAddrZeroCount(t *testing.T) {
	buf := make([]byte, 64)
	buf[0] = byte(syscall.AF_INET)

	addr, err := resolveFromRawAddr(unsafe.Pointer(&buf[0]), 0)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(addr.IPAddrs) != 0 {
		t.Errorf("got %d addresses, want 0", len(addr.IPAddrs))
	}
}

// TestResolveFromRawAddrRespectsBuffer checks that the count reported by the
// kernel cannot walk the decoder past the buffer that was handed to it.
//
// The address count and the reply buffer are separate fields of the same
// getsockopt parameter, so a count that does not match the data is a kernel
// or a memory-corruption bug rather than something a peer can send. It still
// must not be read as permission to walk off the end: an out-of-range count
// would otherwise assemble addresses from whatever follows in memory and
// return them to the caller as though they were real.
func TestResolveFromRawAddrRespectsBuffer(t *testing.T) {
	// Two IPv4 addresses fit; the buffer is bounded to exactly that.
	a := v4Sockaddr(net.IPv4(192, 0, 2, 1), 3868)
	b := v4Sockaddr(net.IPv4(192, 0, 2, 2), 3868)
	// The bound covers the two real entries; packSockaddrs leaves readable
	// slack past it, so an unbounded walk reads defined bytes and the test
	// reports the missing bound rather than crashing.
	limit := uintptr(len(a) + len(b))
	buf := packSockaddrs(a, b)

	// Claim more addresses than the bounded region holds. Each extra entry
	// starts past the end, so this exercises the check made before the family
	// is read.
	if _, err := resolveFromRawAddrBuf(unsafe.Pointer(&buf[0]), 6, limit); err == nil {
		t.Error("a count larger than the buffer was walked without error")
	}

	// An entry that begins inside the buffer but extends past its end is the
	// separate case: the family is readable, so only a check against the size
	// of the address that family implies can reject it. Bounding one byte
	// short of the second entry's end puts it exactly there.
	if _, err := resolveFromRawAddrBuf(unsafe.Pointer(&buf[0]), 2, limit-1); err == nil {
		t.Error("an address extending past the end of the buffer was decoded " +
			"without error")
	}

	// A v6 entry that starts in bounds and runs over must be rejected too; its
	// size differs, so the v4 check alone would not cover it.
	v6 := packSockaddrs(v6Sockaddr(net.ParseIP("2001:db8::1"), 3868, 0))
	v6Limit := uintptr(len(v6Sockaddr(net.ParseIP("2001:db8::1"), 3868, 0))) - 1
	if _, err := resolveFromRawAddrBuf(unsafe.Pointer(&v6[0]), 1, v6Limit); err == nil {
		t.Error("an IPv6 address extending past the end of the buffer was " +
			"decoded without error")
	}

	// An entry starting exactly at the limit has nothing readable at all, not
	// even the two family bytes. The size checks cannot catch this: they run
	// after the family has been read, which is already the over-read. Bounding
	// to exactly one entry and asking for two lands the second entry here.
	oneEntry := uintptr(len(a))
	if _, err := resolveFromRawAddrBuf(unsafe.Pointer(&buf[0]), 2, oneEntry); err == nil {
		t.Error("an address starting at the end of the buffer was decoded " +
			"without error")
	}

	// The honest count still works.
	addr, err := resolveFromRawAddrBuf(unsafe.Pointer(&buf[0]), 2, limit)
	if err != nil {
		t.Fatalf("resolve within bounds: %v", err)
	}
	if len(addr.IPAddrs) != 2 {
		t.Fatalf("got %d addresses, want 2", len(addr.IPAddrs))
	}
}

// TestResolveFromRawAddrNegativeCount checks a negative count is rejected
// rather than used. It reaches the decoder as an int converted from the
// kernel's uint32, so a reply claiming more than 2^31 addresses arrives here
// negative, and make() would panic on it.
func TestResolveFromRawAddrNegativeCount(t *testing.T) {
	buf := packSockaddrs(v4Sockaddr(net.IPv4(192, 0, 2, 1), 3868))
	if _, err := resolveFromRawAddr(unsafe.Pointer(&buf[0]), -1); err == nil {
		t.Error("a negative address count was accepted")
	}
}

// TestResolveFromRawAddrPortFromLaterEntriesIgnored checks the port comes from
// the first address only.
//
// Every address in an association shares one port, so a well-formed reply
// carries the same value throughout and reading the last would be
// indistinguishable from reading the first. A malformed or truncated reply is
// where they diverge, and taking the last would then let trailing bytes
// decide the port of an address the caller is about to connect to.
func TestResolveFromRawAddrPortFromLaterEntriesIgnored(t *testing.T) {
	first := v4Sockaddr(net.IPv4(192, 0, 2, 1), 3868)
	second := v4Sockaddr(net.IPv4(192, 0, 2, 2), 9999)
	buf := packSockaddrs(first, second)

	addr, err := resolveFromRawAddr(unsafe.Pointer(&buf[0]), 2)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if addr.Port != 3868 {
		t.Errorf("port = %d, want 3868 from the first entry (a later entry "+
			"carrying a different port must not override it)", addr.Port)
	}
}

// TestResolveFromRawAddrPortFromFirstEntry checks the port is taken from the
// reply rather than left at zero, for both families. Every address in an
// association shares the port, so the first entry carries it.
func TestResolveFromRawAddrPortFromFirstEntry(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		buf := packSockaddrs(v4Sockaddr(net.IPv4(192, 0, 2, 1), 3868))
		addr, err := resolveFromRawAddr(unsafe.Pointer(&buf[0]), 1)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if addr.Port != 3868 {
			t.Errorf("port = %d, want 3868", addr.Port)
		}
	})
	t.Run("v6", func(t *testing.T) {
		buf := packSockaddrs(v6Sockaddr(net.ParseIP("2001:db8::1"), 2905, 0))
		addr, err := resolveFromRawAddr(unsafe.Pointer(&buf[0]), 1)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		// Read through RawSockaddrInet6 rather than an Inet4 cast. The two
		// structs happen to agree on the offset of Port, so a wrong cast is
		// invisible here; it is still the wrong type to read through.
		if addr.Port != 2905 {
			t.Errorf("port = %d, want 2905", addr.Port)
		}
	})
}

// TestResolveFromRawAddrDoesNotAliasBuffer checks the decoded addresses own
// their bytes. They previously pointed into the caller's buffer, which for
// SCTPGetPrimaryPeerAddr is a stack local that goes out of scope as soon as
// the call returns.
func TestResolveFromRawAddrDoesNotAliasBuffer(t *testing.T) {
	want := net.IPv4(203, 0, 113, 5)
	buf := packSockaddrs(v4Sockaddr(want, 3868))

	addr, err := resolveFromRawAddr(unsafe.Pointer(&buf[0]), 1)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Overwrite the source. An aliased result changes with it.
	for i := range buf {
		buf[i] = 0xff
	}
	if !addr.IPAddrs[0].IP.Equal(want) {
		t.Errorf("address changed to %v after its source buffer was "+
			"overwritten: the result aliases memory it does not own",
			addr.IPAddrs[0].IP)
	}
}

// FuzzResolveFromRawAddr drives the decoder with arbitrary bytes in place of
// the kernel's reply.
//
// The buffer is the kernel's, not a peer's, so this is not a remote attack
// surface. It is fuzzed because the decoder reads it through unsafe pointer
// arithmetic driven by a length the kernel supplies: any disagreement between
// that length and the data, from a kernel bug, a truncated reply, or memory
// corruption, becomes an out-of-bounds read rather than an error.
//
// What this covers is panics and malformed results: no input may crash the
// decoder or produce an address of a length net.IP cannot represent.
//
// What it does not cover is the bounds themselves. Removing the buffer checks
// and fuzzing for a minute survives 4.3M executions, because a read that runs
// past the intended limit still lands inside the same Go allocation, which the
// runtime has no reason to fault on and which leaves these invariants intact.
// The bounds are covered by TestResolveFromRawAddrRespectsBuffer, whose
// assertions were each confirmed by removing the check they guard.
func FuzzResolveFromRawAddr(f *testing.F) {
	// Real shapes first: one v4, one v6, and the mixed pair that was decoded
	// incorrectly before the per-entry walk.
	f.Add(v4Sockaddr(net.IPv4(192, 0, 2, 1), 3868), 1)
	f.Add(v6Sockaddr(net.ParseIP("2001:db8::1"), 3868, 0), 1)
	f.Add(append(v4Sockaddr(net.IPv4(192, 0, 2, 1), 3868),
		v6Sockaddr(net.ParseIP("2001:db8::1"), 3868, 0)...), 2)
	f.Add(append(v6Sockaddr(net.ParseIP("2001:db8::1"), 3868, 0),
		v4Sockaddr(net.IPv4(192, 0, 2, 1), 3868)...), 2)
	f.Add([]byte{}, 0)
	f.Add([]byte{0, 0}, 1)

	f.Fuzz(func(t *testing.T, data []byte, n int) {
		if len(data) == 0 {
			data = make([]byte, 1)
		}
		// Keep the count in a range that cannot exhaust memory on its own; the
		// point is the walk, not make() with a huge argument.
		if n < -4 || n > 64 {
			return
		}

		addr, err := resolveFromRawAddrBuf(unsafe.Pointer(&data[0]), n,
			uintptr(len(data)))
		if err != nil {
			return
		}
		// A successful decode must not claim more addresses than the buffer
		// could hold, and every address must be a length net.IP understands.
		if len(addr.IPAddrs) > n {
			t.Fatalf("decoded %d addresses from a reply claiming %d",
				len(addr.IPAddrs), n)
		}
		for i, ip := range addr.IPAddrs {
			switch len(ip.IP) {
			case net.IPv4len, net.IPv6len:
			default:
				t.Fatalf("address %d has length %d, want 4 or 16", i, len(ip.IP))
			}
		}
	})
}

// TestKernelAddrsRoundTrip decodes what the running kernel actually returns
// for a multi-homed association, rather than a reply built by hand.
//
// The hand-built cases above pin the decoder to the documented layout; this
// one checks that layout is what arrives. It needs a second loopback address,
// so it skips where one is not configured rather than failing.
func TestKernelAddrsRoundTrip(t *testing.T) {
	const second = "127.0.0.2"
	if !hasLocalAddr(t, second) {
		t.Skipf("%s is not configured on this host", second)
	}

	laddr := &SCTPAddr{IPAddrs: []net.IPAddr{
		{IP: net.ParseIP("127.0.0.1")},
		{IP: net.ParseIP(second)},
	}}
	ln, err := ListenSCTP("sctp", laddr)
	if err != nil {
		t.Fatalf("listen multi-homed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	srvAddr, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener has no address")
	}
	if len(srvAddr.IPAddrs) != 2 {
		t.Fatalf("listener reports %d addresses, want the 2 that were bound",
			len(srvAddr.IPAddrs))
	}

	accepted := make(chan *SCTPConn, 1)
	go func() {
		c, aerr := ln.AcceptSCTP()
		if aerr != nil {
			t.Errorf("accept: %v", aerr)
			close(accepted)
			return
		}
		accepted <- c
	}()

	conn, err := DialSCTP("sctp", nil, srvAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	srvConn, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer func() { _ = srvConn.Close() }()

	remote, err := conn.SCTPRemoteAddr(0)
	if err != nil {
		t.Fatalf("SCTPRemoteAddr: %v", err)
	}
	if len(remote.IPAddrs) != 2 {
		t.Errorf("remote reports %d addresses, want 2", len(remote.IPAddrs))
	}
	if remote.Port != srvAddr.Port {
		t.Errorf("remote port %d, want %d", remote.Port, srvAddr.Port)
	}
	for i, a := range remote.IPAddrs {
		// A wrong offset yields zeros rather than an error, so an unspecified
		// address here is the symptom to catch.
		if a.IP == nil || a.IP.IsUnspecified() {
			t.Errorf("remote address %d decoded as %v", i, a.IP)
		}
	}

	prim, err := srvConn.SCTPGetPrimaryPeerAddr()
	if err != nil {
		t.Fatalf("SCTPGetPrimaryPeerAddr: %v", err)
	}
	if len(prim.IPAddrs) != 1 || prim.IPAddrs[0].IP.IsUnspecified() {
		t.Errorf("primary peer decoded as %v", prim.IPAddrs)
	}
}

func hasLocalAddr(t *testing.T, want string) bool {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	target := net.ParseIP(want)
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(target) {
			return true
		}
	}
	return false
}
