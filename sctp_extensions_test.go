//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// Covers the options outside RFC 6458: PR-SCTP (RFC 7496), stream
// reconfiguration (RFC 6525), SCTP-PF thresholds (RFC 7829), AUTH (RFC 4895)
// and the Linux-only association statistics.
//
// Every shape and every semantic asserted here was measured against a live
// kernel with testdata/optprobe before the binding was written. That mattered:
// three of these options reject the plain int their RFC describes and require a
// struct sctp_assoc_value, and SCTP_RECONFIG_SUPPORTED changes meaning once an
// association exists. Neither fact is in the kernel headers or the RFCs.

// extConn builds an association, running preDial on the client descriptor
// before connect and preListen on the listener before bind. Several of these
// extensions are negotiated in the INIT handshake, so setting them after
// connect is too late and a test that did so would pass for the wrong reason.
//
// It returns the client and server ends.
func extConn(t *testing.T, preListen, preDial func(*SCTPConn) error) (*SCTPConn, *SCTPConn) {
	t.Helper()

	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// The listener's own descriptor has to be configured before bind, which
	// ListenSCTP does internally, so the hook goes through SocketConfig's
	// Control callback rather than running against a listening socket.
	cfg := SocketConfig{}
	if preListen != nil {
		cfg.Control = func(network, address string, c syscall.RawConn) error {
			var cerr error
			if err := c.Control(func(fd uintptr) {
				// A temporary SCTPConn over the raw descriptor: the hooks take
				// an *SCTPConn for convenience and none of them retain it.
				cerr = preListen(NewSCTPConn(int(fd), nil))
			}); err != nil {
				return err
			}
			return cerr
		}
	}
	ln, err := cfg.Listen("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan *SCTPConn, 1)
	go func() {
		c, aerr := ln.AcceptSCTP()
		if aerr != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener has no address")
	}

	dialCfg := SocketConfig{}
	if preDial != nil {
		dialCfg.Control = func(network, address string, c syscall.RawConn) error {
			var cerr error
			if err := c.Control(func(fd uintptr) {
				cerr = preDial(NewSCTPConn(int(fd), nil))
			}); err != nil {
				return err
			}
			return cerr
		}
	}
	conn, err := dialCfg.Dial("sctp", nil, la)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	srv, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = srv.Close() })
	return conn, srv
}

// TestDefaultSndInfoRoundTrip pins that SetDefaultSndInfo writes every field and
// GetDefaultSndInfo reads them back.
//
// This is the non-deprecated replacement for SetDefaultSentParam, so the point
// worth proving is not that a setter runs but that all four caller-visible
// fields survive. A struct-size mismatch would be silent for some fields and
// wrong for others, which is exactly what a whole-struct comparison catches and
// a single-field check would not.
func TestDefaultSndInfoRoundTrip(t *testing.T) {
	conn := sockoptConn(t)

	// Distinct values per field: if two fields were swapped in the Go struct,
	// equal values would hide it.
	want := &SndInfo{SID: 3, Flags: 0, PPID: 0xabcd, Context: 0x5eed}
	if err := conn.SetDefaultSndInfo(want); err != nil {
		t.Fatalf("SetDefaultSndInfo: %v", err)
	}

	got, err := conn.GetDefaultSndInfo()
	if err != nil {
		t.Fatalf("GetDefaultSndInfo: %v", err)
	}
	if got.SID != want.SID {
		t.Errorf("SID = %d, want %d", got.SID, want.SID)
	}
	if got.PPID != want.PPID {
		t.Errorf("PPID = %#x, want %#x", got.PPID, want.PPID)
	}
	if got.Context != want.Context {
		t.Errorf("Context = %#x, want %#x", got.Context, want.Context)
	}
	if got.Flags != want.Flags {
		t.Errorf("Flags = %#x, want %#x", got.Flags, want.Flags)
	}
}

// TestDefaultSndInfoRejectsShortOption records that the kernel policices the
// option length here, unlike SCTP_EVENTS which silently accepts a short struct.
//
// That difference is why SndInfo's size is pinned in
// TestStructLayoutsMatchKernel: if the Go struct were ever a field short, this
// option would fail outright rather than degrade.
func TestDefaultSndInfoRejectsShortOption(t *testing.T) {
	conn := sockoptConn(t)

	var si SndInfo
	// 12 rather than sizeof(SndInfo)==16, the size a struct missing AssocID
	// would have.
	_, _, err := setsockopt(conn.fd(), SCTP_DEFAULT_SNDINFO,
		uintptr(unsafe.Pointer(&si)), 12)
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short SCTP_DEFAULT_SNDINFO gave %v, want EINVAL — if the "+
			"kernel now accepts it, SndInfo's size no longer has to be exact "+
			"and the layout test's rationale should be revisited", err)
	}
}

// TestAutoAsconfNeedsBoundSocket pins the asymmetry that makes this option easy
// to call in the wrong place: SetAutoAsconf requires a bound socket, while
// SetReusePort requires an unbound one. A caller applying both in the same hook
// cannot succeed at both.
func TestAutoAsconfNeedsBoundSocket(t *testing.T) {
	// Unbound: rejected.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	fresh := NewSCTPConn(fd, nil)
	defer func() { _ = fresh.Close() }()

	if err := fresh.SetAutoAsconf(true); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("SetAutoAsconf on an unbound socket gave %v, want EINVAL", err)
	}

	// Bound and connected: accepted, and it reads back.
	conn := sockoptConn(t)
	if err := conn.SetAutoAsconf(true); err != nil {
		t.Fatalf("SetAutoAsconf on a connected socket: %v", err)
	}
	on, err := conn.AutoAsconf()
	if err != nil {
		t.Fatalf("AutoAsconf: %v", err)
	}
	if !on {
		t.Error("AutoAsconf = false after SetAutoAsconf(true)")
	}

	if err := conn.SetAutoAsconf(false); err != nil {
		t.Fatalf("SetAutoAsconf(false): %v", err)
	}
	// Asserting the off state as well; a setter that ignored its argument and
	// always wrote 1 would pass the enable half alone.
	if on, err = conn.AutoAsconf(); err != nil {
		t.Fatalf("AutoAsconf: %v", err)
	} else if on {
		t.Error("AutoAsconf = true after SetAutoAsconf(false)")
	}
}

// sctpSysctl reads one of the net.sctp knobs. Several of these extensions are
// gated by a sysctl as well as by the socket option, and a test that ignored the
// sysctl would draw the wrong conclusion from the option.
func sctpSysctl(t *testing.T, name string) (int, bool) {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/sctp/" + name)
	if err != nil {
		t.Logf("cannot read net.sctp.%s: %v", name, err)
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Logf("unexpected net.sctp.%s contents %q", name, b)
		return 0, false
	}
	return v, true
}

// TestPrSupportedFollowsSysctl pins the fact that makes SetPrSupported almost a
// no-op on a stock kernel: net.sctp.prsctp_enable defaults to 1, so PR-SCTP is
// negotiated whether or not the socket option was ever set.
//
// This started out asserting the same both-ends negotiation that
// TestReconfigSupportedNegotiates asserts, on the assumption that two options
// with the same shape behave the same way. They do not, and the probe that
// settled it is in testdata/optprobe. Pinning the real behaviour matters because
// a caller reading true from PrSupported must not conclude the peer asked for
// partial reliability.
func TestPrSupportedFollowsSysctl(t *testing.T) {
	sysctl, ok := sctpSysctl(t, "prsctp_enable")
	if !ok {
		t.Skip("net.sctp.prsctp_enable is unreadable")
	}
	if sysctl == 0 {
		t.Skip("net.sctp.prsctp_enable is 0; this test pins the default-on case")
	}

	enable := func(c *SCTPConn) error { return c.SetPrSupported(true) }

	// With the sysctl on, every combination negotiates PR-SCTP — including the
	// one where neither end set the option.
	for _, tc := range []struct {
		name              string
		preListen, preDia func(*SCTPConn) error
	}{
		{"neither end", nil, nil},
		{"client only", nil, enable},
		{"listener only", enable, nil},
		{"both ends", enable, enable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := extConn(t, tc.preListen, tc.preDia)
			for name, c := range map[string]*SCTPConn{"client": cli, "server": srv} {
				on, err := c.PrSupported()
				if err != nil {
					t.Fatalf("%s PrSupported: %v", name, err)
				}
				if !on {
					t.Errorf("%s PrSupported = false with "+
						"net.sctp.prsctp_enable=1; the sysctl is supposed to "+
						"make the extension available regardless of the "+
						"socket option", name)
				}
			}
		})
	}

	// The opt-out is the direction that has an observable effect, and it is the
	// only thing that distinguishes a working SetPrSupported from one that
	// ignores its argument: with the sysctl on, every enable path reads back
	// true whether or not the setter did anything.
	//
	// Disabling on one end alone suppresses the extension for both, so this
	// also shows the value is carried in the handshake rather than kept locally.
	t.Run("disabling one end suppresses it for both", func(t *testing.T) {
		cli, srv := extConn(t, nil, func(c *SCTPConn) error {
			return c.SetPrSupported(false)
		})
		for name, c := range map[string]*SCTPConn{"client": cli, "server": srv} {
			on, err := c.PrSupported()
			if err != nil {
				t.Fatalf("%s PrSupported: %v", name, err)
			}
			if on {
				t.Errorf("%s PrSupported = true after the client disabled it; "+
					"SetPrSupported(false) is the one direction that has an "+
					"effect when net.sctp.prsctp_enable is 1", name)
			}
		}
	})
}

// TestDefaultPrInfoRoundTrip checks each documented policy is accepted and reads
// back with its value intact.
func TestDefaultPrInfoRoundTrip(t *testing.T) {
	conn := sockoptConn(t)

	for _, tc := range []struct {
		name   string
		policy uint16
		value  uint32
	}{
		{"none", SCTPPrPolicyNone, 0},
		{"ttl", SCTPPrPolicyTTL, 5000},
		{"rtx", SCTPPrPolicyRtx, 3},
		{"prio", SCTPPrPolicyPrio, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := conn.SetDefaultPrInfo(&DefaultPrInfo{
				Policy: tc.policy, Value: tc.value,
			}); err != nil {
				t.Fatalf("SetDefaultPrInfo(%s): %v", tc.name, err)
			}
			got, err := conn.GetDefaultPrInfo()
			if err != nil {
				t.Fatalf("GetDefaultPrInfo: %v", err)
			}
			if got.Policy != tc.policy {
				t.Errorf("Policy = %#x, want %#x", got.Policy, tc.policy)
			}
			// The none policy carries no value, so the kernel is free not to
			// keep it; only check the value where it means something.
			if tc.policy != SCTPPrPolicyNone && got.Value != tc.value {
				t.Errorf("Value = %d, want %d", got.Value, tc.value)
			}
		})
	}
}

// TestPrPolicyConstantValues pins the policy numbers to the values in
// linux/sctp.h.
//
// The round-trip test cannot catch a mix-up here: the kernel echoes back
// whatever policy it was handed, so swapping SCTPPrPolicyRtx and
// SCTPPrPolicyPrio still round-trips cleanly while every caller silently gets
// the wrong reliability behaviour — a retransmission limit where they asked for
// a priority. Only the literal values distinguish them.
func TestPrPolicyConstantValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"SCTPPrPolicyNone", SCTPPrPolicyNone, 0x0000},
		{"SCTPPrPolicyTTL", SCTPPrPolicyTTL, 0x0010},
		{"SCTPPrPolicyRtx", SCTPPrPolicyRtx, 0x0020},
		{"SCTPPrPolicyPrio", SCTPPrPolicyPrio, 0x0030},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#04x, want %#04x per linux/sctp.h",
				tc.name, tc.got, tc.want)
		}
	}

	// Same argument for the stream reset mask: the kernel accepts any subset,
	// so a transposed bit would round-trip and quietly permit the wrong
	// request type.
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"SCTPEnableResetStreamReq", SCTPEnableResetStreamReq, 0x01},
		{"SCTPEnableResetAssocReq", SCTPEnableResetAssocReq, 0x02},
		{"SCTPEnableChangeAssocReq", SCTPEnableChangeAssocReq, 0x04},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#02x, want %#02x per linux/sctp.h",
				tc.name, tc.got, tc.want)
		}
	}

	// And the HMAC identifiers, where the registry skips 2 — an off-by-one
	// would name a value IANA has not assigned.
	if SCTPAuthHmacIDSHA1 != 1 {
		t.Errorf("SCTPAuthHmacIDSHA1 = %d, want 1", SCTPAuthHmacIDSHA1)
	}
	if SCTPAuthHmacIDSHA256 != 3 {
		t.Errorf("SCTPAuthHmacIDSHA256 = %d, want 3", SCTPAuthHmacIDSHA256)
	}
}

// TestOptionNumbersMatchHeader pins the option numbers of the pairs that cannot
// be told apart by behaviour.
//
// SCTP_PR_ASSOC_STATUS and SCTP_PR_STREAM_STATUS return the same struct
// sctp_prstatus and both read zero on an association where nothing has been
// abandoned, so swapping them survives every round-trip test. Distinguishing them
// would need a message actually abandoned under a partial reliability policy, and
// forcing that reliably needs a stalled receiver — measured as unreproducible over
// loopback, where a 1 ms TTL never expires because the send drains first.
//
// So the numbers are asserted against linux/sctp.h instead. That is weaker than a
// behavioural test and is recorded as such rather than presented as equivalent.
func TestOptionNumbersMatchHeader(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"SCTP_PR_ASSOC_STATUS", SCTP_PR_ASSOC_STATUS, 115},
		{"SCTP_PR_STREAM_STATUS", SCTP_PR_STREAM_STATUS, 116},
		{"SCTP_PR_SUPPORTED", SCTP_PR_SUPPORTED, 113},
		{"SCTP_DEFAULT_PRINFO", SCTP_DEFAULT_PRINFO, 114},
		{"SCTP_RECONFIG_SUPPORTED", SCTP_RECONFIG_SUPPORTED, 117},
		{"SCTP_ENABLE_STREAM_RESET", SCTP_ENABLE_STREAM_RESET, 118},
		{"SCTP_RESET_STREAMS", SCTP_RESET_STREAMS, 119},
		{"SCTP_RESET_ASSOC", SCTP_RESET_ASSOC, 120},
		{"SCTP_ADD_STREAMS", SCTP_ADD_STREAMS, 121},
		{"SCTP_PEER_ADDR_THLDS", SCTP_PEER_ADDR_THLDS, 31},
		{"SCTP_PEER_ADDR_THLDS_V2", SCTP_PEER_ADDR_THLDS_V2, 37},
		{"SCTP_GET_ASSOC_STATS", SCTP_GET_ASSOC_STATS, 112},
		{"SCTP_DEFAULT_SNDINFO", SCTP_DEFAULT_SNDINFO, 34},
		{"SCTP_AUTO_ASCONF", SCTP_AUTO_ASCONF, 30},
		{"SCTP_AUTH_CHUNK", SCTP_AUTH_CHUNK, 21},
		{"SCTP_HMAC_IDENT", SCTP_HMAC_IDENT, 22},
		{"SCTP_AUTH_KEY", SCTP_AUTH_KEY, 23},
		{"SCTP_AUTH_ACTIVE_KEY", SCTP_AUTH_ACTIVE_KEY, 24},
		{"SCTP_AUTH_DELETE_KEY", SCTP_AUTH_DELETE_KEY, 25},
		{"SCTP_PEER_AUTH_CHUNKS", SCTP_PEER_AUTH_CHUNKS, 26},
		{"SCTP_LOCAL_AUTH_CHUNKS", SCTP_LOCAL_AUTH_CHUNKS, 27},
		{"SCTP_AUTH_DEACTIVATE_KEY", SCTP_AUTH_DEACTIVATE_KEY, 35},
		// The table used to stop at SCTP_ADD_STREAMS, leaving everything from
		// here on covered only by set/get round trips through the same
		// constant — which cannot fail whatever the number is. Mutation
		// confirmed it: swapping SCTP_ASCONF_SUPPORTED with SCTP_AUTH_SUPPORTED
		// left the complete suite green, while a live probe showed
		// SetAuthSupported(true) reading back 1 through the wrong option with
		// SCTP_AUTH_SUPPORTED still 0 and ASCONF switched on instead. An
		// application asking for AUTH would silently get dynamic address
		// reconfiguration.
		{"SCTP_RECVRCVINFO", SCTP_RECVRCVINFO, 32},
		{"SCTP_RECVNXTINFO", SCTP_RECVNXTINFO, 33},
		{"SCTP_REUSE_PORT", SCTP_REUSE_PORT, 36},
		{"SCTP_STREAM_SCHEDULER", SCTP_STREAM_SCHEDULER, 123},
		{"SCTP_STREAM_SCHEDULER_VALUE", SCTP_STREAM_SCHEDULER_VALUE, 124},
		{"SCTP_INTERLEAVING_SUPPORTED", SCTP_INTERLEAVING_SUPPORTED, 125},
		{"SCTP_EVENT", SCTP_EVENT, 127},
		{"SCTP_ASCONF_SUPPORTED", SCTP_ASCONF_SUPPORTED, 128},
		{"SCTP_AUTH_SUPPORTED", SCTP_AUTH_SUPPORTED, 129},
		{"SCTP_ECN_SUPPORTED", SCTP_ECN_SUPPORTED, 130},
		{"SCTP_EXPOSE_POTENTIALLY_FAILED_STATE", SCTP_EXPOSE_POTENTIALLY_FAILED_STATE, 131},
		{"SCTP_EXPOSE_PF_STATE", SCTP_EXPOSE_PF_STATE, 131},
		{"SCTP_REMOTE_UDP_ENCAPS_PORT", SCTP_REMOTE_UDP_ENCAPS_PORT, 132},
		{"SCTP_PLPMTUD_PROBE_INTERVAL", SCTP_PLPMTUD_PROBE_INTERVAL, 133},
		{"SCTP_SOCKOPT_PEELOFF", SCTP_SOCKOPT_PEELOFF, 102},
		{"SCTP_SOCKOPT_PEELOFF_FLAGS", SCTP_SOCKOPT_PEELOFF_FLAGS, 122},
		{"SCTP_GET_PEER_ADDRS", SCTP_GET_PEER_ADDRS, 108},
		{"SCTP_GET_LOCAL_ADDRS", SCTP_GET_LOCAL_ADDRS, 109},
		{"SCTP_SOCKOPT_CONNECTX", SCTP_SOCKOPT_CONNECTX, 110},
		{"SCTP_SOCKOPT_CONNECTX3", SCTP_SOCKOPT_CONNECTX3, 111},
		{"SCTP_SOCKOPT_BINDX_ADD", SCTP_SOCKOPT_BINDX_ADD, 100},
		{"SCTP_SOCKOPT_BINDX_REM", SCTP_SOCKOPT_BINDX_REM, 101},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d per linux/sctp.h",
				tc.name, tc.got, tc.want)
		}
	}

	// No two options may share a number. A copy-paste that duplicates one is
	// the mistake the table above cannot catch on its own, since each row is
	// checked in isolation.
	seen := map[uintptr]string{}
	for _, tc := range []struct {
		name string
		got  uintptr
	}{
		{"SCTP_AUTH_CHUNK", SCTP_AUTH_CHUNK},
		{"SCTP_HMAC_IDENT", SCTP_HMAC_IDENT},
		{"SCTP_AUTH_KEY", SCTP_AUTH_KEY},
		{"SCTP_AUTH_ACTIVE_KEY", SCTP_AUTH_ACTIVE_KEY},
		{"SCTP_AUTH_DELETE_KEY", SCTP_AUTH_DELETE_KEY},
		{"SCTP_PEER_AUTH_CHUNKS", SCTP_PEER_AUTH_CHUNKS},
		{"SCTP_LOCAL_AUTH_CHUNKS", SCTP_LOCAL_AUTH_CHUNKS},
		{"SCTP_AUTO_ASCONF", SCTP_AUTO_ASCONF},
		{"SCTP_PEER_ADDR_THLDS", SCTP_PEER_ADDR_THLDS},
		{"SCTP_RECVRCVINFO", SCTP_RECVRCVINFO},
		{"SCTP_RECVNXTINFO", SCTP_RECVNXTINFO},
		{"SCTP_DEFAULT_SNDINFO", SCTP_DEFAULT_SNDINFO},
		{"SCTP_AUTH_DEACTIVATE_KEY", SCTP_AUTH_DEACTIVATE_KEY},
		{"SCTP_REUSE_PORT", SCTP_REUSE_PORT},
		{"SCTP_PEER_ADDR_THLDS_V2", SCTP_PEER_ADDR_THLDS_V2},
		{"SCTP_GET_ASSOC_STATS", SCTP_GET_ASSOC_STATS},
		{"SCTP_PR_SUPPORTED", SCTP_PR_SUPPORTED},
		{"SCTP_DEFAULT_PRINFO", SCTP_DEFAULT_PRINFO},
		{"SCTP_PR_ASSOC_STATUS", SCTP_PR_ASSOC_STATUS},
		{"SCTP_PR_STREAM_STATUS", SCTP_PR_STREAM_STATUS},
		{"SCTP_RECONFIG_SUPPORTED", SCTP_RECONFIG_SUPPORTED},
		{"SCTP_ENABLE_STREAM_RESET", SCTP_ENABLE_STREAM_RESET},
		{"SCTP_RESET_STREAMS", SCTP_RESET_STREAMS},
		{"SCTP_RESET_ASSOC", SCTP_RESET_ASSOC},
		{"SCTP_ADD_STREAMS", SCTP_ADD_STREAMS},
		{"SCTP_STREAM_SCHEDULER", SCTP_STREAM_SCHEDULER},
		{"SCTP_STREAM_SCHEDULER_VALUE", SCTP_STREAM_SCHEDULER_VALUE},
		{"SCTP_INTERLEAVING_SUPPORTED", SCTP_INTERLEAVING_SUPPORTED},
		{"SCTP_EVENT", SCTP_EVENT},
		{"SCTP_ASCONF_SUPPORTED", SCTP_ASCONF_SUPPORTED},
		{"SCTP_AUTH_SUPPORTED", SCTP_AUTH_SUPPORTED},
		{"SCTP_ECN_SUPPORTED", SCTP_ECN_SUPPORTED},
		{"SCTP_EXPOSE_POTENTIALLY_FAILED_STATE", SCTP_EXPOSE_POTENTIALLY_FAILED_STATE},
		{"SCTP_REMOTE_UDP_ENCAPS_PORT", SCTP_REMOTE_UDP_ENCAPS_PORT},
		{"SCTP_PLPMTUD_PROBE_INTERVAL", SCTP_PLPMTUD_PROBE_INTERVAL},
	} {
		if prev, dup := seen[tc.got]; dup {
			t.Errorf("%s and %s are both %d", tc.name, prev, tc.got)
		}
		seen[tc.got] = tc.name
	}

	// The ancillary data types are positional in enum sctp_cmsg_type, so an
	// insertion shifts every later one. A wrong SCTP_CMSG_PRINFO makes the
	// kernel reject the send, but SCTP_CMSG_DSTADDRV4/V6 are unreachable from
	// this package's one-to-one sockets and would go unnoticed.
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"SCTP_CMSG_INIT", SCTP_CMSG_INIT, 0},
		{"SCTP_CMSG_SNDRCV", SCTP_CMSG_SNDRCV, 1},
		{"SCTP_CMSG_SNDINFO", SCTP_CMSG_SNDINFO, 2},
		{"SCTP_CMSG_RCVINFO", SCTP_CMSG_RCVINFO, 3},
		{"SCTP_CMSG_NXTINFO", SCTP_CMSG_NXTINFO, 4},
		{"SCTP_CMSG_PRINFO", SCTP_CMSG_PRINFO, 5},
		{"SCTP_CMSG_AUTHINFO", SCTP_CMSG_AUTHINFO, 6},
		{"SCTP_CMSG_DSTADDRV4", SCTP_CMSG_DSTADDRV4, 7},
		{"SCTP_CMSG_DSTADDRV6", SCTP_CMSG_DSTADDRV6, 8},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d per enum sctp_cmsg_type",
				tc.name, tc.got, tc.want)
		}
	}
}

// TestDefaultPrInfoRejectsUnknownPolicy records that the kernel does validate
// this option, in contrast to SCTP_FRAGMENT_INTERLEAVE which accepts an
// undefined level. That contrast is the reason SetDefaultPrInfo has no
// Go-side guard while SetFragmentInterleave does.
func TestDefaultPrInfoRejectsUnknownPolicy(t *testing.T) {
	conn := sockoptConn(t)

	err := conn.SetDefaultPrInfo(&DefaultPrInfo{Policy: 0x40, Value: 1})
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("SetDefaultPrInfo with policy 0x40 gave %v, want EINVAL — if "+
			"the kernel stopped validating, SetDefaultPrInfo needs the same "+
			"Go-side guard SetFragmentInterleave has", err)
	}
}

// TestPrStreamStatusNeedsAssociation pins both halves of this getter: it works
// on a live association and reports EINVAL without one. The failing half matters
// because the error is the only signal a caller gets.
func TestPrStreamStatusNeedsAssociation(t *testing.T) {
	conn := sockoptConn(t)
	st, err := conn.GetPrStreamStatus(0, SCTPPrPolicyTTL)
	if err != nil {
		t.Fatalf("GetPrStreamStatus on a live association: %v", err)
	}
	// Nothing has been abandoned, so both counters must be zero. A non-zero
	// reading here would mean the struct is misaligned and picking up other
	// fields.
	if st.AbandonedUnsent != 0 || st.AbandonedSent != 0 {
		t.Errorf("fresh association reports abandoned unsent=%d sent=%d, "+
			"want 0/0 — a non-zero count suggests a layout mismatch",
			st.AbandonedUnsent, st.AbandonedSent)
	}

	// The stream id must reach the kernel. Querying stream 0 cannot show that:
	// zero is also what an ignored field leaves behind, so dropping sid from
	// the request survives. Ask about a stream that is not the first.
	const sid = 3
	st3, err := conn.GetPrStreamStatus(sid, SCTPPrPolicyTTL)
	if err != nil {
		t.Fatalf("GetPrStreamStatus(%d): %v", sid, err)
	}
	if st3.SID != sid {
		t.Errorf("GetPrStreamStatus(%d) came back describing stream %d; the "+
			"stream id is not being carried into the request", sid, st3.SID)
	}
	if st3.Policy != SCTPPrPolicyTTL {
		t.Errorf("GetPrStreamStatus policy = %d, want %d", st3.Policy, SCTPPrPolicyTTL)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	fresh := NewSCTPConn(fd, nil)
	defer func() { _ = fresh.Close() }()
	if _, err := fresh.GetPrStreamStatus(0, SCTPPrPolicyTTL); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("GetPrStreamStatus without an association gave %v, want EINVAL",
			err)
	}
}

// TestPrAssocStatus covers RFC 7496 §4.3, the association-wide abandonment
// counters.
//
// This option was nearly left unbound on the assumption that it applied to
// one-to-many sockets like SCTP_GET_ASSOC_NUMBER does. It does not — it works
// here, which a probe established before the binding was written. Assuming would
// have been the fourth such mistake in this package.
func TestPrAssocStatus(t *testing.T) {
	conn := sockoptConn(t)

	st, err := conn.GetPrAssocStatus(SCTPPrPolicyTTL)
	if err != nil {
		t.Fatalf("GetPrAssocStatus: %v", err)
	}
	// Nothing has been abandoned, so both counters must read zero. A non-zero
	// value would mean the struct is misaligned and picking up other fields.
	if st.AbandonedUnsent != 0 || st.AbandonedSent != 0 {
		t.Errorf("fresh association reports abandoned unsent=%d sent=%d, want "+
			"0/0 — a non-zero count suggests a layout mismatch",
			st.AbandonedUnsent, st.AbandonedSent)
	}

	// Without an association there is nothing to total.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM,
		syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	fresh := NewSCTPConn(fd, nil)
	defer func() { _ = fresh.Close() }()
	if _, err := fresh.GetPrAssocStatus(SCTPPrPolicyTTL); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("GetPrAssocStatus without an association gave %v, want EINVAL",
			err)
	}
}

// TestPeerAddrThldsV2RoundTrip covers the Linux extension with the third
// threshold.
//
// The probe cutoff is what v2 adds over the RFC 7829 option, so that is the field
// the round trip has to prove — reading back only the two v1 fields would pass
// with the v2 struct one field short and the option length wrong.
func TestPeerAddrThldsV2RoundTrip(t *testing.T) {
	conn := sockoptConn(t)

	got, err := conn.GetPeerAddrThldsV2()
	if err != nil {
		t.Fatalf("GetPeerAddrThldsV2: %v", err)
	}
	// The kernel default for the probe cutoff is 0xffff, meaning a Potentially
	// Failed path is probed indefinitely. Anything else here means the field is
	// being read at the wrong offset.
	if got.PathCpThld != 0xffff {
		t.Errorf("default PathCpThld = %#x, want 0xffff — a different value "+
			"suggests the field is at the wrong offset", got.PathCpThld)
	}

	got.PathMaxRxt = 8
	got.PathPfThld = 3
	got.PathCpThld = 5
	if err := conn.SetPeerAddrThldsV2(got); err != nil {
		t.Fatalf("SetPeerAddrThldsV2: %v", err)
	}

	back, err := conn.GetPeerAddrThldsV2()
	if err != nil {
		t.Fatalf("GetPeerAddrThldsV2 after set: %v", err)
	}
	if back.PathMaxRxt != 8 || back.PathPfThld != 3 || back.PathCpThld != 5 {
		t.Errorf("thresholds read back as maxrxt=%d pf=%d cp=%d, want 8/3/5",
			back.PathMaxRxt, back.PathPfThld, back.PathCpThld)
	}
}

// TestReconfigSupportedNegotiates is the sharpest of these tests, because the
// behaviour it pins looks like a bug from the outside: SetReconfigSupported
// returns success on a connected socket and ReconfigSupported still reports
// false, since the extension can only be negotiated in the INIT.
//
// All three combinations are covered so the "client only" case cannot be
// mistaken for the setter having failed.
func TestReconfigSupportedNegotiates(t *testing.T) {
	enable := func(c *SCTPConn) error { return c.SetReconfigSupported(true) }

	t.Run("both ends", func(t *testing.T) {
		cli, srv := extConn(t, enable, enable)
		for name, c := range map[string]*SCTPConn{"client": cli, "server": srv} {
			on, err := c.ReconfigSupported()
			if err != nil {
				t.Fatalf("%s ReconfigSupported: %v", name, err)
			}
			if !on {
				t.Errorf("%s ReconfigSupported = false with both ends enabled",
					name)
			}
		}
	})

	t.Run("client only reads back false", func(t *testing.T) {
		cli, _ := extConn(t, nil, enable)
		on, err := cli.ReconfigSupported()
		if err != nil {
			t.Fatalf("ReconfigSupported: %v", err)
		}
		if on {
			t.Error("ReconfigSupported = true with only the client enabled")
		}
	})

	t.Run("post-connect set succeeds but does not take", func(t *testing.T) {
		cli, _ := extConn(t, nil, nil)
		// Success here with a false reading afterwards is the documented
		// behaviour; if the kernel ever started rejecting the late set, the
		// doc comment on ReconfigSupported would need revisiting.
		if err := cli.SetReconfigSupported(true); err != nil {
			t.Fatalf("SetReconfigSupported after connect: %v — the "+
				"documentation says this succeeds and is ignored", err)
		}
		on, err := cli.ReconfigSupported()
		if err != nil {
			t.Fatalf("ReconfigSupported: %v", err)
		}
		if on {
			t.Error("ReconfigSupported = true after a post-connect set; the " +
				"extension is negotiated in the INIT and cannot be enabled later")
		}
	})
}

// TestEnableStreamResetRoundTrip covers the mask, including the Go-side
// rejection of undefined bits.
func TestEnableStreamResetRoundTrip(t *testing.T) {
	conn := sockoptConn(t)

	all := uint32(SCTPEnableResetStreamReq | SCTPEnableResetAssocReq |
		SCTPEnableChangeAssocReq)
	for _, mask := range []uint32{
		0,
		SCTPEnableResetStreamReq,
		SCTPEnableResetAssocReq,
		SCTPEnableChangeAssocReq,
		all,
	} {
		if err := conn.SetEnableStreamReset(mask); err != nil {
			t.Fatalf("SetEnableStreamReset(%#x): %v", mask, err)
		}
		got, err := conn.EnableStreamReset()
		if err != nil {
			t.Fatalf("EnableStreamReset: %v", err)
		}
		if got != mask {
			t.Errorf("EnableStreamReset = %#x, want %#x", got, mask)
		}
	}

	// An unknown bit is rejected in Go rather than passed through, because the
	// kernel masks it away silently and the caller would never learn the
	// request was meaningless.
	err := conn.SetEnableStreamReset(all | 0x08)
	if err == nil {
		t.Fatal("SetEnableStreamReset accepted an undefined bit")
	}
	if !strings.Contains(err.Error(), "unknown bits") {
		t.Errorf("error = %q, want it to mention unknown bits", err)
	}
	// The rejection must happen before the syscall, leaving the value alone.
	if err := conn.SetEnableStreamReset(SCTPEnableResetStreamReq); err != nil {
		t.Fatalf("SetEnableStreamReset after a rejected call: %v", err)
	}
	if got, err := conn.EnableStreamReset(); err != nil {
		t.Fatalf("EnableStreamReset: %v", err)
	} else if got != SCTPEnableResetStreamReq {
		t.Errorf("EnableStreamReset = %#x, want %#x after the rejected call "+
			"left the socket untouched", got, SCTPEnableResetStreamReq)
	}
}

// TestAddStreams covers RFC 6525 §6.5, and exists because the first probe of
// this option concluded it was unusable.
//
// That conclusion was wrong: the probe had set SCTP_RECONFIG_SUPPORTED after
// connect, so the extension was never negotiated and the kernel answered
// ENOPROTOOPT — which reads exactly like an unsupported option. With the
// extension negotiated before connect and SCTPEnableChangeAssocReq in the mask,
// it succeeds. Both halves are pinned here so the distinction stays visible.
func TestAddStreams(t *testing.T) {
	prepare := func(c *SCTPConn) error {
		if err := c.SetReconfigSupported(true); err != nil {
			return err
		}
		return c.SetEnableStreamReset(SCTPEnableResetStreamReq |
			SCTPEnableResetAssocReq | SCTPEnableChangeAssocReq)
	}

	t.Run("with the extension negotiated", func(t *testing.T) {
		cli, _ := extConn(t, prepare, prepare)

		// Guard the precondition: if negotiation silently stopped working, the
		// AddStreams failure below would be blamed on the wrong thing.
		on, err := cli.ReconfigSupported()
		if err != nil {
			t.Fatalf("ReconfigSupported: %v", err)
		}
		if !on {
			t.Fatal("reconfiguration was not negotiated; the rest of this " +
				"test cannot distinguish a broken AddStreams from a " +
				"missing extension")
		}

		before, err := cli.GetStatus()
		if err != nil {
			t.Fatalf("GetStatus: %v", err)
		}
		if err := cli.AddStreams(2, 2); err != nil {
			t.Fatalf("AddStreams(2, 2): %v", err)
		}
		after, err := cli.GetStatus()
		if err != nil {
			t.Fatalf("GetStatus after AddStreams: %v", err)
		}
		t.Logf("streams in/out before %d/%d, after %d/%d",
			before.Instreams, before.Ostreams,
			after.Instreams, after.Ostreams)

		// Over loopback the peer answers within the setsockopt call, so the new
		// outbound count is readable immediately. Asserting it rather than just
		// the absence of an error is what separates "the request was accepted"
		// from "the association actually widened" — the former would still hold
		// if the kernel silently dropped the request.
		if after.Ostreams != before.Ostreams+2 {
			t.Errorf("outbound streams = %d, want %d after adding 2; the "+
				"request was accepted but the association did not widen",
				after.Ostreams, before.Ostreams+2)
		}
	})

	t.Run("without the extension", func(t *testing.T) {
		conn := sockoptConn(t)
		err := conn.AddStreams(2, 2)
		if err == nil {
			t.Fatal("AddStreams succeeded without the reconfiguration " +
				"extension negotiated")
		}
		if !errors.Is(err, syscall.ENOPROTOOPT) {
			t.Errorf("AddStreams without the extension gave %v, want "+
				"ENOPROTOOPT — that errno is what made this option look "+
				"unsupported when it is merely un-negotiated", err)
		}
	})
}

// TestPeerAddrThldsRoundTrip exercises the RFC 7829 thresholds.
//
// The size and the 8-byte alignment of the embedded sockaddr_storage are what
// make this struct easy to get wrong — a Go struct without the explicit pads is
// 140 bytes with every field after the assoc id shifted by four, which the
// kernel would reject or misread. This test would fail on both counts.
func TestPeerAddrThldsRoundTrip(t *testing.T) {
	conn := sockoptConn(t)

	got, err := conn.GetPeerAddrThlds()
	if err != nil {
		t.Fatalf("GetPeerAddrThlds: %v", err)
	}
	// The kernel default is 5; a wildly different reading means the fields are
	// being read at the wrong offsets.
	if got.PathMaxRxt == 0 || got.PathMaxRxt > 100 {
		t.Errorf("default PathMaxRxt = %d, which is outside anything the "+
			"kernel would default to — check the struct offsets",
			got.PathMaxRxt)
	}

	got.PathMaxRxt = 8
	got.PathPfThld = 3
	if err := conn.SetPeerAddrThlds(got); err != nil {
		t.Fatalf("SetPeerAddrThlds: %v", err)
	}

	back, err := conn.GetPeerAddrThlds()
	if err != nil {
		t.Fatalf("GetPeerAddrThlds after set: %v", err)
	}
	if back.PathMaxRxt != 8 {
		t.Errorf("PathMaxRxt = %d, want 8", back.PathMaxRxt)
	}
	if back.PathPfThld != 3 {
		t.Errorf("PathPfThld = %d, want 3", back.PathPfThld)
	}
}

// TestAssocStatsCountsTraffic pins that the counters move with real traffic.
//
// Merely reading the struct proves nothing — a zeroed struct at the wrong
// offsets reads as zero too. Sending a message and requiring the packet counter
// to grow is what distinguishes a working binding from a misaligned one.
func TestAssocStatsCountsTraffic(t *testing.T) {
	conn := sockoptConn(t)

	before, err := conn.GetAssocStats()
	if err != nil {
		t.Fatalf("GetAssocStats: %v", err)
	}

	if _, err := conn.SCTPWrite([]byte("stats"), &SndRcvInfo{Stream: 0}); err != nil {
		t.Fatalf("write: %v", err)
	}

	after, err := conn.GetAssocStats()
	if err != nil {
		t.Fatalf("GetAssocStats after write: %v", err)
	}
	if after.OPackets <= before.OPackets {
		t.Errorf("OPackets did not grow across a send: %d -> %d",
			before.OPackets, after.OPackets)
	}
	// Ordered data chunks must have grown too; if only OPackets moved, the
	// later fields are probably at the wrong offsets.
	if after.OOdChunks <= before.OOdChunks {
		t.Errorf("OOdChunks did not grow across a send: %d -> %d",
			before.OOdChunks, after.OOdChunks)
	}
}

// TestAssocStatsNeedsAssociation pins the error path, which is the only signal
// a caller gets on a socket without an association.
func TestAssocStatsNeedsAssociation(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	fresh := NewSCTPConn(fd, nil)
	defer func() { _ = fresh.Close() }()

	if _, err := fresh.GetAssocStats(); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("GetAssocStats without an association gave %v, want EINVAL",
			err)
	}
}

// authEnabled reports whether net.sctp.auth_enable is on. The whole SCTP_AUTH_*
// family fails with EACCES when it is off, and it is off on a stock kernel, so
// the AUTH tests have to know which of the two situations they are in rather
// than treating one as the other.
func authEnabled(t *testing.T) bool {
	t.Helper()
	v, ok := sctpSysctl(t, "auth_enable")
	return ok && v != 0
}

// TestAuthDisabledReportsEACCES is the half of the AUTH coverage that runs on a
// stock kernel, and it is the more useful half: it pins the errno a caller sees
// when the sysctl is off.
//
// EACCES rather than EOPNOTSUPP is worth pinning precisely because it reads like
// a privilege problem. Without this test the diagnosis for "AUTH does not work"
// would start in the wrong place.
func TestAuthDisabledReportsEACCES(t *testing.T) {
	if authEnabled(t) {
		t.Skip("net.sctp.auth_enable is on; TestAuthEnabledRoundTrip covers this")
	}
	conn := sockoptConn(t)

	if _, err := conn.HmacIdent(); !errors.Is(err, syscall.EACCES) {
		t.Errorf("HmacIdent with auth_enable=0 gave %v, want EACCES", err)
	}
	if _, err := conn.AuthActiveKey(); !errors.Is(err, syscall.EACCES) {
		t.Errorf("AuthActiveKey with auth_enable=0 gave %v, want EACCES", err)
	}
	if err := conn.SetAuthActiveKey(1); !errors.Is(err, syscall.EACCES) {
		t.Errorf("SetAuthActiveKey with auth_enable=0 gave %v, want EACCES", err)
	}
	if _, err := conn.LocalAuthChunks(); !errors.Is(err, syscall.EACCES) {
		t.Errorf("LocalAuthChunks with auth_enable=0 gave %v, want EACCES", err)
	}
}

// TestAuthEnabledRoundTrip covers the AUTH accessors on a kernel with the
// sysctl on. Run it with:
//
//	echo 1 > /proc/sys/net/sctp/auth_enable
//
// It is skipped otherwise rather than enabling the sysctl itself, because that
// is a global change and a test has no business making one.
func TestAuthEnabledRoundTrip(t *testing.T) {
	if !authEnabled(t) {
		t.Skip("net.sctp.auth_enable is off; " +
			"set it to 1 to run the AUTH round trip")
	}
	conn := sockoptConn(t)

	idents, err := conn.HmacIdent()
	if err != nil {
		t.Fatalf("HmacIdent: %v", err)
	}
	if len(idents) == 0 {
		t.Fatal("HmacIdent returned no algorithms; RFC 4895 §3.1.1 makes " +
			"SHA-1 mandatory to implement")
	}
	// SHA-1 is mandatory, so it must appear. This also catches a decoder that
	// returned the right count of garbage.
	var haveSHA1 bool
	for _, id := range idents {
		if id == SCTPAuthHmacIDSHA1 {
			haveSHA1 = true
		}
	}
	if !haveSHA1 {
		t.Errorf("HmacIdent = %v, want it to include SHA-1 (%d)",
			idents, SCTPAuthHmacIDSHA1)
	}

	if err := conn.SetAuthActiveKey(0); err != nil {
		t.Fatalf("SetAuthActiveKey(0): %v", err)
	}
	// Key 0 is the null key every association starts with, so this round trip
	// works without installing a shared key first.
	got, err := conn.AuthActiveKey()
	if err != nil {
		t.Fatalf("AuthActiveKey: %v", err)
	}
	if got != 0 {
		t.Errorf("AuthActiveKey = %d, want 0", got)
	}

	// These used to be checked for err == nil only, which a stub returning
	// (nil, nil) satisfies just as well as a working decoder. Ask for a
	// specific chunk type and require it back: DATA is chunk type 0, and
	// SetAuthChunk is what puts it in the local list.
	if err := conn.SetAuthChunk(0); err != nil {
		t.Fatalf("SetAuthChunk(0): %v", err)
	}
	local, err := conn.LocalAuthChunks()
	if err != nil {
		t.Fatalf("LocalAuthChunks: %v", err)
	}
	found := false
	for _, ct := range local {
		if ct == 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("LocalAuthChunks = %v, want it to contain the chunk type 0 that "+
			"SetAuthChunk(0) just added", local)
	}

	// PeerAuthChunks needs the association, which sockoptConn provides. Its
	// contents depend on what the peer asked for, so the assertion here is that
	// the call decodes rather than what it decodes to.
	if _, err := conn.PeerAuthChunks(); err != nil {
		t.Fatalf("PeerAuthChunks: %v", err)
	}

	// HmacIdent likewise: set a specific two-element list and require exactly
	// it back, in order. Returning a hard-coded []uint16{SCTPAuthHmacIDSHA1}
	// satisfied the old assertion.
	if err := conn.SetHmacIdent(SCTPAuthHmacIDSHA256, SCTPAuthHmacIDSHA1); err != nil {
		t.Fatalf("SetHmacIdent: %v", err)
	}
	idents, herr := conn.HmacIdent()
	if herr != nil {
		t.Fatalf("HmacIdent: %v", herr)
	}
	want := []uint16{SCTPAuthHmacIDSHA256, SCTPAuthHmacIDSHA1}
	if len(idents) != len(want) {
		t.Fatalf("HmacIdent = %v, want %v", idents, want)
	}
	for i := range want {
		if idents[i] != want[i] {
			t.Errorf("HmacIdent = %v, want %v: the order is the preference order, "+
				"so a reversed list selects a different algorithm", idents, want)
			break
		}
	}
}

// TestParseHmacIdents covers the struct sctp_hmacalgo decoder directly, because
// the cases that matter cannot be produced by a real kernel.
//
// The one that matters most is a count larger than the option length allows. The
// kernel will not send that, but the decoder must not read past the buffer if it
// ever does, and only a hand-built input can prove it does not.
func TestParseHmacIdents(t *testing.T) {
	// buildHmac lays out a count followed by identifiers, in host order, the
	// way the kernel writes the struct.
	buildHmac := func(count uint32, idents ...uint16) []byte {
		b := make([]byte, 4+2*len(idents))
		nativeEndian.PutUint32(b[:4], count)
		for i, id := range idents {
			nativeEndian.PutUint16(b[4+2*i:], id)
		}
		return b
	}

	t.Run("count matching the length", func(t *testing.T) {
		b := buildHmac(2, SCTPAuthHmacIDSHA1, SCTPAuthHmacIDSHA256)
		got, err := parseHmacIdents(b, len(b))
		if err != nil {
			t.Fatalf("parseHmacIdents: %v", err)
		}
		if len(got) != 2 || got[0] != SCTPAuthHmacIDSHA1 ||
			got[1] != SCTPAuthHmacIDSHA256 {
			t.Errorf("got %v, want [%d %d]", got,
				SCTPAuthHmacIDSHA1, SCTPAuthHmacIDSHA256)
		}
	})

	t.Run("count exceeding the length is clamped", func(t *testing.T) {
		// Claims 8 identifiers, carries room for 1. Trusting the count would
		// read 14 bytes past the end.
		b := buildHmac(8, SCTPAuthHmacIDSHA1)
		got, err := parseHmacIdents(b, len(b))
		if err != nil {
			t.Fatalf("parseHmacIdents: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d identifiers, want 1 — the count must not be "+
				"trusted over the option length", len(got))
		}
		if got[0] != SCTPAuthHmacIDSHA1 {
			t.Errorf("got %v, want [%d]", got, SCTPAuthHmacIDSHA1)
		}
	})

	t.Run("empty list", func(t *testing.T) {
		b := buildHmac(0)
		got, err := parseHmacIdents(b, len(b))
		if err != nil {
			t.Fatalf("parseHmacIdents: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want an empty list", got)
		}
	})

	t.Run("too short for a count", func(t *testing.T) {
		if _, err := parseHmacIdents(make([]byte, 8), 3); err == nil {
			t.Error("parseHmacIdents accepted a 3 byte option")
		}
	})

	t.Run("length beyond the buffer", func(t *testing.T) {
		if _, err := parseHmacIdents(make([]byte, 8), 64); err == nil {
			t.Error("parseHmacIdents accepted an option length past the buffer")
		}
	})
}

// TestParseAuthChunks covers the struct sctp_authchunks decoder.
//
// Keeping the leading association id in the returned list would look harmless —
// four extra zero bytes — but zero is the DATA chunk type, so the caller would
// read it as a peer requiring DATA to be authenticated. That is why the
// off-by-four is tested explicitly rather than left to the round trip, which
// cannot tell the two apart.
func TestParseAuthChunks(t *testing.T) {
	b := make([]byte, 8)
	nativeEndian.PutUint32(b[:4], 0) // association id
	b[4], b[5], b[6], b[7] = 0xc0, 0xc1, 0x0e, 0x0d

	got, err := parseAuthChunks(b, len(b))
	if err != nil {
		t.Fatalf("parseAuthChunks: %v", err)
	}
	want := []uint8{0xc0, 0xc1, 0x0e, 0x0d}
	if len(got) != len(want) {
		t.Fatalf("got %d chunk types (%v), want %d — a length of %d suggests "+
			"the association id was not skipped", len(got), got, len(want),
			len(want)+4)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chunk %d = %#x, want %#x", i, got[i], want[i])
		}
	}

	t.Run("id only", func(t *testing.T) {
		got, err := parseAuthChunks(make([]byte, 8), 4)
		if err != nil {
			t.Fatalf("parseAuthChunks: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want an empty list for an option carrying only "+
				"the association id", got)
		}
	})

	t.Run("too short", func(t *testing.T) {
		if _, err := parseAuthChunks(make([]byte, 8), 2); err == nil {
			t.Error("parseAuthChunks accepted a 2 byte option")
		}
	})

	t.Run("length beyond the buffer", func(t *testing.T) {
		if _, err := parseAuthChunks(make([]byte, 8), 64); err == nil {
			t.Error("parseAuthChunks accepted an option length past the buffer")
		}
	})
}

// TestPeerAuthChunksNeedsAssociation pins that this getter has no meaning
// without a peer, and that the missing association is reported as EINVAL
// regardless of the auth_enable sysctl.
//
// The ordering is the point. Every other SCTP_AUTH_* option reports EACCES when
// the sysctl is off, so the obvious expectation is EACCES here too — but the
// kernel checks for the association first, and returns EINVAL even with AUTH
// disabled. That was measured. A caller cannot use the errno from this one option
// to tell whether AUTH is available.
func TestPeerAuthChunksNeedsAssociation(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	fresh := NewSCTPConn(fd, nil)
	defer func() { _ = fresh.Close() }()

	_, err = fresh.PeerAuthChunks()
	if err == nil {
		t.Fatal("PeerAuthChunks succeeded on a socket with no association")
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("PeerAuthChunks without an association gave %v, want EINVAL "+
			"(the association check precedes the auth_enable check, so this "+
			"holds whichever way the sysctl is set)", err)
	}
}
