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
	"syscall"
	"testing"
	"unsafe"
)

// TestPeerAddrParamsLayoutMatchesKernel pins every offset in the packed form.
//
// sctp_paddrparams is the one struct here that Go cannot mirror field by field:
// it is declared packed and aligned(4), and the 128-byte address leaves
// spp_pathmtu at offset 138, a uint32 on a two-byte boundary. So the exported
// type is an ordinary Go struct and the wire form is marshalled, which means
// the offsets are code rather than something the compiler derives — and code
// with no test is a guess.
//
// The numbers come from compiling the kernel header; see testdata/README.md.
func TestPeerAddrParamsLayoutMatchesKernel(t *testing.T) {
	if paddrparamsSize != 156 {
		t.Errorf("paddrparamsSize = %d, want 156", paddrparamsSize)
	}
	for _, tc := range []struct {
		field string
		got   int
		want  int
	}{
		{"spp_assoc_id", pppAssocID, 0},
		{"spp_address", pppAddress, 4},
		{"spp_hbinterval", pppHBInterval, 132},
		{"spp_pathmaxrxt", pppPathMaxRxt, 136},
		{"spp_pathmtu", pppPathMTU, 138},
		{"spp_sackdelay", pppSackDelay, 142},
		{"spp_flags", pppFlags, 146},
		{"spp_ipv6_flowlabel", pppFlowLabel, 150},
		{"spp_dscp", pppDSCP, 154},
	} {
		if tc.got != tc.want {
			t.Errorf("%s at offset %d, kernel has it at %d", tc.field, tc.got, tc.want)
		}
	}
}

// TestPeerAddrParamsRoundTripsThroughItsPackedForm checks the marshalling is
// reversible, with a distinct value in every field so a swapped pair shows.
func TestPeerAddrParamsRoundTripsThroughItsPackedForm(t *testing.T) {
	want := PeerAddrParams{
		AssocID:       0x11223344,
		HBInterval:    0x55667788,
		PathMaxRxt:    0x99aa,
		PathMTU:       0xbbccddee,
		SackDelay:     0x01020304,
		Flags:         SPP_HB_ENABLE | SPP_SACKDELAY_DISABLE,
		IPv6FlowLabel: 0x05060708,
		DSCP:          0x5c,
	}
	for i := range want.Address {
		want.Address[i] = byte(i)
	}

	b := want.marshal()
	if len(b) != paddrparamsSize {
		t.Fatalf("marshal produced %d bytes, want %d", len(b), paddrparamsSize)
	}
	var got PeerAddrParams
	got.unmarshal(b)
	if got != want {
		t.Errorf("round trip changed the value:\n got %+v\nwant %+v", got, want)
	}
}

// TestPeerAddrParamsRoundTripsThroughTheKernel is the half a hand-written
// buffer cannot cover: that the layout matches what the kernel reads and
// writes, not just what this test thinks it is.
func TestPeerAddrParamsRoundTripsThroughTheKernel(t *testing.T) {
	client, _ := eorPair(t)

	var before PeerAddrParams
	if err := client.GetPeerAddrParams(&before); err != nil {
		t.Fatalf("GetPeerAddrParams: %v", err)
	}
	// The kernel's default heartbeat period. A wrong offset here reads some
	// other field, so this doubles as a check on the layout.
	if before.HBInterval == 0 {
		t.Errorf("HBInterval = 0; the kernel's default is 30000ms, so the "+
			"field is being read from the wrong offset (got %+v)", before)
	}

	const wantHB = 5000
	set := before
	set.HBInterval = wantHB
	set.Flags = SPP_HB_ENABLE
	if err := client.SetPeerAddrParams(&set); err != nil {
		t.Fatalf("SetPeerAddrParams: %v", err)
	}

	var after PeerAddrParams
	if err := client.GetPeerAddrParams(&after); err != nil {
		t.Fatalf("GetPeerAddrParams after set: %v", err)
	}
	if after.HBInterval != wantHB {
		t.Errorf("HBInterval = %d after setting %d; on an idle association "+
			"the heartbeat is the only thing that notices a silent path, and "+
			"its period was unreachable from this package before",
			after.HBInterval, wantHB)
	}
}

// TestGetPeerAddrInfoReportsThePath covers the getter for a struct that was
// defined and layout-pinned but had no way to be filled in.
//
// GetStatus reports the primary path only, so on a multi-homed association
// nothing else says whether a secondary path is active or what its round-trip
// time is.
func TestGetPeerAddrInfoReportsThePath(t *testing.T) {
	client, _ := eorPair(t)

	primary, err := client.SCTPGetPrimaryPeerAddr()
	if err != nil {
		t.Fatalf("SCTPGetPrimaryPeerAddr: %v", err)
	}

	info := &PeerAddrinfo{}
	copy(info.Address[:], primary.ToRawSockAddrBuf())
	if err := client.GetPeerAddrInfo(info); err != nil {
		t.Fatalf("GetPeerAddrInfo: %v", err)
	}
	if info.State != SCTP_ACTIVE {
		t.Errorf("primary path state = %v, want SCTP_ACTIVE", info.State)
	}
	if info.MTU == 0 {
		t.Errorf("MTU = 0 for an established association; the reply is not "+
			"being decoded (%+v)", info)
	}
}

// TestFeatureNegotiationOptionsRoundTrip covers the block of options at 123-131
// that had neither constants nor wrappers.
//
// They were invisible to the header sweep that produced the coverage claim,
// because that sweep looked for constants *referenced* in the package and a
// declared constant counts as referenced. These were not even declared.
func TestFeatureNegotiationOptionsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*SCTPConn, bool) error
		get  func(*SCTPConn) (bool, error)
	}{
		{"ASCONF", (*SCTPConn).SetAsconfSupported, (*SCTPConn).AsconfSupported},
		{"AUTH", (*SCTPConn).SetAuthSupported, (*SCTPConn).AuthSupported},
		{"ECN", (*SCTPConn).SetEcnSupported, (*SCTPConn).EcnSupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An unconnected socket: these are announced in the INIT, so they
			// can only be changed before the association exists.
			conn := unboundConn(t)

			if err := tc.set(conn, true); err != nil {
				t.Fatalf("enable: %v", err)
			}
			on, err := tc.get(conn)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if !on {
				t.Errorf("%s reads back off after being enabled", tc.name)
			}

			if err := tc.set(conn, false); err != nil {
				t.Fatalf("disable: %v", err)
			}
			if on, err = tc.get(conn); err != nil {
				t.Fatalf("read back: %v", err)
			}
			if on {
				t.Errorf("%s reads back on after being disabled", tc.name)
			}
		})
	}
}

// TestAuthSupportedDoesNotNeedTheSysctl is the measurement that contradicts
// this package's own documentation.
//
// The AUTH accessors are documented as needing net.sctp.auth_enable, which only
// root can set system-wide. SCTP_AUTH_SUPPORTED turns AUTH on for one socket
// instead. This test does not depend on the sysctl's value either way: it
// asserts the option is accepted and takes effect, which is the claim.
func TestAuthSupportedDoesNotNeedTheSysctl(t *testing.T) {
	conn := unboundConn(t)

	if err := conn.SetAuthSupported(true); err != nil {
		t.Fatalf("SetAuthSupported: %v; the per-socket option is what makes "+
			"AUTH usable without root editing net.sctp.auth_enable", err)
	}
	on, err := conn.AuthSupported()
	if err != nil {
		t.Fatalf("AuthSupported: %v", err)
	}
	if !on {
		t.Error("AUTH reads back off after SetAuthSupported(true)")
	}
}

// TestExposePotentiallyFailedRoundTrips covers the option that makes RFC 7829's
// PF state visible at all.
func TestExposePotentiallyFailedRoundTrips(t *testing.T) {
	conn := unboundConn(t)

	// Pin the numbers, not just the round trip. The kernel enum is
	// UNSET/DISABLE/ENABLE, so a constant block written as the more usual
	// off/on/locked shape puts "exposed" on the value that disables it — and a
	// round-trip test cannot tell, because the number written is the number
	// read back. These are checked against
	// include/net/sctp/constants.h SCTP_PF_EXPOSE_*.
	if SCTPPFStateUnset != 0 || SCTPPFStateDisabled != 1 || SCTPPFStateEnabled != 2 {
		t.Fatalf("PF exposure levels are unset=%d disabled=%d enabled=%d; the "+
			"kernel enum is 0, 1, 2 in that order",
			SCTPPFStateUnset, SCTPPFStateDisabled, SCTPPFStateEnabled)
	}

	for _, level := range []uint32{SCTPPFStateEnabled, SCTPPFStateDisabled} {
		if err := conn.SetExposePotentiallyFailed(level); err != nil {
			t.Fatalf("SetExposePotentiallyFailed(%d): %v", level, err)
		}
		got, err := conn.ExposePotentiallyFailed()
		if err != nil {
			t.Fatalf("ExposePotentiallyFailed: %v", err)
		}
		if got != level {
			t.Errorf("exposure level = %d after setting %d", got, level)
		}
	}
}

// TestStreamSchedulerRoundTrips covers RFC 8260 §4 scheduling.
//
// The default ignores streams entirely and sends in the order messages were
// handed over, so a caller who separates traffic by stream and expects that to
// affect scheduling gets nothing until this is set.
func TestStreamSchedulerRoundTrips(t *testing.T) {
	client, _ := eorPair(t)

	got, err := client.StreamScheduler()
	if err != nil {
		t.Fatalf("StreamScheduler: %v", err)
	}
	if got != SCTPSchedFCFS {
		t.Errorf("default scheduler = %d, want SCTPSchedFCFS (%d)", got, SCTPSchedFCFS)
	}

	if err := client.SetStreamScheduler(SCTPSchedPrio); err != nil {
		t.Fatalf("SetStreamScheduler(prio): %v", err)
	}
	if got, err = client.StreamScheduler(); err != nil {
		t.Fatalf("StreamScheduler: %v", err)
	}
	if got != SCTPSchedPrio {
		t.Fatalf("scheduler = %d after selecting prio (%d)", got, SCTPSchedPrio)
	}

	const stream, priority = 3, 7
	if err := client.SetStreamSchedulerValue(stream, priority); err != nil {
		t.Fatalf("SetStreamSchedulerValue: %v", err)
	}
	v, err := client.GetStreamSchedulerValue(stream)
	if err != nil {
		t.Fatalf("GetStreamSchedulerValue: %v", err)
	}
	if v != priority {
		t.Errorf("stream %d priority = %d, want %d", stream, v, priority)
	}
}

// TestBooleanSockoptsRoundTrip covers the two options that carry a bare int.
func TestBooleanSockoptsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*SCTPConn, bool) error
		get  func(*SCTPConn) (bool, error)
	}{
		{"DisableFragments", (*SCTPConn).SetDisableFragments, (*SCTPConn).DisableFragments},
		{"MappedV4Addr", (*SCTPConn).SetMappedV4Addr, (*SCTPConn).MappedV4Addr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := unboundConn(t)
			for _, want := range []bool{true, false} {
				if err := tc.set(conn, want); err != nil {
					t.Fatalf("set(%v): %v", want, err)
				}
				got, err := tc.get(conn)
				if err != nil {
					t.Fatalf("get: %v", err)
				}
				if got != want {
					t.Errorf("read back %v after setting %v", got, want)
				}
			}
		})
	}
}

// TestAdaptationLayerRoundTrips covers the sharpest asymmetry in the package
// before this: the peer's adaptation indication was parsed, with a size
// constant and a truncation test, while the local one could not be set.
func TestAdaptationLayerRoundTrips(t *testing.T) {
	conn := unboundConn(t)

	// Typed, not an untyped constant: 0xdeadbeef overflows int on a 32-bit
	// target, so an untyped one fails to compile for linux/arm and linux/386.
	// `go build` does not compile test files, which is why the CI vet job
	// covers those targets separately.
	var want uint32 = 0xdeadbeef
	if err := conn.SetAdaptationLayer(want); err != nil {
		t.Fatalf("SetAdaptationLayer: %v", err)
	}
	got, err := conn.GetAdaptationLayer()
	if err != nil {
		t.Fatalf("GetAdaptationLayer: %v", err)
	}
	if got != want {
		t.Errorf("adaptation indication = %#x, want %#x", got, want)
	}
}

// TestGetInitMsgReadsBackWhatWasSet covers the missing half of SCTP_INITMSG.
//
// A zero field in an InitMsg means "leave the default", so what was set and
// what is in force are different things, and without the getter there was no
// way to see the second.
func TestGetInitMsgReadsBackWhatWasSet(t *testing.T) {
	conn := unboundConn(t)

	want := InitMsg{NumOstreams: 7, MaxInstreams: 9, MaxAttempts: 3, MaxInitTimeout: 4000}
	if err := conn.SetInitMsg(int(want.NumOstreams), int(want.MaxInstreams),
		int(want.MaxAttempts), int(want.MaxInitTimeout)); err != nil {
		t.Fatalf("SetInitMsg: %v", err)
	}
	got, err := conn.GetInitMsg()
	if err != nil {
		t.Fatalf("GetInitMsg: %v", err)
	}
	if *got != want {
		t.Errorf("GetInitMsg = %+v, want %+v", *got, want)
	}
}

// TestSetInitMsgRejectsOutOfRangeValues covers the narrowing that used to be
// silent.
//
// Every SCTP_INITMSG field is a uint16. An int argument above that was
// truncated, and 65536 streams became 0 — which the kernel reads as "leave the
// default", so the caller got the opposite of what they asked for with no
// error.
func TestSetInitMsgRejectsOutOfRangeValues(t *testing.T) {
	conn := unboundConn(t)

	for _, tc := range []struct {
		name string
		args [4]int
	}{
		{"streams above uint16", [4]int{1 << 16, 0, 0, 0}},
		{"instreams above uint16", [4]int{0, 1 << 16, 0, 0}},
		{"attempts above uint16", [4]int{0, 0, 1 << 16, 0}},
		{"timeout above uint16", [4]int{0, 0, 0, 1 << 16}},
		{"negative", [4]int{-1, 0, 0, 0}},
	} {
		err := conn.SetInitMsg(tc.args[0], tc.args[1], tc.args[2], tc.args[3])
		if err == nil {
			t.Errorf("SetInitMsg%v returned no error; the value is truncated "+
				"to uint16 and a truncation to 0 means \"keep the default\"",
				tc.args)
		}
	}

	// The boundary itself must still be accepted.
	if err := conn.SetInitMsg(1<<16-1, 0, 0, 0); err != nil {
		t.Errorf("SetInitMsg with the largest valid value: %v", err)
	}
}

// TestPeelOffArgMatchesTheKernelABI pins the argument struct.
//
// Both members are 32 bits in the kernel, so it is 8 bytes with sd at offset 4.
// Declaring sd as Go's int made it 16 bytes with sd at offset 8 on every 64-bit
// target: the kernel wrote the descriptor at 4 and PeelOff read 8, which
// nothing had written, so it returned a connection wrapping descriptor 0 — the
// process's standard input — and leaked the real one. It was correct on 32-bit,
// where Go's int is 32 bits, and nothing tested it on either.
func TestPeelOffArgMatchesTheKernelABI(t *testing.T) {
	var arg peeloffArg
	if got := unsafe.Sizeof(arg); got != 8 {
		t.Errorf("sizeof(peeloffArg) = %d, kernel's sctp_peeloff_arg_t is 8", got)
	}
	if got := unsafe.Offsetof(arg.sd); got != 4 {
		t.Errorf("peeloffArg.sd at offset %d, kernel has sd at 4; PeelOff "+
			"would read a word the kernel never wrote", got)
	}
	if got := unsafe.Offsetof(arg.assocID); got != 0 {
		t.Errorf("peeloffArg.assocID at offset %d, want 0", got)
	}
}

// TestPeelOffRejectsAOneToOneSocket records what PeelOff does on the sockets
// this package creates.
//
// sctp_do_peeloff refuses any socket that is not one-to-many, so this is EINVAL
// for every connection made through Dial or Accept here. The method is usable
// through NewSCTPConn on a SOCK_SEQPACKET descriptor the caller made
// themselves. Asserting the refusal keeps the doc comment honest — and would
// catch a kernel that started allowing it, at which point the ABI above starts
// mattering for real.
func TestPeelOffRejectsAOneToOneSocket(t *testing.T) {
	client, _ := eorPair(t)

	conn, err := client.PeelOff(0)
	if err == nil {
		_ = conn.Close()
		t.Fatal("PeelOff succeeded on a one-to-one socket; the kernel is " +
			"expected to refuse that, and the doc comment says so")
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("PeelOff on a one-to-one socket = %v, want EINVAL", err)
	}
}

// unboundConn returns an SCTP socket with no association, for the options that
// are announced in the INIT and so can only be set beforehand.
func unboundConn(t *testing.T) *SCTPConn {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("cannot create an SCTP socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return NewSCTPConn(fd, nil)
}

// TestSendFlagsMatchTheKernel pins the per-message send flags.
//
// They were written as a contiguous iota block, which the kernel's are not:
// bits 4 and 5 belong to SCTP_PR_SCTP_MASK, and SCTP_EOF is MSG_FIN rather
// than a bit of its own. As the fifth iota, SCTP_EOF came out as 1<<4 — exactly
// SCTP_PR_SCTP_TTL. A caller asking for a graceful shutdown on their last
// message selected a partial reliability policy instead, and got neither the
// shutdown nor an error.
func TestSendFlagsMatchTheKernel(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"SCTP_UNORDERED", SCTP_UNORDERED, 0x0001},
		{"SCTP_ADDR_OVER", SCTP_ADDR_OVER, 0x0002},
		{"SCTP_ABORT", SCTP_ABORT, 0x0004},
		{"SCTP_SACK_IMMEDIATELY", SCTP_SACK_IMMEDIATELY, 0x0008},
		{"SCTP_SENDALL", SCTP_SENDALL, 0x0040},
		{"SCTP_PR_SCTP_ALL", SCTP_PR_SCTP_ALL, 0x0080},
		{"SCTP_EOF (MSG_FIN)", SCTP_EOF, 0x0200},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, kernel has %#x", tc.name, tc.got, tc.want)
		}
	}

	// The specific collision that was there: bits 4 and 5 are the partial
	// reliability policy, so nothing in this block may occupy them.
	const prPolicyMask = 0x0030
	for _, tc := range []struct {
		name string
		flag int
	}{
		{"SCTP_UNORDERED", SCTP_UNORDERED},
		{"SCTP_ADDR_OVER", SCTP_ADDR_OVER},
		{"SCTP_ABORT", SCTP_ABORT},
		{"SCTP_SACK_IMMEDIATELY", SCTP_SACK_IMMEDIATELY},
		{"SCTP_SENDALL", SCTP_SENDALL},
		{"SCTP_PR_SCTP_ALL", SCTP_PR_SCTP_ALL},
		{"SCTP_EOF", SCTP_EOF},
	} {
		if tc.flag&prPolicyMask != 0 {
			t.Errorf("%s (%#x) overlaps SCTP_PR_SCTP_MASK (%#x); setting it "+
				"selects a partial reliability policy instead",
				tc.name, tc.flag, prPolicyMask)
		}
	}
}

// TestSockaddrStorageOptionLayouts pins the four option structs whose layout
// depends on the word size.
//
// Most of the SCTP option structs carrying an address are declared
// packed, aligned(4), so they are identical everywhere. These four are not, and
// their sockaddr_storage keeps its natural alignment — which comes from the
// unsigned long inside it and so follows the pointer size. Measured with a C
// probe compiled for both:
//
//	                      linux/amd64      linux/arm/v7
//	sockaddr_storage      align 8          align 4
//	sctp_udpencaps        144, addr@8      136, addr@4
//	sctp_probeinterval    144, addr@8      136, addr@4
//	sctp_paddrthlds       144, addr@8      136, addr@4
//	sctp_paddrthlds_v2    144, addr@8      140, addr@4
//
// The previous version of this test asserted the 64-bit numbers unconditionally,
// so it passed on the development host and could never see the 32-bit case —
// while the package's implementation is tagged linux && !386 and so builds for
// linux/arm and linux/mips. The setters demand an exact optlen and would be
// refused there; the getters accept an oversized one and come back with the
// address read from the wrong offset and the trailing field untouched, which is
// silent.
func TestSockaddrStorageOptionLayouts(t *testing.T) {
	wantAddr := uintptr(8)
	sizes := map[string]uintptr{
		"sctp_udpencaps": 144, "sctp_probeinterval": 144,
		"sctp_paddrthlds": 144, "sctp_paddrthlds_v2": 144,
	}
	if unsafe.Sizeof(uintptr(0)) == 4 {
		wantAddr = 4
		sizes = map[string]uintptr{
			"sctp_udpencaps": 136, "sctp_probeinterval": 136,
			"sctp_paddrthlds": 136, "sctp_paddrthlds_v2": 140,
		}
	}

	if ssAddrOffset != wantAddr {
		t.Errorf("ssAddrOffset = %d, want %d on a %d-bit target",
			ssAddrOffset, wantAddr, unsafe.Sizeof(uintptr(0))*8)
	}
	if ssTailOffset != wantAddr+128 {
		t.Errorf("ssTailOffset = %d, want %d", ssTailOffset, wantAddr+128)
	}

	for _, tc := range []struct {
		name string
		got  uintptr
	}{
		{"sctp_udpencaps", udpEncapsSize},
		{"sctp_probeinterval", probeIntervalSize},
		{"sctp_paddrthlds", peerAddrThldsSize},
		{"sctp_paddrthlds_v2", peerAddrThldsV2Size},
	} {
		if want := sizes[tc.name]; tc.got != want {
			t.Errorf("%s marshalled size = %d, kernel struct is %d on this target",
				tc.name, tc.got, want)
		}
	}

	// The marshalled buffers must be exactly those sizes: the setters pass
	// len(b) as the option length, and every one of these options begins by
	// rejecting an optlen that is not exactly sizeof.
	for _, tc := range []struct {
		name string
		got  int
	}{
		{"sctp_udpencaps", len((&UDPEncaps{}).marshal())},
		{"sctp_probeinterval", len((&ProbeInterval{}).marshal())},
		{"sctp_paddrthlds", len((&PeerAddrThlds{}).marshal())},
		{"sctp_paddrthlds_v2", len((&PeerAddrThldsV2{}).marshal())},
	} {
		if want := int(sizes[tc.name]); tc.got != want {
			t.Errorf("%s marshal() produced %d bytes, want %d", tc.name, tc.got, want)
		}
	}
}

// TestSockaddrStorageLayoutFormula checks the arithmetic that derives the
// offsets against the C measurements, for both word sizes at once.
//
// TestSockaddrStorageOptionLayouts can only ever assert the target it was
// compiled for, so on a 64-bit host it cannot tell ssAlign = 8 from
// ssAlign = unsafe.Sizeof(uintptr(0)) — mutation confirms exactly that: pinning
// the alignment to 8 survives on amd64 and fails on arm. This recomputes the
// same formula for both alignments so at least a mistake in the formula is
// caught anywhere, and the numbers below are the C ones.
func TestSockaddrStorageLayoutFormula(t *testing.T) {
	// Measured with a C probe over <linux/sctp.h>, compiled for linux/amd64 and
	// linux/arm/v7.
	for _, tc := range []struct {
		align, addr, tail          uintptr
		udp, probe, thlds, thldsV2 uintptr
	}{
		{align: 4, addr: 4, tail: 132, udp: 136, probe: 136, thlds: 136, thldsV2: 140},
		{align: 8, addr: 8, tail: 136, udp: 144, probe: 144, thlds: 144, thldsV2: 144},
	} {
		round := func(n uintptr) uintptr { return (n + tc.align - 1) &^ (tc.align - 1) }
		addr := round(4)
		tail := addr + 128
		got := []struct {
			name      string
			got, want uintptr
		}{
			{"address offset", addr, tc.addr},
			{"tail offset", tail, tc.tail},
			{"sctp_udpencaps", round(tail + 2), tc.udp},
			{"sctp_probeinterval", round(tail + 4), tc.probe},
			{"sctp_paddrthlds", round(tail + 4), tc.thlds},
			{"sctp_paddrthlds_v2", round(tail + 6), tc.thldsV2},
		}
		for _, g := range got {
			if g.got != g.want {
				t.Errorf("align %d: %s = %d, kernel has %d", tc.align, g.name, g.got, g.want)
			}
		}

		// And the constants the package actually uses must agree with the row
		// matching this build.
		if tc.align != ssAlign {
			continue
		}
		for _, g := range got {
			switch g.name {
			case "address offset":
				if ssAddrOffset != g.want {
					t.Errorf("ssAddrOffset = %d, want %d", ssAddrOffset, g.want)
				}
			case "sctp_udpencaps":
				if udpEncapsSize != g.want {
					t.Errorf("udpEncapsSize = %d, want %d", udpEncapsSize, g.want)
				}
			case "sctp_paddrthlds_v2":
				if peerAddrThldsV2Size != g.want {
					t.Errorf("peerAddrThldsV2Size = %d, want %d", peerAddrThldsV2Size, g.want)
				}
			}
		}
	}
}

// TestSockaddrStorageOptionsRoundTripThroughBytes checks each marshaller against
// its own unmarshaller, with a distinct value per field.
//
// The offsets are derived rather than written down, so a mistake shifts every
// field after the address at once — which a single-field check would miss on
// whichever field happened to stay put.
func TestSockaddrStorageOptionsRoundTripThroughBytes(t *testing.T) {
	var addr [128]byte
	for i := range addr {
		addr[i] = byte(i)
	}

	t.Run("UDPEncaps", func(t *testing.T) {
		in := UDPEncaps{AssocID: 0x11223344, Address: addr, Port: 0x5566}
		var out UDPEncaps
		out.unmarshal(in.marshal())
		if out != in {
			t.Errorf("round trip changed the value:\n got %+v\nwant %+v", out.Port, in.Port)
		}
	})
	t.Run("ProbeInterval", func(t *testing.T) {
		in := ProbeInterval{AssocID: 0x11223344, Address: addr, Interval: 0x55667788}
		var out ProbeInterval
		out.unmarshal(in.marshal())
		if out != in {
			t.Errorf("round trip changed the value: interval %#x, want %#x",
				out.Interval, in.Interval)
		}
	})
	t.Run("PeerAddrThlds", func(t *testing.T) {
		in := PeerAddrThlds{AssocID: 0x11223344, Address: addr, PathMaxRxt: 0x5566, PathPfThld: 0x7788}
		var out PeerAddrThlds
		out.unmarshal(in.marshal())
		if out != in {
			t.Errorf("round trip changed the value: maxrxt %#x pf %#x, want %#x %#x",
				out.PathMaxRxt, out.PathPfThld, in.PathMaxRxt, in.PathPfThld)
		}
	})
	t.Run("PeerAddrThldsV2", func(t *testing.T) {
		in := PeerAddrThldsV2{AssocID: 0x11223344, Address: addr,
			PathMaxRxt: 0x5566, PathPfThld: 0x7788, PathCpThld: 0x99AA}
		var out PeerAddrThldsV2
		out.unmarshal(in.marshal())
		if out != in {
			t.Errorf("round trip changed the value: maxrxt %#x pf %#x cp %#x, want %#x %#x %#x",
				out.PathMaxRxt, out.PathPfThld, out.PathCpThld,
				in.PathMaxRxt, in.PathPfThld, in.PathCpThld)
		}
	})

	// The address must land where the kernel expects it, not merely somewhere
	// consistent — a round trip alone would pass with every offset wrong by the
	// same amount.
	b := (&UDPEncaps{Address: addr, Port: 0x5566}).marshal()
	if b[ssAddrOffset] != 0 || b[ssAddrOffset+1] != 1 {
		t.Errorf("address does not start at offset %d: bytes there are %#x %#x",
			ssAddrOffset, b[ssAddrOffset], b[ssAddrOffset+1])
	}
	if nativeEndian.Uint16(b[ssTailOffset:]) != 0x5566 {
		t.Errorf("port is not at offset %d", ssTailOffset)
	}
}

// TestUDPEncapsAndProbeIntervalRoundTrip exercises both against a live socket.
//
// These are the last two kernel options that apply to the one-to-one sockets
// this package creates and had no wrapper. RFC 6951 encapsulation is what lets
// an association cross a middlebox that drops IP protocol 132, which is most
// consumer NAT; RFC 8899 PLPMTUD is how a path finds its MTU without ICMP.
func TestUDPEncapsAndProbeIntervalRoundTrip(t *testing.T) {
	client, _ := eorPair(t)

	t.Run("udp encapsulation port", func(t *testing.T) {
		set := UDPEncaps{Port: 9899}
		if err := client.SetRemoteUDPEncapsPort(&set); err != nil {
			t.Skipf("SCTP_REMOTE_UDP_ENCAPS_PORT not usable here: %v", err)
		}
		got := UDPEncaps{}
		if err := client.GetRemoteUDPEncapsPort(&got); err != nil {
			t.Fatalf("GetRemoteUDPEncapsPort: %v", err)
		}
		if got.Port != set.Port {
			t.Errorf("encapsulation port = %d, want %d", got.Port, set.Port)
		}
	})

	t.Run("plpmtud probe interval", func(t *testing.T) {
		set := ProbeInterval{Interval: 5000}
		if err := client.SetProbeInterval(&set); err != nil {
			t.Skipf("SCTP_PLPMTUD_PROBE_INTERVAL not usable here: %v", err)
		}
		got := ProbeInterval{}
		if err := client.GetProbeInterval(&got); err != nil {
			t.Fatalf("GetProbeInterval: %v", err)
		}
		if got.Interval != set.Interval {
			t.Errorf("probe interval = %d, want %d", got.Interval, set.Interval)
		}
	})
}

// TestExposePotentiallyFailedHasNoLockedState pins the corrected claim.
//
// The doc comment used to say SCTPPFStateHiddenNoOverride locked the option and
// that a later change returned EACCES. Neither was true, and neither was
// measured: sctp_setsockopt_pf_expose rejects only a value above
// SCTP_PF_EXPOSE_ENABLE, with EINVAL, and has no locked state at all. The
// constant named there had also been renamed out of existence, so godoc showed a
// dangling identifier.
//
// A wrong doc comment is not caught by any of the round-trip tests, which is how
// an invented behaviour survived review. This asserts the real one.
func TestExposePotentiallyFailedHasNoLockedState(t *testing.T) {
	conn := unboundConn(t)

	// Every order, including returning to a level already used. If any level
	// locked the option, one of these would fail.
	for _, level := range []uint32{
		SCTPPFStateEnabled, SCTPPFStateDisabled, SCTPPFStateEnabled,
		SCTPPFStateUnset, SCTPPFStateEnabled, SCTPPFStateUnset,
	} {
		if err := conn.SetExposePotentiallyFailed(level); err != nil {
			t.Fatalf("SetExposePotentiallyFailed(%d) after earlier changes: %v; "+
				"the option is not supposed to lock", level, err)
		}
		got, err := conn.ExposePotentiallyFailed()
		if err != nil {
			t.Fatalf("ExposePotentiallyFailed: %v", err)
		}
		if got != level {
			t.Fatalf("level = %d after setting %d", got, level)
		}
	}

	// A value above the maximum is the one thing it does reject, and with
	// EINVAL rather than EACCES.
	err := conn.SetExposePotentiallyFailed(SCTPPFStateEnabled + 1)
	if err == nil {
		t.Fatal("an out-of-range exposure level was accepted")
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("out-of-range level = %v, want EINVAL", err)
	}
}
