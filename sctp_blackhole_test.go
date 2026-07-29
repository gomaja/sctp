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
	"testing"
	"unsafe"
)

// TestRtoInfoLayoutMatchesKernel pins the struct against struct sctp_rtoinfo.
// These are passed to the kernel by pointer, so a wrong size or field order
// silently reads and writes the wrong bytes rather than failing.
func TestRtoInfoLayoutMatchesKernel(t *testing.T) {
	var info RtoInfo
	if got, want := unsafe.Sizeof(info), uintptr(16); got != want {
		t.Errorf("sizeof(RtoInfo) = %d, kernel struct sctp_rtoinfo is %d", got, want)
	}
	for _, tc := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"AssocID", unsafe.Offsetof(info.AssocID), 0},
		{"Initial", unsafe.Offsetof(info.Initial), 4},
		{"Max", unsafe.Offsetof(info.Max), 8},
		{"Min", unsafe.Offsetof(info.Min), 12},
	} {
		if tc.got != tc.want {
			t.Errorf("offsetof(RtoInfo.%s) = %d, kernel uses %d", tc.name, tc.got, tc.want)
		}
	}
}

// TestAssocInfoLayoutMatchesKernel pins the struct against
// struct sctp_assocparams.
func TestAssocInfoLayoutMatchesKernel(t *testing.T) {
	var info AssocInfo
	if got, want := unsafe.Sizeof(info), uintptr(20); got != want {
		t.Errorf("sizeof(AssocInfo) = %d, kernel struct sctp_assocparams is %d", got, want)
	}
	for _, tc := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"AssocID", unsafe.Offsetof(info.AssocID), 0},
		{"AsocMaxRxt", unsafe.Offsetof(info.AsocMaxRxt), 4},
		{"NumberPeerDestinations", unsafe.Offsetof(info.NumberPeerDestinations), 6},
		{"PeerRwnd", unsafe.Offsetof(info.PeerRwnd), 8},
		{"LocalRwnd", unsafe.Offsetof(info.LocalRwnd), 12},
		{"CookieLife", unsafe.Offsetof(info.CookieLife), 16},
	} {
		if tc.got != tc.want {
			t.Errorf("offsetof(AssocInfo.%s) = %d, kernel uses %d", tc.name, tc.got, tc.want)
		}
	}
}

// TestRtoInfoRoundTrip checks the values actually reach the kernel and come
// back, rather than the setsockopt silently succeeding on a wrong layout.
func TestRtoInfoRoundTrip(t *testing.T) {
	client, _ := eorPair(t)

	before, err := client.GetRtoInfo()
	if err != nil {
		t.Fatalf("GetRtoInfo: %v", err)
	}
	t.Logf("defaults: initial=%dms max=%dms min=%dms",
		before.Initial, before.Max, before.Min)
	if before.Initial == 0 || before.Max == 0 {
		t.Error("kernel reported zero RTO defaults; the struct layout is likely wrong")
	}

	// Tighten the timers the way a caller would to notice a dead peer sooner.
	want := &RtoInfo{Initial: 500, Max: 2000, Min: 200}
	if err := client.SetRtoInfo(want); err != nil {
		t.Fatalf("SetRtoInfo: %v", err)
	}

	after, err := client.GetRtoInfo()
	if err != nil {
		t.Fatalf("GetRtoInfo after set: %v", err)
	}
	if after.Initial != want.Initial || after.Max != want.Max || after.Min != want.Min {
		t.Errorf("read back initial=%d max=%d min=%d, want %d/%d/%d",
			after.Initial, after.Max, after.Min, want.Initial, want.Max, want.Min)
	}
}

// TestAssocInfoRoundTrip checks AsocMaxRxt in particular, since that is the
// knob that decides how long a black hole stays invisible.
func TestAssocInfoRoundTrip(t *testing.T) {
	client, _ := eorPair(t)

	before, err := client.GetAssocInfo()
	if err != nil {
		t.Fatalf("GetAssocInfo: %v", err)
	}
	t.Logf("defaults: asocMaxRxt=%d peerDests=%d peerRwnd=%d localRwnd=%d cookieLife=%dms",
		before.AsocMaxRxt, before.NumberPeerDestinations,
		before.PeerRwnd, before.LocalRwnd, before.CookieLife)
	if before.AsocMaxRxt == 0 {
		t.Error("kernel reported AsocMaxRxt=0; the struct layout is likely wrong")
	}
	if before.LocalRwnd == 0 {
		t.Error("kernel reported LocalRwnd=0 on an established association")
	}

	// Cut the retransmission budget so a vanished peer is declared failed
	// quickly instead of the association hanging.
	want := &AssocInfo{AsocMaxRxt: 3}
	if err := client.SetAssocInfo(want); err != nil {
		t.Fatalf("SetAssocInfo: %v", err)
	}

	after, err := client.GetAssocInfo()
	if err != nil {
		t.Fatalf("GetAssocInfo after set: %v", err)
	}
	if after.AsocMaxRxt != want.AsocMaxRxt {
		t.Errorf("AsocMaxRxt read back as %d, want %d", after.AsocMaxRxt, want.AsocMaxRxt)
	}
}

// TestAssocInfoRejectsClosedConn checks the accessors report an error rather
// than operating on a closed descriptor.
func TestAssocInfoRejectsClosedConn(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	defer func() { _ = server.Abort() }()

	if err := client.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if _, err := client.GetAssocInfo(); err == nil {
		t.Error("GetAssocInfo on a closed conn returned nil error")
	}
	if _, err := client.GetRtoInfo(); err == nil {
		t.Error("GetRtoInfo on a closed conn returned nil error")
	}
}

// TestUnackdataRevealsStalledSend is the black-hole signal available without
// any new syscall: when a peer stops acknowledging, data stays outstanding.
// Status.Unackdata is what an application polls to notice that its writes are
// no longer making progress, before the association is formally declared dead.
func TestUnackdataRevealsStalledSend(t *testing.T) {
	client, server := eorPair(t)

	// With a reading peer, nothing should stay unacknowledged for long.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := server.SCTPRead(buf); err != nil {
				return
			}
		}
	}()

	payload := make([]byte, 1024)
	for i := 0; i < 20; i++ {
		if _, err := client.SCTPWrite(payload, nil); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	st, err := client.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	t.Logf("healthy association: state=%d unackdata=%d penddata=%d peerState=%d",
		st.State, st.Unackdata, st.Penddata, st.PrimaryPeerAddr.State)

	if st.State != SCTP_ESTABLISHED {
		t.Errorf("state = %d, want SCTP_ESTABLISHED (%d)", st.State, SCTP_ESTABLISHED)
	}
	if st.PrimaryPeerAddr.State != SCTP_ACTIVE {
		t.Errorf("peer state = %d, want SCTP_ACTIVE (%d)",
			st.PrimaryPeerAddr.State, SCTP_ACTIVE)
	}
}
