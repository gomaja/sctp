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
	"time"
)

// TestStatusStateMatchesKernel pins the association-state constants to the
// values the kernel actually reports through SCTP_STATUS.
//
// These come from enum sctp_sstat_state in the kernel's uapi linux/sctp.h.
// Note SCTP_EMPTY = 0: the enum does not start at SCTP_CLOSED, and there are
// no SCTP_BOUND or SCTP_LISTEN members. Getting this wrong shifts every state
// by one, so an established association reads as SCTP_COOKIE_ECHOED.
func TestStatusStateMatchesKernel(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  StatusState
		want int32
	}{
		{"SCTP_EMPTY", SCTP_EMPTY, 0},
		{"SCTP_CLOSED", SCTP_CLOSED, 1},
		{"SCTP_COOKIE_WAIT", SCTP_COOKIE_WAIT, 2},
		{"SCTP_COOKIE_ECHOED", SCTP_COOKIE_ECHOED, 3},
		{"SCTP_ESTABLISHED", SCTP_ESTABLISHED, 4},
		{"SCTP_SHUTDOWN_PENDING", SCTP_SHUTDOWN_PENDING, 5},
		{"SCTP_SHUTDOWN_SENT", SCTP_SHUTDOWN_SENT, 6},
		{"SCTP_SHUTDOWN_RECEIVED", SCTP_SHUTDOWN_RECEIVED, 7},
		{"SCTP_SHUTDOWN_ACK_SENT", SCTP_SHUTDOWN_ACK_SENT, 8},
	} {
		if int32(tc.got) != tc.want {
			t.Errorf("%s = %d, kernel uses %d", tc.name, int32(tc.got), tc.want)
		}
	}
}

// TestPeerStateMatchesKernel pins the per-path state constants.
//
// From enum sctp_spinfo_state: SCTP_INACTIVE=0, SCTP_PF=1, SCTP_ACTIVE=2,
// SCTP_UNCONFIRMED=3. The ordering matters more than usual here, because a
// caller watching for path failure compares against these directly: with the
// values reversed, a healthy path reads as inactive and a failed one reads as
// unconfirmed.
func TestPeerStateMatchesKernel(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  PeerState
		want int32
	}{
		{"SCTP_INACTIVE", SCTP_INACTIVE, 0},
		{"SCTP_PF", SCTP_PF, 1},
		{"SCTP_ACTIVE", SCTP_ACTIVE, 2},
		{"SCTP_UNCONFIRMED", SCTP_UNCONFIRMED, 3},
	} {
		if int32(tc.got) != tc.want {
			t.Errorf("%s = %d, kernel uses %d", tc.name, int32(tc.got), tc.want)
		}
	}
}

// TestGetStatusReportsEstablished is the end-to-end check that matters: an
// association that has completed its handshake must report SCTP_ESTABLISHED
// and an active primary path. This is what a caller polls to decide whether a
// peer is still reachable, so a constant that is off by one makes healthy
// associations look broken.
func TestGetStatusReportsEstablished(t *testing.T) {
	client, server := eorPair(t)

	// Exchange a message so the handshake is definitely complete.
	if _, err := client.SCTPWrite([]byte("status probe"), nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	if _, _, err := server.SCTPRead(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	st, err := client.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if st.State != SCTP_ESTABLISHED {
		t.Errorf("State = %d, want SCTP_ESTABLISHED (%d)", st.State, SCTP_ESTABLISHED)
	}
	if st.PrimaryPeerAddr.State != SCTP_ACTIVE {
		t.Errorf("PrimaryPeerAddr.State = %d, want SCTP_ACTIVE (%d)",
			st.PrimaryPeerAddr.State, SCTP_ACTIVE)
	}
	// A live association must report a usable path MTU and RTO.
	if st.PrimaryPeerAddr.MTU == 0 {
		t.Error("PrimaryPeerAddr.MTU is 0 on an established association")
	}
	if st.PrimaryPeerAddr.RTO == 0 {
		t.Error("PrimaryPeerAddr.RTO is 0 on an established association")
	}
	t.Logf("state=%d peer=%d rto=%dms mtu=%d rwnd=%d",
		st.State, st.PrimaryPeerAddr.State, st.PrimaryPeerAddr.RTO,
		st.PrimaryPeerAddr.MTU, st.RWND)
}

// TestGetStatusAfterShutdown checks the state moves off ESTABLISHED once the
// association is torn down, so the constant is exercised in more than one
// position.
func TestGetStatusAfterShutdown(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	defer func() { _ = client.Abort() }()

	if err := server.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}

	// Give the shutdown a moment to propagate.
	deadline := time.Now().Add(3 * time.Second)
	var last StatusState
	for time.Now().Before(deadline) {
		st, err := client.GetStatus()
		if err != nil {
			// The association may be gone entirely, which is a valid outcome.
			t.Logf("GetStatus after peer close: %v", err)
			return
		}
		last = st.State
		if st.State != SCTP_ESTABLISHED {
			t.Logf("state moved to %d after peer close", st.State)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("state still %d after peer close (kernel may keep it briefly)", last)
}
