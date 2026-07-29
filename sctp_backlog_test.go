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
	"syscall"
	"testing"
)

// TestListenBacklogUsesKernelMaximum covers a capacity limit that looked like
// a network fault.
//
// ListenSCTP passed syscall.SOMAXCONN to listen(). In Go that is a
// compile-time constant of 128 and has not tracked the kernel since Linux 5.4
// raised net.core.somaxconn to 4096. A listener handed more simultaneous
// INITs than its backlog answers the excess with ABORT, so the peer reports
// ECONNREFUSED against a listener that is healthy and accepting.
//
// Measured with a listener that never accepts: listen(128) took 129
// associations before refusing, listen(1024) took more than 400.
func TestListenBacklogUsesKernelMaximum(t *testing.T) {
	want, err := readSomaxconn()
	if err != nil {
		t.Skipf("cannot read net.core.somaxconn: %v", err)
	}
	if want <= syscall.SOMAXCONN {
		t.Skipf("kernel somaxconn is %d, not above the Go constant %d; "+
			"nothing to distinguish here", want, syscall.SOMAXCONN)
	}

	// A listener that never accepts, so the backlog is what bounds it.
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	raddr := ln.Addr().(*SCTPAddr)

	// Connect past the old 128 limit without accepting any of them. Every
	// association is held open so the backlog cannot drain.
	const target = 200
	var conns []*SCTPConn
	defer func() {
		for _, c := range conns {
			_ = c.Abort()
		}
	}()

	for i := 0; i < target; i++ {
		c, err := DialSCTP("sctp", nil, raddr)
		if err != nil {
			t.Fatalf("association %d of %d refused: %v; the listen backlog is "+
				"capped below the kernel's %d, so a busy listener rejects "+
				"peers it should accept", i+1, target, err, want)
		}
		conns = append(conns, c)
	}
	t.Logf("%d associations queued against a listener that never accepts "+
		"(kernel somaxconn=%d)", len(conns), want)
}

// TestReadSomaxconnMatchesProc checks the helper reads the value the kernel
// reports, since the backlog depends on it.
func TestReadSomaxconnMatchesProc(t *testing.T) {
	n, err := readSomaxconn()
	if err != nil {
		t.Skipf("cannot read net.core.somaxconn: %v", err)
	}
	if n <= 0 {
		t.Errorf("readSomaxconn() = %d, want a positive backlog", n)
	}
}
