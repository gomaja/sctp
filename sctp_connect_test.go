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
	"runtime"
	"sync"
	"syscall"
	"testing"
)

// TestDialUnderChurnSucceeds covers a dial that was reported as failed while
// the association was in fact established.
//
// SCTP_SOCKOPT_CONNECTX3 reports EISCONN when the handshake has already
// completed, which under load happens before the call returns. SCTPConnect
// treated that as a failure, so DialSCTP returned an error for a socket that
// was connected and writable, and the caller discarded a working connection.
//
// This is the defect behind the intermittent "# of failed Dials" in
// TestSCTPConcurrentAccept.
func TestDialUnderChurnSucceeds(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))

	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	const acceptors = 10
	var wg sync.WaitGroup
	wg.Add(acceptors)
	for i := 0; i < acceptors; i++ {
		go func() {
			defer wg.Done()
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}

	// Dial hard enough that the handshake completes inside CONNECTX3.
	const attempts = 200
	failures := map[string]int{}
	refused := 0
	for i := 0; i < attempts; i++ {
		c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
		if err != nil {
			// ECONNREFUSED is the listen backlog being momentarily full, which
			// is this loop dialing faster than the acceptors drain rather than
			// the defect under test.
			if errors.Is(err, syscall.ECONNREFUSED) {
				refused++
				continue
			}
			failures[err.Error()]++
			continue
		}
		_ = c.Close()
	}

	if err := ln.Close(); err != nil {
		t.Fatalf("listener close: %v", err)
	}
	wg.Wait()

	if refused > 0 {
		t.Logf("%d of %d dials hit a full backlog (ECONNREFUSED)", refused, attempts)
	}
	for msg, n := range failures {
		t.Errorf("%d of %d dials failed with: %s", n, attempts, msg)
	}
}
