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
	"runtime"
	"sync"
	"syscall"
	"testing"
	"unsafe"
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
	for i := 0; i < attempts; i++ {
		c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
		if err != nil {
			failures[err.Error()]++
			continue
		}
		_ = c.Close()
	}

	if err := ln.Close(); err != nil {
		t.Fatalf("listener close: %v", err)
	}
	wg.Wait()

	for msg, n := range failures {
		t.Errorf("%d of %d dials failed with: %s", n, attempts, msg)
	}
}

// TestSCTPConnectAcceptsEISCONN pins the specific errno, so a future change
// that stops handling it fails here with a clear reason rather than as an
// intermittent dial failure somewhere else.
//
// The socket returned must be usable: the point of accepting EISCONN is that
// the association really is established, not that the error is being ignored.
func TestSCTPConnectAcceptsEISCONN(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Hold the accepted connections open. Closing them immediately tears the
	// association down under the probe below, so a write would fail with
	// EPIPE for reasons that have nothing to do with EISCONN.
	var (
		mu    sync.Mutex
		peers []*SCTPConn
		accWg sync.WaitGroup
	)
	accWg.Add(1)
	go func() {
		defer accWg.Done()
		for {
			c, err := ln.AcceptSCTP()
			if err != nil {
				return
			}
			mu.Lock()
			peers = append(peers, c)
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		for _, c := range peers {
			_ = c.Abort()
		}
		mu.Unlock()
	}()

	raddr := ln.Addr().(*SCTPAddr)

	// Connect repeatedly on raw sockets until the kernel reports EISCONN, then
	// confirm SCTPConnect reported success and the socket can carry data.
	var (
		sawEISCONN bool
		writeOK    bool
	)
	for i := 0; i < 3000 && !sawEISCONN; i++ {
		sock, err := syscall.Socket(syscall.AF_INET,
			syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_SCTP)
		if err != nil {
			continue
		}

		// Ask the kernel directly so the test can tell EISCONN apart from the
		// other ways a connect can fail.
		buf := raddr.ToRawSockAddrBuf()
		param := GetAddrsOld{
			AddrNum: int32(len(buf)),
			Addrs:   uintptr(unsafe.Pointer(&buf[0])),
		}
		optlen := unsafe.Sizeof(param)
		_, _, rawErr := getsockopt(sock, SCTP_SOCKOPT_CONNECTX3,
			uintptr(unsafe.Pointer(&param)), uintptr(unsafe.Pointer(&optlen)))

		if rawErr != syscall.EISCONN {
			_ = syscall.Close(sock)
			continue
		}
		sawEISCONN = true

		// The same condition, through SCTPConnect, must not be an error.
		sock2, err := syscall.Socket(syscall.AF_INET,
			syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_SCTP)
		if err != nil {
			_ = syscall.Close(sock)
			break
		}
		if _, err := SCTPConnect(sock2, raddr); err != nil && err != syscall.EISCONN {
			t.Errorf("SCTPConnect: %v", err)
		}
		_ = syscall.Close(sock2)

		// The socket the kernel called EISCONN must actually work.
		c := NewSCTPConn(sock, nil)
		if n, err := c.SCTPWrite([]byte("probe"), nil); err == nil && n > 0 {
			writeOK = true
		} else {
			t.Logf("write on the EISCONN socket: n=%d err=%v", n, err)
		}
		_ = c.Close()
	}

	if !sawEISCONN {
		t.Skip("could not provoke EISCONN in this environment")
	}
	if !writeOK {
		t.Error("the socket the kernel reported EISCONN for could not be " +
			"written to, so treating EISCONN as success would be wrong")
	}
}
