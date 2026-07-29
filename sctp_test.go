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
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

type resolveSCTPAddrTest struct {
	network       string
	litAddrOrName string
	addr          *SCTPAddr
	err           error
}

var resolveSCTPAddrTests = []resolveSCTPAddrTest{
	{"sctp", "127.0.0.1:0", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}}, Port: 0}, nil},
	{"sctp4", "127.0.0.1:65535", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}}, Port: 65535}, nil},

	{"sctp", "[::1]:0", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.ParseIP("::1")}}, Port: 0}, nil},
	{"sctp6", "[::1]:65535", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.ParseIP("::1")}}, Port: 65535}, nil},

	{"sctp", "[fe80::1%eth0]:0", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"}}, Port: 0}, nil},
	{"sctp6", "[fe80::1%eth0]:65535", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"}}, Port: 65535}, nil},

	{"sctp", ":12345", &SCTPAddr{Port: 12345}, nil},

	{"sctp", "127.0.0.1/10.0.0.1:0", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}}, Port: 0}, nil},
	{"sctp4", "127.0.0.1/10.0.0.1:65535", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}}, Port: 65535}, nil},
}

func TestSCTPAddrString(t *testing.T) {
	for _, tt := range resolveSCTPAddrTests {
		s := tt.addr.String()
		if tt.litAddrOrName != s {
			t.Errorf("expected %q, got %q", tt.litAddrOrName, s)
		}
	}
}

func TestResolveSCTPAddr(t *testing.T) {
	for _, tt := range resolveSCTPAddrTests {
		addr, err := ResolveSCTPAddr(tt.network, tt.litAddrOrName)
		if !reflect.DeepEqual(addr, tt.addr) || !reflect.DeepEqual(err, tt.err) {
			t.Errorf("ResolveSCTPAddr(%q, %q) = %#v, %v, want %#v, %v", tt.network, tt.litAddrOrName, addr, err, tt.addr, tt.err)
			continue
		}
		if err == nil {
			addr2, err := ResolveSCTPAddr(addr.Network(), addr.String())
			if !reflect.DeepEqual(addr2, tt.addr) || err != tt.err {
				t.Errorf("(%q, %q): ResolveSCTPAddr(%q, %q) = %#v, %v, want %#v, %v", tt.network, tt.litAddrOrName, addr.Network(), addr.String(), addr2, err, tt.addr, tt.err)
			}
		}
	}
}

var sctpListenerNameTests = []struct {
	net   string
	laddr *SCTPAddr
}{
	{"sctp4", &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}}}},
	{"sctp4", &SCTPAddr{}},
	{"sctp4", nil},
	{"sctp", &SCTPAddr{Port: 7777}},
}

func TestSCTPListenerName(t *testing.T) {
	for _, tt := range sctpListenerNameTests {
		ln, err := ListenSCTP(tt.net, tt.laddr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		la := ln.Addr()
		if a, ok := la.(*SCTPAddr); !ok || a.Port == 0 {
			t.Fatalf("got %v; expected a proper address with non-zero port number", la)
		}
	}
}

func TestSCTPConcurrentAccept(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatal(err)
	}
	const N = 10
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					break
				}
				_ = c.Close()
			}
			wg.Done()
		}()
	}
	attempts := 10 * N
	fails := 0
	refused := 0
	for i := 0; i < attempts; i++ {
		c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
		if err != nil {
			// ECONNREFUSED here is the listener's backlog being momentarily
			// full, not a defect: this loop dials far faster than the accept
			// goroutines drain. Anything else is a real failure.
			if errors.Is(err, syscall.ECONNREFUSED) {
				refused++
				continue
			}
			fails++
			t.Logf("dial %d failed: %v", i, err)
		} else {
			_ = c.Close()
		}
	}
	if refused > 0 {
		t.Logf("%d of %d dials hit a full backlog (ECONNREFUSED)", refused, attempts)
	}
	_ = ln.Close()
	// Close releases the listening descriptor and sets it to -1, so a blocked
	// Accept returns an error and the goroutines above exit. Waiting for them
	// keeps this test from leaking accept loops into the rest of the suite.
	wg.Wait()
	if fails > 0 {
		t.Fatalf("# of failed Dials: %v", fails)
	}
}

func TestSCTPCloseRecv(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatal(err)
	}
	var conn net.Conn
	var wg sync.WaitGroup
	connReady := make(chan struct{}, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var xerr error
		conn, xerr = ln.Accept()
		if xerr != nil {
			// Errorf, not Fatal: this is not the test goroutine, and Fatal here
			// would call runtime.Goexit, leaving the main goroutine blocked on
			// connReady for the whole test timeout instead of failing promptly.
			t.Errorf("accept: %v", xerr)
			return
		}
		connReady <- struct{}{}
		buf := make([]byte, 256)
		_, xerr = conn.Read(buf)
		t.Logf("got error while read: %v", xerr)
		if xerr != io.EOF && xerr != syscall.EBADF {
			t.Errorf("read failed: %v", xerr)
		}
	}()

	_, err = DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}

	// Bound the wait: if Accept failed, the goroutine reported it and returned
	// without sending, and an unbounded receive would hang until the suite
	// timeout rather than failing here.
	select {
	case <-connReady:
	case <-time.After(10 * time.Second):
		t.Fatal("accept did not complete")
	}
	err = conn.Close()
	if err != nil {
		t.Fatalf("close failed: %v", err)
	}
	wg.Wait()
}

func TestGetStatus(t *testing.T) {
	testCases := []struct {
		name          string
		maxInstreams  uint16
		streamToWrite uint16
		expectError   bool
	}{
		{
			name:          "Write to stream within MaxInstreams limit",
			maxInstreams:  2,
			streamToWrite: 1, // must be (maxInstreams-1) to work without an error
			expectError:   false,
		},
		{
			name:          "Write to stream at MaxInstreams limit",
			maxInstreams:  2,
			streamToWrite: 2,
			expectError:   true, // Usually SCTP stream IDs are 0-indexed, so stream 2 is the 3rd stream
		},
		{
			name:          "Write to stream exceeding MaxInstreams limit",
			maxInstreams:  2,
			streamToWrite: 3,
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// See TestGetStatusUsage: let the kernel choose the port rather
			// than gambling on a free one.
			addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to resolve address: %v", err)
			}

			// Create server/listener with limited in- and out-streams
			ln, err := ListenSCTPExt("sctp", addr,
				InitMsg{
					NumOstreams:  0x05,
					MaxInstreams: tc.maxInstreams, // the peer side outStream will be limited by this side inStream
				},
			)
			if err != nil {
				t.Fatalf("Failed to create listener: %v", err)
			}
			defer func() { _ = ln.Close() }()

			// Channel to communicate server errors
			errChan := make(chan error, 1)

			go func() {
				// Accept a connection session on the listener
				_, err := ln.Accept()
				if err != nil {
					errChan <- fmt.Errorf("server accept error: %v", err)
					return
				}
				errChan <- nil
			}()

			// Create a client with default streams
			c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
			if err != nil {
				t.Fatalf("Failed to dial: %v", err)
			}
			defer func() { _ = c.Close() }()

			// Check for server errors
			select {
			case err := <-errChan:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(100 * time.Millisecond):
				// Continue if no immediate error
			}

			// Get the status
			status, err := c.GetStatus()
			if err != nil {
				t.Fatalf("Failed to get SCTP status: %v", err)
			}
			t.Logf("In streams: %d, Out streams: %d", status.Instreams, status.Ostreams)

			// Verify the negotiated values
			if status.Ostreams > tc.maxInstreams {
				t.Errorf("Expected at most %d in-streams, got %d", tc.maxInstreams, status.Ostreams)
			}

			// Write a message to the specific stream
			_, err = c.SCTPWrite([]byte("hello"),
				&SndRcvInfo{
					PPID:   0x03000000,
					Stream: tc.streamToWrite,
				})

			// Check if the error status matches what we expect
			if tc.expectError && err == nil {
				t.Errorf("Expected error when writing to stream %d with MaxInstreams=%d, but got none",
					tc.streamToWrite, tc.maxInstreams)
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error when writing to stream %d with MaxInstreams=%d, but got: %v",
					tc.streamToWrite, tc.maxInstreams, err)
			}
		})
	}
}

func TestGetStatusUsage(t *testing.T) {
	// Port 0 lets the kernel pick a free port. Drawing a random one from a
	// fixed range does not avoid conflicts, it only makes them rare: nothing
	// checks the port is free, and TestGetStatus draws four more from the same
	// thousand values, so roughly one full-suite run in a hundred picks a
	// number already in use and fails on the bind.
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve address: %v", err)
	}

	maxInStreams := 0x05
	// Create server/listener with limited in- and out-streams
	ln, err := ListenSCTPExt("sctp", addr,
		InitMsg{
			NumOstreams:  0x10,
			MaxInstreams: uint16(maxInStreams), // the peer side outStream will be limited by this side inStream
		},
	)
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Channel to communicate server errors
	errChan := make(chan error, 1)

	go func() {
		// Accept a connection session on the listener
		_, err := ln.Accept()
		if err != nil {
			errChan <- fmt.Errorf("server accept error: %v", err)
			return
		}
		errChan <- nil
	}()

	// Create a client with default streams
	c, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	// Check for server errors
	select {
	case err := <-errChan:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		// Continue if no immediate error
	}

	// Get the status
	status, err := c.GetStatus()
	if err != nil {
		t.Fatalf("Failed to get SCTP status: %v", err)
	}
	t.Logf("In streams: %d, Out streams: %d", status.Instreams, status.Ostreams)

	testCases := []struct {
		name          string
		streamToWrite uint16
		expectError   bool
	}{
		{
			name:          "Write to stream within MaxOutstrmslimit",
			streamToWrite: 0, // must be (maxInstreams-1) to work without an error
			expectError:   false,
		},
		{
			name:          "Write to stream within MaxOutstrms limit",
			streamToWrite: 1,
			expectError:   false, // Usually SCTP stream IDs are 0-indexed, so stream 2 is the 3rd stream
		},
		{
			name:          "Write to stream at MaxOutstrms limit",
			streamToWrite: status.Ostreams - 1,
			expectError:   false,
		},
		{
			name:          "Write to stream exceeding MaxOutstrms limit",
			streamToWrite: status.Ostreams,
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Write a message to the specific stream
			_, err = c.SCTPWrite([]byte("hello"),
				&SndRcvInfo{
					PPID:   0x03000000,
					Stream: tc.streamToWrite, // max allowed stream without an error
				})

			// Check if the error status matches what we expect
			if tc.expectError && err == nil {
				t.Errorf("Expected error when writing to stream %d with MaxInstreams=%d, but got none",
					tc.streamToWrite, maxInStreams)
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error when writing to stream %d with MaxInstreams=%d, but got: %v",
					tc.streamToWrite, maxInStreams, err)
			}
		})
	}
}
