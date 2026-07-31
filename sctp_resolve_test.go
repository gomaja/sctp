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
	"strings"
	"testing"
)

// TestResolveSCTPAddrRejectsMalformedInput covers the negative paths of the
// package's main untrusted-string entry point.
//
// The existing table expected a nil error from every case, so four error
// branches had never been reached, and two inputs produced an address that was
// wrong rather than refused:
//
//   - "1.2.3.4/5.6.7.8/:80" returned an empty address list with port 80, which
//     binds the wildcard. Every address the caller explicitly named was
//     discarded, with no error — so a trailing separator in a configuration file
//     turns "listen on these two" into "listen on everything".
//   - "/127.0.0.1:80" returned a nil IP followed by the real one, which binds
//     0.0.0.0 as well as the address named.
//
// The multi-homing slash syntax is this package's own invention, so nothing else
// validates it.
func TestResolveSCTPAddrRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
	}{
		{"trailing separator before the port", "1.2.3.4/5.6.7.8/:80"},
		{"leading separator", "/127.0.0.1:80"},
		{"empty element in the middle", "1.2.3.4//5.6.7.8:80"},
		{"port out of range", "127.0.0.1:99999"},
		{"no port at all", "127.0.0.1"},
		{"not an address", "!!!:80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := ResolveSCTPAddr("sctp", tc.addr)
			if err == nil {
				t.Fatalf("ResolveSCTPAddr(%q) = %v with no error; it should be "+
					"refused rather than turned into an address the caller did "+
					"not ask for", tc.addr, addr)
			}
		})
	}
}

// TestResolveSCTPAddrAcceptsTheDocumentedForms is the other half: the fix must
// not narrow what already worked.
func TestResolveSCTPAddrAcceptsTheDocumentedForms(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		addr    string
		ips     []string
		port    int
	}{
		{"bare port is the wildcard", "sctp", ":80", nil, 80},
		{"one address", "sctp", "127.0.0.1:80", []string{"127.0.0.1"}, 80},
		{"two addresses", "sctp", "127.0.0.1/127.0.0.2:80",
			[]string{"127.0.0.1", "127.0.0.2"}, 80},
		{"three addresses", "sctp", "127.0.0.1/127.0.0.2/127.0.0.3:9",
			[]string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}, 9},
		{"empty network means sctp", "", "127.0.0.1:80", []string{"127.0.0.1"}, 80},
		{"ipv6", "sctp6", "[::1]:80", []string{"::1"}, 80},
		{"two ipv6 addresses", "sctp6", "[::1]/[::1]:80",
			[]string{"::1", "::1"}, 80},
		{"port zero", "sctp", "127.0.0.1:0", []string{"127.0.0.1"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := ResolveSCTPAddr(tc.network, tc.addr)
			if err != nil {
				t.Fatalf("ResolveSCTPAddr(%q, %q): %v", tc.network, tc.addr, err)
			}
			if addr.Port != tc.port {
				t.Errorf("port = %d, want %d", addr.Port, tc.port)
			}
			if len(addr.IPAddrs) != len(tc.ips) {
				t.Fatalf("got %d addresses (%v), want %d (%v)",
					len(addr.IPAddrs), addr.IPAddrs, len(tc.ips), tc.ips)
			}
			for i, want := range tc.ips {
				if addr.IPAddrs[i].IP == nil {
					t.Errorf("address %d is nil; binding that asks for the "+
						"wildcard alongside the addresses named", i)
					continue
				}
				if got := addr.IPAddrs[i].IP.String(); got != want {
					t.Errorf("address %d = %s, want %s", i, got, want)
				}
			}
		})
	}
}

// TestResolveSCTPAddrNeverReturnsANilAddress states the invariant the two
// defects above both broke, independent of which input reached it.
func TestResolveSCTPAddrNeverReturnsANilAddress(t *testing.T) {
	inputs := []string{
		":0", "127.0.0.1:0", "127.0.0.1/127.0.0.2:0",
		"1.2.3.4/5.6.7.8/:80", "/127.0.0.1:80", "//:80", "/:0",
	}
	for _, in := range inputs {
		addr, err := ResolveSCTPAddr("sctp", in)
		if err != nil {
			continue // refused, which is a fine answer
		}
		for i, ip := range addr.IPAddrs {
			if ip.IP == nil {
				t.Errorf("ResolveSCTPAddr(%q) returned a nil IP at index %d "+
					"(%v); it would be bound as the wildcard", in, i, addr.IPAddrs)
			}
		}
	}
}

// FuzzResolveSCTPAddr exercises the parser with arbitrary input.
//
// This is the package's main place where a caller's string becomes an address
// that gets bound, and it had no fuzz target. The property asserted is the one
// that matters and that the two defects above both violated: a successful parse
// must not silently produce something the input did not describe.
func FuzzResolveSCTPAddr(f *testing.F) {
	for _, seed := range []string{
		":0",
		"127.0.0.1:80",
		"127.0.0.1/127.0.0.2:80",
		"1.2.3.4/5.6.7.8/:80",
		"/127.0.0.1:80",
		"[::1]:80",
		"[::1]/[fe80::1%25lo]:80",
		"",
		":",
		"/",
		"::::",
		strings.Repeat("1.2.3.4/", 64) + "5.6.7.8:1",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, addrs string) {
		for _, network := range []string{"sctp", "sctp4", "sctp6"} {
			addr, err := ResolveSCTPAddr(network, addrs)
			if err != nil {
				if addr != nil {
					t.Errorf("ResolveSCTPAddr(%q, %q) returned both %v and %v",
						network, addrs, addr, err)
				}
				continue
			}
			if addr == nil {
				t.Fatalf("ResolveSCTPAddr(%q, %q) returned nil with no error",
					network, addrs)
			}
			for i, ip := range addr.IPAddrs {
				if ip.IP == nil {
					t.Errorf("ResolveSCTPAddr(%q, %q) produced a nil IP at %d; "+
						"binding it asks for the wildcard", network, addrs, i)
				}
			}
			if addr.Port < 0 || addr.Port > 65535 {
				t.Errorf("ResolveSCTPAddr(%q, %q) produced port %d",
					network, addrs, addr.Port)
			}
			// Encoding must not panic and must produce something a decode can
			// read back, since this is what reaches the kernel.
			if buf := addr.ToRawSockAddrBuf(); len(buf) == 0 {
				t.Errorf("ResolveSCTPAddr(%q, %q) produced an address that "+
					"encodes to nothing", network, addrs)
			}
			_ = addr.String()
		}
	})
}
