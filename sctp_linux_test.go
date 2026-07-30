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
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// loopbackAddr returns a loopback address with no port, so the kernel assigns
// one.
//
// These tests used to bind port 54321. That is inside the kernel's ephemeral
// range — 32768 to 60999 on a stock configuration — so any of the many `:0` binds
// elsewhere in the suite could be handed it first, and then these tests failed
// with "address already in use". It reproduced deterministically once something
// else held the port:
//
//	--- FAIL: TestNotificationHandlerAssignmentOnDialing
//	    sctp_linux_test.go:39: address already in use
//
// Letting the kernel choose removes the collision rather than making it rarer.
// Where a test needs to connect back, it must use the listener's reported address
// rather than the one passed to ListenSCTP, since that one has no port yet.
func loopbackAddr() *SCTPAddr {
	return &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}}
}

// listenerAddr extracts the address a listener actually bound, which is the only
// way to reach a kernel-assigned port.
//
// The zero-port check cannot be reached while ListenSCTP works, so no test covers
// it and removing it keeps the suite green. It is kept because both callers feed
// the result straight into a dial: a zero port there fails as a connection error
// somewhere else, and this turns that into a statement of what actually went
// wrong.
func listenerAddr(t *testing.T, ln *SCTPListener) *SCTPAddr {
	t.Helper()
	la, ok := ln.Addr().(*SCTPAddr)
	if !ok || la.Port == 0 {
		t.Fatalf("listener address = %v; want a bound address with a non-zero port",
			la)
	}
	return la
}

func TestNotificationHandlerAssignmentOnDialing(t *testing.T) {
	network := "sctp"
	testErr := errors.New("test error")
	notificationHandler := func([]byte) error { return testErr }

	listener, err := ListenSCTP(network, loopbackAddr())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialSCTPExtConfig(network, nil, listenerAddr(t, listener),
		InitMsg{}, nil, notificationHandler)
	if err != nil {
		t.Fatalf("failed to establish connection due to: %v", err)
	}
	if conn == nil || conn.notificationHandler(nil) != testErr {
		t.Fatalf("notification handler has not been assigned")
	}
	_ = listener.Close()
	_ = conn.Close()
}

func TestNotificationHandlerAssignmentOnListening(t *testing.T) {
	network := "sctp"
	testErr := errors.New("test error")
	notificationHandler := func([]byte) error { return testErr }

	listener, err := listenSCTPExtConfig(network, loopbackAddr(), InitMsg{}, nil,
		notificationHandler)
	if err != nil {
		t.Fatalf("failed to start listening due to: %v", err)
	}
	if listener == nil || listener.notificationHandler(nil) != testErr {
		t.Fatalf("notification handler has not been assigned")
	}
	_ = listener.Close()
}

func TestDialUseControlFuncWithoutLocalAddress(t *testing.T) {
	network := "sctp"
	raddr := &SCTPAddr{IPAddrs: []net.IPAddr{net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}}}
	initMsg := InitMsg{}
	customControlFunc := validationControlFunc(t, network)
	conn, err := dialSCTPExtConfig(network, nil, raddr, initMsg, customControlFunc, nil)
	if err != nil && !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("failed to dial connection due to: %v", err)
	}
	_ = conn.Close()
}

func TestListenUseControlFuncWithoutLocalAddress(t *testing.T) {
	network := "sctp"
	initMsg := InitMsg{}
	customControlFunc := validationControlFunc(t, network)
	listener, err := listenSCTPExtConfig(network, nil, initMsg, customControlFunc, nil)
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer func() { _ = listener.Close() }()
}

func validationControlFunc(t *testing.T, network string) func(networkFunc, address string, c syscall.RawConn) error {
	return func(networkFunc, address string, c syscall.RawConn) error {
		if networkFunc != network {
			t.Errorf("unexpected network: got %s, want %s", networkFunc, network)
		}
		if address != "" {
			t.Error("expected empty address")
		}
		if c == nil {
			t.Error("RawConn is nil")
		}
		return nil
	}
}

func TestSyscallConn(t *testing.T) {
	network := "sctp"
	listener, err := ListenSCTP(network, loopbackAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if raw == nil {
		t.Fatalf("Expected non-nil RawConn, got nil")
	}
	conn, err := DialSCTP(network, nil, listenerAddr(t, listener))
	if err != nil {
		t.Fatalf("Failed to create SCTP connection: %v", err)
	}
	defer func() { _ = conn.Close() }()

	raw, err = conn.SyscallConn()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if raw == nil {
		t.Fatalf("Expected non-nil RawConn, got nil")
	}

	controlCalled := false
	err = raw.Control(func(fd uintptr) {
		controlCalled = true
	})
	if err != nil {
		t.Fatalf("Control failed: %v", err)
	}
	if !controlCalled {
		t.Errorf("Control callback was not called")
	}

	t.Run("after close", func(t *testing.T) {
		_ = conn.Close()
		raw, err := conn.SyscallConn()
		if err != syscall.EINVAL {
			t.Errorf("Expected EINVAL, got %v", err)
		}
		if raw != nil {
			t.Errorf("Expected nil RawConn, got %v", raw)
		}
	})
}

func TestSCTPListenerNameFromFd(t *testing.T) {
	ln, err := ListenSCTP("sctp", loopbackAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// This assertion is why the test asks for port 0 rather than a fixed one and
	// still means something: the kernel has to report back a real port.
	la, ok := ln.Addr().(*SCTPAddr)
	if !ok || la.Port == 0 {
		t.Fatalf("got %v; expected a proper address with non-zero port number", la)
	}

	raw, err := ln.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	var fln *SCTPListener
	// A Control error means the callback never ran, which would leave fln nil
	// and fail below for an unrelated-looking reason.
	if cerr := raw.Control(func(fd uintptr) {
		// os.NewFile takes ownership of the descriptor it is handed, and its
		// finalizer closes it once the *os.File becomes unreachable. Passing
		// the listener's own descriptor hands ownership of a socket that ln
		// still uses to the garbage collector: at the next GC the finalizer
		// closes it, the kernel reuses the number for an unrelated socket, and
		// the failure surfaces in whichever test is holding it by then.
		//
		// Duplicate it so the *os.File owns a descriptor of its own.
		dup, derr := syscall.Dup(int(fd))
		if derr != nil {
			t.Errorf("dup listener fd: %v", derr)
			return
		}
		f := os.NewFile(uintptr(dup), "listener")
		// FileListener dups again for the returned listener, so this file has
		// no owner once it returns and must be closed explicitly rather than
		// left to the finalizer.
		defer func() { _ = f.Close() }()
		fln, err = FileListener(f)
	}); cerr != nil {
		t.Fatalf("control: %v", cerr)
	}
	if err != nil {
		t.Fatalf("FileListener: %v", err)
	}
	if fln == nil {
		t.Fatal("FileListener returned no listener")
	}
	defer func() { _ = fln.Close() }()

	fla, ok := fln.Addr().(*SCTPAddr)
	if !ok || fla.Port == 0 {
		t.Fatalf("got %v; expected a proper address with non-zero port number", la)
	}

	if la.String() != fla.String() {
		t.Fatalf("got %v; expected %v", la.String(), fla.String())
	}
}

// TestListenerSurvivesGCAfterFileListener checks that building an SCTPListener
// from a listener's own descriptor leaves that descriptor owned by the
// listener alone.
//
// os.NewFile takes ownership of the descriptor it is given and closes it from
// a finalizer once the *os.File is unreachable. Handing it a live listener's
// descriptor therefore schedules a close of a socket still in use, and the
// kernel reuses the number immediately: the damage lands on whichever
// unrelated socket is holding it when the collector next runs, which is why
// this reproduces only in a full suite and never in isolation.
//
// Forcing collection here makes that deterministic.
func TestListenerSurvivesGCAfterFileListener(t *testing.T) {
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	raw, err := ln.SyscallConn()
	if err != nil {
		t.Fatalf("syscallconn: %v", err)
	}

	var lnFd int
	var fln *SCTPListener
	if cerr := raw.Control(func(fd uintptr) {
		lnFd = int(fd)
		dup, derr := syscall.Dup(int(fd))
		if derr != nil {
			t.Errorf("dup: %v", derr)
			return
		}
		f := os.NewFile(uintptr(dup), "listener")
		defer func() { _ = f.Close() }()
		fln, err = FileListener(f)
	}); cerr != nil {
		t.Fatalf("control: %v", cerr)
	}
	if err != nil {
		t.Fatalf("FileListener: %v", err)
	}
	if fln == nil {
		t.Fatal("FileListener returned no listener")
	}
	defer func() { _ = fln.Close() }()

	// Run finalizers for anything the block above dropped. Twice: the first
	// collection queues the finalizer, the second lets it run.
	runtime.GC()
	runtime.GC()

	if _, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(lnFd),
		syscall.F_GETFD, 0); e != 0 {
		t.Fatalf("listener descriptor %d was closed by a finalizer while the "+
			"listener still owned it: %v", lnFd, e)
	}

	// The listener must still be usable, not merely still hold a descriptor.
	// A dial that completes proves the socket is the one still listening.
	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener address unavailable after GC")
	}
	conn, err := DialSCTP("sctp", nil, la)
	if err != nil {
		t.Fatalf("dial listener after GC: %v", err)
	}
	if cerr := conn.Close(); cerr != nil {
		t.Errorf("close dialled conn: %v", cerr)
	}
}
