//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// openFds reports how many descriptors this process holds.
func openFds(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	// ReadDir itself holds one descriptor while it runs, which is released by
	// the time this returns; the count is stable enough to compare against
	// itself across iterations.
	return len(ents)
}

// TestSetupFailureReleasesDescriptor checks that a setup path failing after the
// socket exists still releases it.
//
// listenSCTPExtConfig and dialSCTPExtConfig create the socket first and then
// configure it, so every error between those two points owns a descriptor that
// no caller can reach: the functions return nil rather than a listener or a
// connection, leaving nothing to Close. A leak here is invisible in normal use
// and exhausts the process only under sustained failure, which is exactly when
// a server can least afford it.
//
// The count is compared against itself after a warm-up rather than against an
// absolute number, so unrelated descriptors held by the test binary do not
// matter.
func TestSetupFailureReleasesDescriptor(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	errForced := errors.New("forced setup failure")
	cfg := SocketConfig{
		// Control runs after the socket is created and before it is bound, so
		// returning an error here fails the path with a live descriptor open.
		Control: func(network, address string, c syscall.RawConn) error {
			return errForced
		},
	}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "listen",
			call: func() error {
				ln, err := cfg.Listen("sctp", addr)
				if ln != nil {
					_ = ln.Close()
					return errors.New("listen unexpectedly succeeded")
				}
				return err
			},
		},
		{
			name: "dial",
			call: func() error {
				conn, err := cfg.Dial("sctp", nil, addr)
				if conn != nil {
					_ = conn.Close()
					return errors.New("dial unexpectedly succeeded")
				}
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Warm up first: the first calls may allocate descriptors that are
			// then reused, and counting from cold reads that as a leak.
			for i := 0; i < 20; i++ {
				if err := tc.call(); !errors.Is(err, errForced) {
					t.Fatalf("want the forced failure, got %v", err)
				}
			}

			before := openFds(t)
			const iterations = 200
			for i := 0; i < iterations; i++ {
				if err := tc.call(); !errors.Is(err, errForced) {
					t.Fatalf("iteration %d: want the forced failure, got %v", i, err)
				}
			}
			after := openFds(t)

			// Each leaked iteration costs one descriptor, so a real leak grows
			// by iterations. Allow a small margin for descriptors the runtime
			// happens to open in between.
			if after-before > 10 {
				t.Errorf("descriptor count grew from %d to %d across %d failing "+
					"%s calls: the socket is not released when setup fails",
					before, after, iterations, tc.name)
			}
		})
	}
}

// TestListenSuccessDoesNotReleaseDescriptor is the negative case for the test
// above. A cleanup path that fired unconditionally rather than only on error
// would pass every leak assertion while closing sockets that succeeded, so the
// success path is asserted separately.
func TestListenSuccessDoesNotReleaseDescriptor(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	var cfg SocketConfig
	ln, err := cfg.Listen("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener has no address")
	}

	// A dial that completes proves the descriptor is still open and listening,
	// which an fd-count check on its own would not show.
	conn, err := DialSCTP("sctp", nil, la)
	if err != nil {
		t.Fatalf("dial a listener that was set up successfully: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}
