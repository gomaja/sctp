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

// fileFromListener hands back an *os.File owning a descriptor of its own,
// duplicated from ln, so FileListener can be called without giving away the
// listener's descriptor to the file's finalizer.
func fileFromListener(t *testing.T, ln *SCTPListener) *os.File {
	t.Helper()
	raw, err := ln.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var f *os.File
	if cerr := raw.Control(func(fd uintptr) {
		dup, derr := syscall.Dup(int(fd))
		if derr != nil {
			t.Errorf("dup: %v", derr)
			return
		}
		f = os.NewFile(uintptr(dup), "listener")
	}); cerr != nil {
		t.Fatalf("control: %v", cerr)
	}
	if f == nil {
		t.Fatal("no file")
	}
	return f
}

// TestFileListenerDoesNotLeakDescriptors covers the descriptor accounting of
// FileListener, on both the path that succeeds and the one that fails.
//
// FileListener duplicates the descriptor it is handed, which means it owns one
// from the moment the dup returns. That ownership is the whole reason its error
// paths matter: the function returns nil rather than a listener, so a descriptor
// it fails to release is unreachable by any caller. The fix for that shipped
// without a test.
//
// The counts are compared against a warmed-up baseline rather than an absolute
// number, in the style of TestSetupFailureReleasesDescriptor.
func TestFileListenerDoesNotLeakDescriptors(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	t.Run("the failing dup releases nothing because it owns nothing", func(t *testing.T) {
		// A closed *os.File reports an invalid descriptor, so F_DUPFD_CLOEXEC
		// fails before anything is owned. This is the reachable half of the
		// error handling: the branch below it, where SetNonblock fails after a
		// successful dup, cannot be provoked — measured, fcntl(F_SETFL) on a
		// freshly duplicated valid descriptor does not fail, including on the
		// O_PATH descriptor that looked most likely to refuse it. That branch
		// is defensive and is kept, in the same spirit as the state check in
		// hasEstablishedAssoc.
		bad := fileFromListener(t, ln)
		if err := bad.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		for i := 0; i < 5; i++ {
			if _, err := FileListener(bad); err == nil {
				t.Fatal("FileListener on a closed file returned no error")
			}
		}
		before := openFds(t)
		for i := 0; i < 50; i++ {
			got, err := FileListener(bad)
			if err == nil {
				_ = got.Close()
				t.Fatal("FileListener on a closed file returned no error")
			}
			if !errors.Is(err, syscall.EBADF) {
				t.Fatalf("FileListener on a closed file gave %v, want EBADF", err)
			}
		}
		if after := openFds(t); after > before {
			t.Errorf("%d descriptors leaked over 50 failed calls (%d -> %d)",
				after-before, before, after)
		}
	})

	t.Run("the succeeding path releases on Close", func(t *testing.T) {
		f := fileFromListener(t, ln)
		defer func() { _ = f.Close() }()

		// Warm up, so a one-off allocation inside the first call is not counted
		// as a leak.
		for i := 0; i < 3; i++ {
			l, err := FileListener(f)
			if err != nil {
				t.Fatalf("FileListener: %v", err)
			}
			_ = l.Close()
		}

		before := openFds(t)
		for i := 0; i < 50; i++ {
			l, err := FileListener(f)
			if err != nil {
				t.Fatalf("FileListener: %v", err)
			}
			if err := l.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		}
		if after := openFds(t); after > before {
			t.Errorf("%d descriptors leaked over 50 create/close cycles (%d -> %d)",
				after-before, before, after)
		}
	})

	t.Run("the listener owns a descriptor of its own", func(t *testing.T) {
		// The dup is what makes FileListener safe to call on a file the caller
		// keeps using. Without it, closing either one would close both, and the
		// error-path accounting above would be about someone else's descriptor.
		f := fileFromListener(t, ln)
		defer func() { _ = f.Close() }()

		fl, err := FileListener(f)
		if err != nil {
			t.Fatalf("FileListener: %v", err)
		}
		if err := fl.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		// The caller's file must still work after the listener it produced has
		// been closed.
		if _, err := f.Stat(); err != nil {
			t.Errorf("the source file is unusable after closing the listener "+
				"built from it (%v); FileListener adopted the descriptor "+
				"instead of duplicating it", err)
		}
	})
}
