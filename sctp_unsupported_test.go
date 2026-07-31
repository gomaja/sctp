//go:build !linux || (linux && 386)
// +build !linux linux,386

package sctp

import (
	"context"
	"errors"
	"testing"
)

// TestErrUnsupportedWrapsStdlibSentinel pins the wrapping.
//
// The portable way to ask "is this operation simply not available here" is
// errors.Is(err, errors.ErrUnsupported). This package's own sentinel shares the
// name, which made it easy to assume the generic check worked when it returned
// false — a caller then concluded the failure was something other than "this
// platform has no SCTP".
//
// This file is the mirror of the linux build tag, so it runs exactly where
// ErrUnsupported is defined.
func TestErrUnsupportedWrapsStdlibSentinel(t *testing.T) {
	if !errors.Is(ErrUnsupported, errors.ErrUnsupported) {
		t.Error("errors.Is(ErrUnsupported, errors.ErrUnsupported) = false; " +
			"the portable check a caller writes does not work")
	}
	// The specific check must keep working, including through the wrapping.
	if !errors.Is(ErrUnsupported, ErrUnsupported) {
		t.Error("ErrUnsupported does not match itself")
	}
}

// TestUnsupportedEntryPointsReportTheSentinel checks that every stub in this
// file returns the sentinel, rather than a bare nil a caller would read as
// success.
//
// It covers all of them, not the four it started with. Twenty-six of the thirty
// could be changed to return nil with the suite green — and the consequence is
// not a confusing error but a crash: with ListenSCTP returning (nil, nil), a
// caller doing the correct thing and checking err panics on the next line
// dereferencing the listener.
//
// The build tags also mean nothing else reaches this file. `go build` for a
// cross target does not compile _test.go files, `go vet` type-checks without
// running, and the suite proper only ever runs on linux/amd64 — so signature
// drift is caught but return values are not, on any platform, by any job. The
// CI workflow gains a macos-latest job for exactly this reason.
func TestUnsupportedEntryPointsReportTheSentinel(t *testing.T) {
	var c *SCTPConn
	var ln *SCTPListener

	// A thunk per entry point rather than generic helpers: go.mod declares
	// go 1.12, so type parameters are not available here.
	for _, tc := range []struct {
		name string
		call func() error
	}{
		// Reads and writes.
		{"SCTPConn.SCTPWrite", func() error { _, err := c.SCTPWrite(nil, nil); return err }},
		{"SCTPConn.SCTPWriteInfo", func() error { _, err := c.SCTPWriteInfo(nil, nil, nil, nil); return err }},
		{"SCTPConn.SCTPRead", func() error { _, _, err := c.SCTPRead(nil); return err }},
		{"SCTPConn.SCTPReadFlags", func() error { _, _, _, err := c.SCTPReadFlags(nil); return err }},
		{"SCTPConn.SCTPReadNextInfo", func() error { _, _, _, _, err := c.SCTPReadNextInfo(nil); return err }},
		{"SCTPConn.ReadMsg", func() error { _, _, err := c.ReadMsg(1); return err }},

		// Lifecycle.
		{"SCTPConn.Close", func() error { return c.Close() }},
		{"SCTPConn.Abort", func() error { return c.Abort() }},
		{"SCTPConn.CloseWithTimeout", func() error { return c.CloseWithTimeout(0) }},
		{"SCTPConn.PeelOff", func() error { _, err := c.PeelOff(0); return err }},
		{"SCTPConn.SyscallConn", func() error { _, err := c.SyscallConn(); return err }},

		// Buffers.
		{"SCTPConn.SetWriteBuffer", func() error { return c.SetWriteBuffer(0) }},
		{"SCTPConn.GetWriteBuffer", func() error { _, err := c.GetWriteBuffer(); return err }},
		{"SCTPConn.SetReadBuffer", func() error { return c.SetReadBuffer(0) }},
		{"SCTPConn.GetReadBuffer", func() error { _, err := c.GetReadBuffer(); return err }},

		// Listeners.
		{"ListenSCTP", func() error { _, err := ListenSCTP("sctp", nil); return err }},
		{"ListenSCTPExt", func() error { _, err := ListenSCTPExt("sctp", nil, InitMsg{}); return err }},
		{"listenSCTPExtConfig", func() error {
			_, err := listenSCTPExtConfig("sctp", nil, InitMsg{}, nil, nil)
			return err
		}},
		{"FileListener", func() error { _, err := FileListener(nil); return err }},
		{"SCTPListener.Accept", func() error { _, err := ln.Accept(); return err }},
		{"SCTPListener.AcceptSCTP", func() error { _, err := ln.AcceptSCTP(); return err }},
		{"SCTPListener.Close", func() error { return ln.Close() }},
		{"SCTPListener.SyscallConn", func() error { _, err := ln.SyscallConn(); return err }},

		// Dialers.
		{"DialSCTP", func() error { _, err := DialSCTP("sctp", nil, nil); return err }},
		{"DialSCTPExt", func() error { _, err := DialSCTPExt("sctp", nil, nil, InitMsg{}); return err }},
		{"dialSCTPExtConfig", func() error {
			_, err := dialSCTPExtConfig("sctp", nil, nil, InitMsg{}, nil, nil)
			return err
		}},
		{"DialSCTPContext", func() error {
			_, err := DialSCTPContext(context.Background(), "sctp", nil, nil, InitMsg{})
			return err
		}},
		{"dialSCTPExtConfigContext", func() error {
			_, err := dialSCTPExtConfigContext(context.Background(), "sctp", nil, nil, InitMsg{}, nil, nil)
			return err
		}},

		// The socket-option primitives every wrapper in sctp.go funnels into.
		{"setsockopt", func() error { _, _, err := setsockopt(0, 0, 0, 0); return err }},
		{"getsockopt", func() error { _, _, err := getsockopt(0, 0, 0, 0); return err }},
	} {
		err := tc.call()
		if err == nil {
			t.Errorf("%s returned a nil error on a platform without SCTP; "+
				"a caller checking err then uses a nil result", tc.name)
			continue
		}
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s err = %v, want it to wrap errors.ErrUnsupported", tc.name, err)
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s err = %v, want it to wrap sctp.ErrUnsupported", tc.name, err)
		}
	}
}
