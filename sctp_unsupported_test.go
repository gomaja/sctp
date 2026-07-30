//go:build !linux || (linux && 386)
// +build !linux linux,386

package sctp

import (
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

// TestUnsupportedEntryPointsReportTheSentinel checks that the methods added for
// cross-compilation actually return it, rather than a bare nil that a caller
// would read as success.
func TestUnsupportedEntryPointsReportTheSentinel(t *testing.T) {
	var c *SCTPConn
	var ln *SCTPListener

	if _, err := c.SyscallConn(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("SCTPConn.SyscallConn err = %v, want ErrUnsupported", err)
	}
	if _, err := ln.SyscallConn(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("SCTPListener.SyscallConn err = %v, want ErrUnsupported", err)
	}
	if _, err := c.SCTPWriteInfo(nil, nil, nil, nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("SCTPWriteInfo err = %v, want ErrUnsupported", err)
	}
	if _, err := c.SCTPWrite(nil, nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("SCTPWrite err = %v, want ErrUnsupported", err)
	}
}
