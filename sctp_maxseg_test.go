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
	"testing"
	"unsafe"
)

// TestAssocValueLayoutMatchesKernel pins AssocValue against
// struct sctp_assoc_value, which the kernel probe reports as 8 bytes with
// assoc_id at 0 and assoc_value at 4. It is passed by pointer, so a wrong
// layout writes the wrong field rather than failing.
func TestAssocValueLayoutMatchesKernel(t *testing.T) {
	var v AssocValue
	if got, want := unsafe.Sizeof(v), uintptr(8); got != want {
		t.Errorf("sizeof(AssocValue) = %d, kernel struct sctp_assoc_value is %d", got, want)
	}
	if got, want := unsafe.Offsetof(v.AssocID), uintptr(0); got != want {
		t.Errorf("offsetof(AssocValue.AssocID) = %d, kernel uses %d", got, want)
	}
	if got, want := unsafe.Offsetof(v.AssocVal), uintptr(4); got != want {
		t.Errorf("offsetof(AssocValue.AssocVal) = %d, kernel uses %d", got, want)
	}
}

// TestMaxSegSizeRoundTrip checks the value reaches the kernel and comes back,
// rather than the setsockopt succeeding against a wrong layout.
func TestMaxSegSizeRoundTrip(t *testing.T) {
	client, _ := eorPair(t)

	before, err := client.GetMaxSegSize()
	if err != nil {
		t.Fatalf("GetMaxSegSize: %v", err)
	}
	t.Logf("default max segment size: %d", before)

	const want = 1200
	if err := client.SetMaxSegSize(want); err != nil {
		t.Fatalf("SetMaxSegSize(%d): %v", want, err)
	}

	after, err := client.GetMaxSegSize()
	if err != nil {
		t.Fatalf("GetMaxSegSize after set: %v", err)
	}
	// The kernel clamps the request to what the path can carry, so it may
	// report less than asked, but it must not ignore the request entirely.
	if after > want {
		t.Errorf("max segment size = %d after setting %d; the value did not take effect",
			after, want)
	}
	t.Logf("after SetMaxSegSize(%d): %d", want, after)
}

// TestMaxSegSizeRejectsOutOfRange checks the guard rather than letting a
// negative int wrap into a huge uint32 on its way to the kernel.
func TestMaxSegSizeRejectsOutOfRange(t *testing.T) {
	client, _ := eorPair(t)

	if err := client.SetMaxSegSize(-1); err == nil {
		t.Error("SetMaxSegSize(-1) returned nil error")
	}
	if err := client.SetMaxSegSize(1 << 33); err == nil {
		t.Error("SetMaxSegSize(1<<33) returned nil error")
	}
	// Zero is legal: it restores the default.
	if err := client.SetMaxSegSize(0); err != nil {
		t.Errorf("SetMaxSegSize(0) should restore the default, got %v", err)
	}
}

// TestMaxSegSizeRejectsClosedConn checks the accessors report an error rather
// than operating on a closed descriptor.
func TestMaxSegSizeRejectsClosedConn(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	defer func() { _ = server.Abort() }()

	if err := client.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if _, err := client.GetMaxSegSize(); err == nil {
		t.Error("GetMaxSegSize on a closed conn returned nil error")
	}
	if err := client.SetMaxSegSize(1200); err == nil {
		t.Error("SetMaxSegSize on a closed conn returned nil error")
	}
}
