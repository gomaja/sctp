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
	"syscall"
	"testing"
	"unsafe"
)

// TestToBufSerialisesFixedSizeStructs covers the call sites that exist: every
// one passes a fixed-size struct, and the bytes handed to the kernel must be
// exactly as long as the struct.
func TestToBufSerialisesFixedSizeStructs(t *testing.T) {
	v4 := syscall.RawSockaddrInet4{Family: syscall.AF_INET}
	if got, want := len(toBuf(v4)), int(unsafe.Sizeof(v4)); got != want {
		t.Errorf("toBuf(RawSockaddrInet4) = %d bytes, want %d", got, want)
	}

	v6 := syscall.RawSockaddrInet6{Family: syscall.AF_INET6}
	if got, want := len(toBuf(v6)), int(unsafe.Sizeof(v6)); got != want {
		t.Errorf("toBuf(RawSockaddrInet6) = %d bytes, want %d", got, want)
	}

	info := SndRcvInfo{Stream: 1}
	if got, want := len(toBuf(info)), int(sndRcvInfoSize); got != want {
		t.Errorf("toBuf(SndRcvInfo) = %d bytes, want %d", got, want)
	}
}

// TestToBufPanicsOnUnserialisableType covers the failure that used to be
// discarded.
//
// binary.Write refuses a type that is not fixed-size, and toBuf ignored that
// error and returned the empty buffer it had written. The callers hand the
// result straight to the kernel as a socket address or control message, and
// ToRawSockAddrBuf indexes buf[0], so an empty buffer either sends a truncated
// message or panics later with nothing pointing at the cause.
//
// Failing loudly at the point of the mistake is the contract; this test pins
// it so the error cannot quietly go back to being dropped.
func TestToBufPanicsOnUnserialisableType(t *testing.T) {
	// A slice field has no fixed size, so binary.Write cannot encode it.
	type notFixedSize struct {
		A uint16
		B []byte
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("toBuf returned normally for a type binary.Write cannot " +
				"encode; the error is being discarded and the caller would " +
				"receive an empty buffer")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value = %#v, want a string naming the type", r)
		}
		// The message must name what failed, since the point of panicking is
		// to identify the mistake.
		if want := "sctp: cannot serialise"; len(msg) < len(want) || msg[:len(want)] != want {
			t.Errorf("panic message = %q, want it to start with %q", msg, want)
		}
	}()

	_ = toBuf(notFixedSize{A: 1, B: []byte{2, 3}})
}
