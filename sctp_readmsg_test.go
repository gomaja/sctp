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
	"bytes"
	"errors"
	"syscall"
	"testing"
)

// fill builds a message with position-dependent bytes, so a reassembly that
// splices fragments in the wrong order is detected rather than passing on a
// uniform payload.
func fill(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i/251)
	}
	return b
}

// TestReadMsgSizeMaxMatrix walks message sizes against ReadMsg limits, with
// particular attention to the points where the internal buffer growth
// switches behaviour: the initial 2048-byte chunk, and max itself.
func TestReadMsgSizeMaxMatrix(t *testing.T) {
	client, server := eorPair(t)

	// These straddle ReadMsg's initial 2048-byte allocation and its doubling
	// points, where the growth arithmetic changes behaviour.
	sizes := []int{
		1, 2047, 2048, 2049,
		4095, 4096, 4097,
		8192, 20000,
	}
	maxes := []int{2048, 4096, 65536}

	for _, max := range maxes {
		for _, size := range sizes {
			msg := fill(size)
			if _, err := client.SCTPWrite(msg, nil); err != nil {
				t.Fatalf("write size=%d: %v", size, err)
			}

			got, _, err := server.ReadMsg(max)

			if size <= max {
				if err != nil {
					t.Errorf("size=%d max=%d: unexpected error %v", size, max, err)
					continue
				}
				if !bytes.Equal(got, msg) {
					t.Errorf("size=%d max=%d: payload mismatch (got %d bytes)",
						size, max, len(got))
				}
				continue
			}

			// size > max: must report ErrMsgTooLong with a correct prefix.
			if !errors.Is(err, ErrMsgTooLong) {
				t.Errorf("size=%d max=%d: err = %v, want ErrMsgTooLong", size, max, err)
			}
			if len(got) > max {
				t.Errorf("size=%d max=%d: returned %d bytes, over the limit",
					size, max, len(got))
			}
			if !bytes.HasPrefix(msg, got) {
				t.Errorf("size=%d max=%d: returned prefix does not match the message",
					size, max)
			}
			// Drain whatever remains so the next case starts clean.
			drain(t, server)
		}
	}
}

// drain consumes the queued remainder of a partially read message, so the
// next case starts on a clean association.
//
// SetReadDeadline is a stub returning EOPNOTSUPP on this type, so a blocking
// read would hang once the remainder is consumed. Apply SO_RCVTIMEO directly
// to bound the wait instead.
func drain(t testingTB, c *SCTPConn) {
	t.Helper()

	fd := c.fd()
	tv := syscall.Timeval{Sec: 0, Usec: 200000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		t.Fatalf("drain: set SO_RCVTIMEO: %v", err)
	}
	defer func() {
		zero := syscall.Timeval{}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &zero)
	}()

	buf := make([]byte, 65536)
	for i := 0; i < 256; i++ {
		_, _, flags, err := c.SCTPReadFlags(buf)
		if err != nil {
			// EAGAIN/EWOULDBLOCK: nothing left queued.
			return
		}
		if flags&MSG_EOR != 0 {
			return
		}
	}
}

// TestReadMsgExactMaxIsComplete pins the boundary case: a message whose
// length is exactly max is a complete message and must be reported as such,
// not as ErrMsgTooLong. The remainder-detection must not depend on whether
// the final fragment happened to fill the buffer.
func TestReadMsgExactMaxIsComplete(t *testing.T) {
	client, server := eorPair(t)

	for _, size := range []int{64, 2048, 4096, 9000} {
		msg := fill(size)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Fatalf("write %d: %v", size, err)
		}

		got, _, err := server.ReadMsg(size) // max == len(msg)
		if err != nil {
			t.Errorf("size=%d max=%d: err = %v, want nil (message fits exactly)",
				size, size, err)
			drain(t, server)
			continue
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("size=%d: payload mismatch", size)
		}
	}
}

// TestReadMsgOneOverMax checks the other side of the boundary.
func TestReadMsgOneOverMax(t *testing.T) {
	client, server := eorPair(t)

	for _, max := range []int{64, 2048, 4096} {
		msg := fill(max + 1)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Fatalf("write: %v", err)
		}

		got, _, err := server.ReadMsg(max)
		if !errors.Is(err, ErrMsgTooLong) {
			t.Errorf("max=%d: err = %v, want ErrMsgTooLong", max, err)
		}
		if len(got) != max {
			t.Errorf("max=%d: got %d bytes, want %d", max, len(got), max)
		}
		drain(t, server)
	}
}

// TestZeroLengthSendIsRefusedByTheKernel pins what actually happens when a
// caller asks to send an empty message.
//
// This used to be TestReadMsgZeroLengthMessage, which set out to check that an
// empty message is delivered as one rather than mistaken for EOF — and opened
// with a guard that skipped when the write was refused. The write is always
// refused: sctp_sendmsg rejects a zero-length message with EINVAL, so the body
// had never run on Linux, in the documented harness or anywhere else. Unlike
// the two AUTH skips, no second pass reached it either. A test that cannot run
// is not coverage, so it now asserts the contract that exists.
//
// SCTPWrite and SCTPWriteInfo pass the kernel's answer through: a caller asking
// for a zero-length SCTP message asked for something specific and is entitled to
// be told it is not available. Conn.Write is the one held to the net.Conn
// contract instead — see TestWriteWithZeroLengthBufferIsANoOp.
func TestZeroLengthSendIsRefusedByTheKernel(t *testing.T) {
	client, server := eorPair(t)

	for _, tc := range []struct {
		name string
		call func() (int, error)
	}{
		{"SCTPWrite empty slice", func() (int, error) { return client.SCTPWrite([]byte{}, nil) }},
		{"SCTPWrite nil", func() (int, error) { return client.SCTPWrite(nil, nil) }},
		{"SCTPWriteInfo empty slice", func() (int, error) {
			return client.SCTPWriteInfo([]byte{}, nil, nil, nil)
		}},
	} {
		n, err := tc.call()
		if !errors.Is(err, syscall.EINVAL) {
			t.Errorf("%s = (%d, %v), want EINVAL: the kernel refuses a "+
				"zero-length message", tc.name, n, err)
		}
		if n != 0 {
			t.Errorf("%s reported %d bytes sent", tc.name, n)
		}
	}

	// And the refusal must leave the association usable — a rejected send that
	// disturbed the socket would be worse than the refusal.
	want := []byte("after-empty")
	if _, err := client.SCTPWrite(want, nil); err != nil {
		t.Fatalf("write after the refused sends: %v", err)
	}
	got, _, err := server.ReadMsg(4096)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// FuzzReadMsg drives real messages through a real association, varying the
// message length and the ReadMsg limit. The invariant is total: either the
// full message comes back, or ErrMsgTooLong with a correct, bounded prefix.
func FuzzReadMsg(f *testing.F) {
	f.Add(1, 4096)
	f.Add(2048, 2048)
	f.Add(2049, 2048)
	f.Add(4096, 4096)
	f.Add(8192, 2048)
	f.Add(65535, 65536)

	client, server := eorPair(f)

	f.Fuzz(func(t *testing.T, size, max int) {
		// Keep the association usable: bound the inputs rather than
		// rejecting them, so more of the space is actually exercised.
		if size < 0 {
			size = -size
		}
		if max < 0 {
			max = -max
		}
		size %= 70000
		max %= 70000
		if max == 0 {
			max = 1
		}

		msg := fill(size)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Skipf("write %d: %v", size, err)
		}

		got, _, err := server.ReadMsg(max)

		switch {
		case size <= max:
			if err != nil {
				t.Fatalf("size=%d max=%d: unexpected err %v", size, max, err)
			}
			if !bytes.Equal(got, msg) {
				t.Fatalf("size=%d max=%d: payload mismatch, got %d bytes",
					size, max, len(got))
			}
		default:
			if !errors.Is(err, ErrMsgTooLong) {
				t.Fatalf("size=%d max=%d: err = %v, want ErrMsgTooLong",
					size, max, err)
			}
			if len(got) > max {
				t.Fatalf("size=%d max=%d: returned %d bytes, over limit",
					size, max, len(got))
			}
			if !bytes.HasPrefix(msg, got) {
				t.Fatalf("size=%d max=%d: prefix mismatch", size, max)
			}
			drain(t, server)
		}
	})
}
