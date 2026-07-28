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
	"os"
	"testing"
	"time"
)

// TestReadDeadlineExpires is the basic contract: with no data arriving, a
// read must return ErrDeadlineExceeded at roughly the deadline rather than
// blocking forever.
func TestReadDeadlineExpires(t *testing.T) {
	_, server := eorPair(t)

	if err := server.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	start := time.Now()
	buf := make([]byte, 1024)
	_, _, err := server.SCTPRead(buf)
	elapsed := time.Since(start)

	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed < 200*time.Millisecond {
		t.Errorf("returned after %v, well before the 300ms deadline", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Errorf("returned after %v, far past the 300ms deadline", elapsed)
	}
}

// TestReadDeadlineInThePast checks a deadline already elapsed fails at once
// instead of being programmed as a zero timeout, which the kernel reads as
// "block forever".
func TestReadDeadlineInThePast(t *testing.T) {
	_, server := eorPair(t)

	if err := server.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		_, _, err := server.SCTPRead(buf)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read with an elapsed deadline blocked instead of failing")
	}
}

// TestReadDeadlineCleared verifies a zero time removes the deadline.
func TestReadDeadlineCleared(t *testing.T) {
	client, server := eorPair(t)

	if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1024)
	if _, _, err := server.SCTPRead(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected the deadline to fire, got %v", err)
	}

	// Clear it; a subsequent read must wait for real data.
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}

	want := []byte("sent after the deadline was cleared")
	go func() {
		time.Sleep(200 * time.Millisecond)
		_, _ = client.SCTPWrite(want, nil)
	}()

	n, _, err := server.SCTPRead(buf)
	if err != nil {
		t.Fatalf("read after clearing: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Errorf("got %q, want %q", buf[:n], want)
	}
}

// TestReadDeadlineDoesNotTruncateData ensures the deadline machinery does not
// interfere with a normal read that completes in time.
func TestReadDeadlineDoesNotTruncateData(t *testing.T) {
	client, server := eorPair(t)

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	defer func() { _ = server.SetReadDeadline(time.Time{}) }()

	for _, size := range []int{64, 4096, 20000} {
		msg := fill(size)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Fatalf("write %d: %v", size, err)
		}
		got, _, err := server.ReadMsg(1 << 20)
		if err != nil {
			t.Fatalf("ReadMsg %d: %v", size, err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("size %d: payload mismatch", size)
		}
	}
}

// TestReadMsgDeadlineBoundsWholeCall is the case that distinguishes an
// absolute deadline from a per-syscall timeout. ReadMsg may issue several
// recvmsg calls; the deadline must bound the call as a whole, so a peer that
// stops sending mid-message cannot hold the reader indefinitely.
func TestReadMsgDeadlineBoundsWholeCall(t *testing.T) {
	client, server := eorPair(t)

	// Send a message far larger than a single read, then stop. The receiver
	// should hit the deadline while waiting for the rest.
	msg := fill(200000)
	go func() {
		_, _ = client.SCTPWrite(msg, nil)
	}()

	if err := server.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	defer func() { _ = server.SetReadDeadline(time.Time{}) }()

	start := time.Now()
	got, _, err := server.ReadMsg(1 << 20)
	elapsed := time.Since(start)

	if err == nil {
		// The whole message arrived within the deadline, which is a valid
		// outcome on a fast loopback.
		if !bytes.Equal(got, msg) {
			t.Errorf("ReadMsg succeeded but returned %d of %d bytes",
				len(got), len(msg))
		}
		return
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want nil or os.ErrDeadlineExceeded", err)
	}
	// Must not have run far past the deadline: the point of an absolute
	// deadline is that each internal read shortens the remaining budget.
	if elapsed > 3*time.Second {
		t.Errorf("ReadMsg took %v with a 500ms deadline; the deadline is "+
			"being restarted per read rather than bounding the whole call",
			elapsed)
	}
	drain(t, server)
}

// TestWriteDeadlineInThePast covers the write side. Writes use MSG_DONTWAIT
// and never block, so the only observable deadline behaviour is that an
// already-elapsed deadline is refused rather than silently ignored.
func TestWriteDeadlineInThePast(t *testing.T) {
	client, _ := eorPair(t)

	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	if _, err := client.SCTPWrite([]byte("should not be sent"), nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}

	// Clearing it restores normal writes.
	if err := client.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, err := client.SCTPWrite([]byte("fine now"), nil); err != nil {
		t.Errorf("write after clearing the deadline: %v", err)
	}
}

// TestSetDeadlineSetsBoth checks the combined setter.
func TestSetDeadlineSetsBoth(t *testing.T) {
	client, _ := eorPair(t)

	if err := client.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := client.SCTPWrite([]byte("x"), nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("write err = %v, want os.ErrDeadlineExceeded", err)
	}
	buf := make([]byte, 64)
	if _, _, err := client.SCTPRead(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("read err = %v, want os.ErrDeadlineExceeded", err)
	}
}

// TestDeadlineSetFromAnotherGoroutine exercises the atomic access path, with
// a deadline always in force so no read can block indefinitely.
//
// Note the ordering requirement: a deadline must be set before the first read
// starts. SO_RCVTIMEO is only consulted when a syscall begins, so a read that
// starts before any deadline exists blocks until data arrives regardless of
// what another goroutine sets afterwards.
func TestDeadlineSetFromAnotherGoroutine(t *testing.T) {
	_, server := eorPair(t)

	if err := server.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}
	}()

	buf := make([]byte, 1024)
	for i := 0; i < 20; i++ {
		start := time.Now()
		_, _, err := server.SCTPRead(buf)
		if d := time.Since(start); d > 5*time.Second {
			close(stop)
			<-done
			t.Fatalf("read %d blocked for %v (err=%v)", i, d, err)
		}
	}
	close(stop)
	<-done
}
