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
	"time"
	"unsafe"
)

// testingTB is the subset of testing.TB the connection helper needs, so the
// same setup serves both tests and fuzz targets.
type testingTB interface {
	Helper()
	Fatalf(format string, args ...interface{})
	Cleanup(func())
}

// dialRetry dials raddr, retrying past the transient failures that rapid
// reconnect churn provokes.
//
// SCTPConnect can return EISCONN or EALREADY on a freshly created socket when
// associations are being torn down concurrently; see
// TestDialUnderChurnReportsEISCONN, which documents that behaviour
// deliberately. Every other test wants a working association rather than a
// lottery, so they dial through here.
func dialRetry(raddr *SCTPAddr) (*SCTPConn, error) {
	var (
		conn *SCTPConn
		err  error
	)
	for attempt := 0; attempt < 50; attempt++ {
		conn, err = DialSCTP("sctp", nil, raddr)
		if err == nil {
			return conn, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, err
}

// eorPair brings up a loopback association and returns both ends.
func eorPair(t testingTB) (client, server *SCTPConn) {
	t.Helper()

	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type accepted struct {
		conn *SCTPConn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.AcceptSCTP()
		ch <- accepted{c, err}
	}()

	client, err = dialRetry(ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Bound the cleanup close. A test that leaves its peer aborted would
	// otherwise make this wait out the full default grace period with nothing
	// left to answer the shutdown.
	t.Cleanup(func() { _ = client.CloseWithTimeout(200 * time.Millisecond) })

	a := <-ch
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	t.Cleanup(func() { _ = a.conn.CloseWithTimeout(200 * time.Millisecond) })

	return client, a.conn
}

// TestSCTPReadFlagsReportsTruncation is the core regression test: a message
// larger than the read buffer must come back without MSG_EOR, and the
// remainder must still be retrievable. Before SCTPReadFlags existed the
// caller had no way to tell this case from a complete message.
func TestSCTPReadFlagsReportsTruncation(t *testing.T) {
	client, server := eorPair(t)

	const bufSize = 1500
	// 1024 and 1400 fit the buffer; 1600 and up do not. These are the sizes
	// the truncation was originally observed at.
	for _, size := range []int{1024, 1400, 1600, 4096, 16384} {
		msg := bytes.Repeat([]byte{byte(size % 251)}, size)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Fatalf("write %d: %v", size, err)
		}

		var (
			got       []byte
			buf       = make([]byte, bufSize)
			reads     int
			sawNonEOR bool
		)
		for {
			n, _, flags, err := server.SCTPReadFlags(buf)
			if err != nil {
				t.Fatalf("read %d: %v", size, err)
			}
			reads++
			got = append(got, buf[:n]...)
			if flags&MSG_EOR != 0 {
				break
			}
			sawNonEOR = true
			if reads > 64 {
				t.Fatalf("size %d: too many reads without MSG_EOR", size)
			}
		}

		if !bytes.Equal(got, msg) {
			t.Errorf("size %d: reassembled %d bytes, want %d", size, len(got), size)
		}
		// A message that exceeds the buffer must have been flagged as
		// truncated at least once; one that fits must not be.
		if want := size > bufSize; sawNonEOR != want {
			t.Errorf("size %d: saw truncation=%v, want %v (reads=%d)",
				size, sawNonEOR, want, reads)
		}
	}
}

// TestSCTPReadLosesTruncationSignal documents the behaviour that motivated
// SCTPReadFlags: via plain SCTPRead an oversized message is silently split,
// and the tail arrives looking like an independent message.
func TestSCTPReadLosesTruncationSignal(t *testing.T) {
	client, server := eorPair(t)

	const bufSize = 1500
	msg := bytes.Repeat([]byte{0xAB}, 4096)
	if _, err := client.SCTPWrite(msg, nil); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, bufSize)
	n, _, err := server.SCTPRead(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != bufSize {
		t.Fatalf("first read got %d bytes, want a full buffer (%d)", n, bufSize)
	}
	// Nothing in this return value distinguishes it from a complete
	// 1500-byte message; that is precisely the bug.

	// Drain the rest so the association is clean for the deferred close.
	for total := n; total < len(msg); {
		n, _, flags, err := server.SCTPReadFlags(buf)
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
		total += n
		if flags&MSG_EOR != 0 {
			break
		}
	}
}

// TestReadMsgReassembles checks the opt-in helper returns whole messages
// regardless of size, without the caller sizing a buffer up front.
func TestReadMsgReassembles(t *testing.T) {
	client, server := eorPair(t)

	for _, size := range []int{1, 100, 1400, 1600, 4096, 16384, 65536} {
		msg := bytes.Repeat([]byte{byte(size % 251)}, size)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Fatalf("write %d: %v", size, err)
		}

		got, _, err := server.ReadMsg(1 << 20)
		if err != nil {
			t.Fatalf("ReadMsg %d: %v", size, err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("size %d: got %d bytes, want %d", size, len(got), size)
		}
	}
}

// TestReadMsgRespectsMax verifies an oversized message stops at the limit and
// reports ErrMsgTooLong rather than growing without bound.
func TestReadMsgRespectsMax(t *testing.T) {
	client, server := eorPair(t)

	msg := bytes.Repeat([]byte{0xCD}, 16384)
	if _, err := client.SCTPWrite(msg, nil); err != nil {
		t.Fatalf("write: %v", err)
	}

	const max = 4096
	got, _, err := server.ReadMsg(max)
	if !errors.Is(err, ErrMsgTooLong) {
		t.Fatalf("ReadMsg err = %v, want ErrMsgTooLong", err)
	}
	if len(got) != max {
		t.Errorf("got %d bytes, want %d", len(got), max)
	}
	if !bytes.Equal(got, msg[:max]) {
		t.Error("returned prefix does not match the sent message")
	}
}

func TestReadMsgRejectsNonPositiveMax(t *testing.T) {
	_, server := eorPair(t)
	for _, max := range []int{0, -1} {
		if _, _, err := server.ReadMsg(max); err != syscall.EINVAL {
			t.Errorf("ReadMsg(%d) err = %v, want EINVAL", max, err)
		}
	}
}

// TestMsgEORMatchesKernel guards the exported constant against the value the
// kernel actually uses.
func TestMsgEORMatchesKernel(t *testing.T) {
	if MSG_EOR != syscall.MSG_EOR {
		t.Errorf("MSG_EOR = %#x, kernel uses %#x", MSG_EOR, syscall.MSG_EOR)
	}
}

// TestWrappedConnZeroesInfoWhenAbsent covers the second defect: when no
// ancillary data accompanies a message, the wrapped conn used to leave the
// caller's buffer untouched, so stale bytes were read back as a valid
// SndRcvInfo.
func TestWrappedConnZeroesInfoWhenAbsent(t *testing.T) {
	client, server := eorPair(t)

	// Deliberately do NOT subscribe to SCTP_EVENT_DATA_IO on the reader, so
	// no SndRcvInfo cmsg arrives and SCTPRead yields info == nil.
	wrapped := &SCTPSndRcvInfoWrappedConn{conn: server}

	payload := []byte("payload")
	if _, err := client.SCTPWrite(payload, nil); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Poison the header region; a correct Read must not leave it in place.
	buf := make([]byte, int(sndRcvInfoSize)+len(payload))
	for i := 0; i < int(sndRcvInfoSize); i++ {
		buf[i] = 0xFF
	}

	n, err := wrapped.Read(buf)
	if err != nil {
		t.Fatalf("wrapped read: %v", err)
	}
	if want := int(sndRcvInfoSize) + len(payload); n != want {
		t.Fatalf("read n = %d, want %d", n, want)
	}
	if got := buf[int(sndRcvInfoSize):n]; !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}

	info := (*SndRcvInfo)(unsafe.Pointer(&buf[0]))
	if info.Stream == 0xFFFF || info.PPID == 0xFFFFFFFF {
		t.Errorf("SndRcvInfo header left stale: stream=%#x ppid=%#x",
			info.Stream, info.PPID)
	}
	for i := 0; i < int(sndRcvInfoSize); i++ {
		if buf[i] != 0 {
			t.Errorf("header byte %d = %#x, want 0", i, buf[i])
			break
		}
	}
}
