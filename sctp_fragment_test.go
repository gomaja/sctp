//go:build linux && !386
// +build linux,!386

package sctp

import (
	"bytes"
	"testing"
	"time"
)

// Messages that cross the fragmentation point.
//
// SCTP fragments a message larger than the association's fragmentation point
// across several DATA chunks and reassembles it at the far end (RFC 9260 §6.9).
// The suite sent messages up to 65536 bytes, but nothing tied those sizes to the
// value the kernel actually reports: on this stack the point is 65484, so the
// largest existing case cleared it by 52 bytes essentially by accident, and a
// change in MTU or in the kernel's accounting would have moved the boundary out
// from under the tests silently.
//
// These read the fragmentation point from the association and build the sizes
// from it, so they stay on the boundary wherever it moves.

// fragPoint returns the association's fragmentation point, skipping if the
// kernel does not report a usable one.
func fragPoint(t *testing.T, c *SCTPConn) int {
	t.Helper()
	st, err := c.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if st.FragmentationPoint == 0 {
		t.Skip("kernel reports no fragmentation point for this association")
	}
	return int(st.FragmentationPoint)
}

// TestMessagesAcrossTheFragmentationPoint sends messages either side of the
// boundary and requires each to arrive whole and intact.
//
// The sizes are derived from the kernel's own figure rather than hardcoded. The
// case that matters is point+1: the first size that must be split into multiple
// DATA chunks and reassembled. A reassembly defect that dropped or reordered a
// fragment shows here as a short or corrupted message, which a size-only check
// would miss — so the payload is verified byte for byte, with a pattern that
// does not repeat across fragment boundaries.
func TestMessagesAcrossTheFragmentationPoint(t *testing.T) {
	client, server := eorPair(t)

	point := fragPoint(t, client)
	t.Logf("association fragmentation point: %d bytes", point)

	sizes := []struct {
		name string
		n    int
	}{
		{"well under", point / 2},
		{"one under", point - 1},
		{"exactly at", point},
		{"one over", point + 1},
		{"two chunks", point*2 + 3},
	}

	if err := server.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}

	for _, tc := range sizes {
		t.Run(tc.name, func(t *testing.T) {
			msg := patternBytes(tc.n)
			if err := writeAll(client, msg, nil); err != nil {
				t.Fatalf("write %d bytes: %v", tc.n, err)
			}

			// ReadMsg reassembles across as many reads as the kernel needs, so
			// this covers the caller-visible contract rather than the raw
			// recvmsg behaviour SCTPReadFlags exposes.
			got, _, err := server.ReadMsg(tc.n * 2)
			if err != nil {
				t.Fatalf("read %d bytes: %v", tc.n, err)
			}
			if len(got) != tc.n {
				t.Fatalf("got %d bytes, want %d", len(got), tc.n)
			}
			if !bytes.Equal(got, msg) {
				t.Errorf("payload differs at byte %d", firstDiff(got, msg))
			}
		})
	}
}

// TestFragmentedMessageReportsEORCorrectly pins the flag a caller uses to tell a
// truncated read from a complete message.
//
// A fragmented message read through a buffer smaller than itself must come back
// without MSG_EOR on every read but the last. Without that, a caller splitting
// on message boundaries treats each fragment as its own message — the defect
// SCTPReadFlags exists to expose, checked here at the size where the kernel
// really is fragmenting rather than at an arbitrary large number.
func TestFragmentedMessageReportsEORCorrectly(t *testing.T) {
	client, server := eorPair(t)

	point := fragPoint(t, client)
	size := point + 1024 // certainly fragmented
	msg := patternBytes(size)

	if err := writeAll(client, msg, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}

	// A buffer well under the message, so the kernel must deliver it in pieces.
	buf := make([]byte, 4096)
	var (
		assembled []byte
		reads     int
		eorSeen   bool
	)
	for len(assembled) < size {
		n, _, flags, err := server.SCTPReadFlags(buf)
		if err != nil {
			t.Fatalf("read %d: %v", reads, err)
		}
		reads++
		assembled = append(assembled, buf[:n]...)
		if flags&MSG_EOR != 0 {
			eorSeen = true
			break
		}
		if reads > size/len(buf)+16 {
			t.Fatalf("read %d times without MSG_EOR; assembled %d of %d bytes",
				reads, len(assembled), size)
		}
	}

	if !eorSeen {
		t.Error("never saw MSG_EOR; the end of the message was not reported")
	}
	if reads < 2 {
		t.Errorf("message of %d bytes arrived in %d read(s) through a %d-byte "+
			"buffer; it was not fragmented, so this test proved nothing",
			size, reads, len(buf))
	}
	if len(assembled) != size {
		t.Fatalf("assembled %d bytes, want %d", len(assembled), size)
	}
	if !bytes.Equal(assembled, msg) {
		t.Errorf("reassembled payload differs at byte %d", firstDiff(assembled, msg))
	}
	t.Logf("%d-byte message reassembled from %d reads", size, reads)
}

// patternBytes builds a buffer whose contents vary along its length, so a
// dropped, duplicated or reordered fragment changes the bytes rather than
// leaving an identical-looking buffer.
func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i%251) ^ byte((i/251)%7)
	}
	return b
}

// firstDiff reports the index of the first differing byte, for a failure
// message that localises the corruption instead of dumping kilobytes.
func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
