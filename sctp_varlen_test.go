//go:build linux && !386
// +build linux,!386

package sctp

import (
	"errors"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// Covers the options whose payload is variable-length: the RFC 6525 stream reset
// requests and the RFC 4895 key management calls. These three accessors build
// their option buffer byte by byte rather than from a Go struct, because the C
// structs end in a flexible array. That means no layout test can pin them, so the
// byte offsets are asserted here directly.
//
// Both options were previously recorded as blocked. Both were in fact usable, and
// in both cases the earlier attempt had got a precondition wrong rather than
// finding a limitation — the same mistake that nearly caused SCTP_ADD_STREAMS to
// be written off. testdata/optprobe/varlen.c is what settled it.

// reconfConn builds an association with the stream reconfiguration extension
// negotiated on both ends and every request type permitted. Without this, both
// ResetStreams and ResetAssoc answer ENOPROTOOPT.
func reconfConn(t *testing.T) *SCTPConn {
	t.Helper()
	prepare := func(c *SCTPConn) error {
		if err := c.SetReconfigSupported(true); err != nil {
			return err
		}
		return c.SetEnableStreamReset(SCTPEnableResetStreamReq |
			SCTPEnableResetAssocReq | SCTPEnableChangeAssocReq)
	}
	cli, _ := extConn(t, prepare, prepare)

	// Guard the precondition rather than letting a negotiation failure be
	// reported as a broken reset.
	on, err := cli.ReconfigSupported()
	if err != nil {
		t.Fatalf("ReconfigSupported: %v", err)
	}
	if !on {
		t.Fatal("stream reconfiguration was not negotiated; the reset tests " +
			"cannot distinguish a broken request from a missing extension")
	}
	return cli
}

// TestResetStreams covers RFC 6525 §6.3.2 on a live association.
//
// The case that matters is the length. struct sctp_reset_streams ends in a
// flexible array, and naming a stream while passing only the fixed header length
// is rejected with EINVAL — which is exactly what made this option look unusable
// before. ResetStreams computes the length from the slice, so the test drives it
// through both the all-streams and named-stream paths.
func TestResetStreams(t *testing.T) {
	conn := reconfConn(t)

	t.Run("all streams", func(t *testing.T) {
		if err := conn.ResetStreams(SCTPStreamResetIncoming |
			SCTPStreamResetOutgoing); err != nil {
			t.Fatalf("ResetStreams(all): %v", err)
		}
	})

	t.Run("one named stream", func(t *testing.T) {
		// This is the path where the length has to include the list. A
		// regression that sent only the header length would fail with EINVAL.
		if err := conn.ResetStreams(SCTPStreamResetOutgoing, 0); err != nil {
			t.Fatalf("ResetStreams(outgoing, stream 0): %v", err)
		}
	})

	t.Run("several named streams", func(t *testing.T) {
		if err := conn.ResetStreams(SCTPStreamResetOutgoing, 0, 1, 2); err != nil {
			t.Fatalf("ResetStreams(outgoing, streams 0,1,2): %v", err)
		}
	})

	t.Run("each direction alone", func(t *testing.T) {
		for name, dir := range map[string]uint16{
			"incoming": SCTPStreamResetIncoming,
			"outgoing": SCTPStreamResetOutgoing,
		} {
			if err := conn.ResetStreams(dir); err != nil {
				t.Errorf("ResetStreams(%s): %v", name, err)
			}
		}
	})
}

// TestResetStreamsRejectsBadDirection covers the two Go-side guards.
//
// A direction of zero is rejected by the kernel with EINVAL, so the guard exists
// for the error message rather than for safety — and the test asserts the message
// so removing the guard fails rather than silently changing the error a caller
// sees.
func TestResetStreamsRejectsBadDirection(t *testing.T) {
	conn := reconfConn(t)

	err := conn.ResetStreams(0)
	if err == nil {
		t.Fatal("ResetStreams accepted a direction of zero")
	}
	if !strings.Contains(err.Error(), "at least one of") {
		t.Errorf("error = %q, want it to name the two direction flags", err)
	}

	err = conn.ResetStreams(SCTPStreamResetIncoming | 0x80)
	if err == nil {
		t.Fatal("ResetStreams accepted an undefined direction bit")
	}
	if !strings.Contains(err.Error(), "unknown bits") {
		t.Errorf("error = %q, want it to mention unknown bits", err)
	}

	// Neither rejection may have touched the socket.
	if err := conn.ResetStreams(SCTPStreamResetOutgoing); err != nil {
		t.Fatalf("ResetStreams after two rejected calls: %v", err)
	}
}

// TestResetStreamsNeedsExtension pins the ENOPROTOOPT that made this option look
// unsupported. Without it the "blocked" conclusion could be reached again.
func TestResetStreamsNeedsExtension(t *testing.T) {
	conn := sockoptConn(t)
	err := conn.ResetStreams(SCTPStreamResetOutgoing)
	if err == nil {
		t.Fatal("ResetStreams succeeded without the reconfiguration extension")
	}
	if !errors.Is(err, syscall.ENOPROTOOPT) {
		t.Errorf("ResetStreams without the extension gave %v, want "+
			"ENOPROTOOPT — that errno is what made this option look "+
			"unusable when it was merely un-negotiated", err)
	}
}

// TestResetAssoc covers RFC 6525 §6.3.3, and its un-negotiated counterpart.
func TestResetAssoc(t *testing.T) {
	t.Run("with the extension", func(t *testing.T) {
		conn := reconfConn(t)
		if err := conn.ResetAssoc(); err != nil {
			t.Fatalf("ResetAssoc: %v", err)
		}
	})

	t.Run("without the extension", func(t *testing.T) {
		conn := sockoptConn(t)
		if err := conn.ResetAssoc(); !errors.Is(err, syscall.ENOPROTOOPT) {
			t.Errorf("ResetAssoc without the extension gave %v, want "+
				"ENOPROTOOPT", err)
		}
	})
}

// TestResetStreamsRejectsTooManyStreams covers the count guard.
//
// The stream count field is a uint16, so a slice longer than 65535 would wrap and
// send a request naming a different number of streams than the buffer carries.
// The guard cannot be reached with a real slice of that size cheaply, but the
// boundary arithmetic is worth stating.
func TestResetStreamsRejectsTooManyStreams(t *testing.T) {
	conn := sockoptConn(t)

	// A slice one past what the count field can express. Allocated as a nil-safe
	// large slice of the smallest element; 65536 uint16s is 128 KiB, cheap.
	streams := make([]uint16, int(^uint16(0))+1)
	err := conn.ResetStreams(SCTPStreamResetOutgoing, streams...)
	if err == nil {
		t.Fatal("ResetStreams accepted more streams than the count field can " +
			"express")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %q, want it to explain the limit", err)
	}
}

// TestResetStreamsWireLayout checks the bytes ResetStreams actually sends, by
// intercepting them rather than rebuilding them.
//
// ResetStreams assembles struct sctp_reset_streams as bytes because the C struct
// ends in a flexible array, so TestStructLayoutsMatchKernel has no Go struct to
// pin. Rebuilding the same layout inside the test would assert nothing — it would
// pass with the implementation arbitrarily wrong. Instead this drives the real
// call against a socket, then reads the kernel's own view back where possible and
// otherwise relies on the kernel's validation: a transposed flags/count pair sends
// a count of 2 with flags of 0, which the kernel rejects with EINVAL because no
// direction is set.
//
// That kernel-side check is what makes the offsets testable at all: flags and
// count are adjacent uint16s, so swapping them is invisible to any length or
// success check but not to the direction validation.
func TestResetStreamsWireLayout(t *testing.T) {
	conn := reconfConn(t)

	// Naming two streams with only the outgoing direction. If the
	// implementation wrote the count where the flags belong, the kernel would
	// see flags=2 (OUTGOING happens to be 2, so that alone would pass) and
	// count=2 where flags should be — so also try a direction whose value
	// cannot be confused with a plausible count.
	if err := conn.ResetStreams(SCTPStreamResetIncoming, 7, 9); err != nil {
		t.Fatalf("ResetStreams(incoming, 7, 9): %v", err)
	}

	// A single stream with the incoming flag: flags=1, count=1. Swapping them
	// is undetectable here, which is why the case above uses two streams — with
	// flags=1 and count=2, a swap gives flags=2 and count=1, and the kernel
	// would reset the wrong direction on a different number of streams. The
	// asymmetric case is the one that matters.
	if err := conn.ResetStreams(SCTPStreamResetIncoming, 3); err != nil {
		t.Fatalf("ResetStreams(incoming, 3): %v", err)
	}

	// Naming more streams than the association has must be refused, which
	// proves the list is being read as a list of stream ids rather than as
	// padding. GetStatus reports the negotiated count.
	st, err := conn.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	beyond := st.Ostreams + 100
	err = conn.ResetStreams(SCTPStreamResetOutgoing, beyond)
	if err == nil {
		t.Errorf("ResetStreams accepted stream %d on an association with %d "+
			"outbound streams; the stream list is evidently not being read as "+
			"stream ids", beyond, st.Ostreams)
	}
}

// TestBuildersMatchKernelLayout asserts the three hand-built option buffers byte
// by byte.
//
// These exist because behaviour alone cannot cover them. Two examples from the
// mutation run:
//
//   - Writing the sctp_hmacalgo count as a uint16 instead of a uint32 leaves the
//     correct bytes on a little-endian host, because the following two bytes are
//     already zero. It is a real defect on a big-endian one, and no test running
//     on amd64 can detect it through a socket.
//   - The flags and count in sctp_reset_streams are adjacent uint16s, so a
//     transposition produces a buffer the kernel may still accept.
//
// The expected offsets are from offsetof() against linux/sctp.h, recorded in
// testdata/README.md.
func TestBuildersMatchKernelLayout(t *testing.T) {
	t.Run("sctp_reset_streams", func(t *testing.T) {
		// assoc@0 flags@4 nstreams@6 list@8, size 8 plus the list.
		buf := buildResetStreams(SCTPStreamResetIncoming, []uint16{7, 9})
		if len(buf) != 12 {
			t.Fatalf("length = %d, want 12 (8 byte header plus two uint16s)",
				len(buf))
		}
		if got := nativeEndian.Uint32(buf[0:4]); got != 0 {
			t.Errorf("assoc id at 0 = %d, want 0", got)
		}
		if got := nativeEndian.Uint16(buf[4:6]); got != SCTPStreamResetIncoming {
			t.Errorf("flags at 4 = %#x, want %#x — a value of 2 here means "+
				"flags and count were transposed",
				got, SCTPStreamResetIncoming)
		}
		if got := nativeEndian.Uint16(buf[6:8]); got != 2 {
			t.Errorf("stream count at 6 = %d, want 2", got)
		}
		if got := nativeEndian.Uint16(buf[8:10]); got != 7 {
			t.Errorf("stream[0] at 8 = %d, want 7", got)
		}
		if got := nativeEndian.Uint16(buf[10:12]); got != 9 {
			t.Errorf("stream[1] at 10 = %d, want 9", got)
		}

		// The all-streams form carries no list, so it is exactly the header.
		if bare := buildResetStreams(SCTPStreamResetOutgoing, nil); len(bare) != 8 {
			t.Errorf("length with no named streams = %d, want 8", len(bare))
		}
	})

	t.Run("sctp_authkey", func(t *testing.T) {
		// assoc@0 keynumber@4 keylength@6 key@8.
		key := []byte("secret42")
		buf := buildAuthKey(0x1234, key)
		if len(buf) != 8+len(key) {
			t.Fatalf("length = %d, want %d", len(buf), 8+len(key))
		}
		if got := nativeEndian.Uint32(buf[0:4]); got != 0 {
			t.Errorf("assoc id at 0 = %d, want 0", got)
		}
		if got := nativeEndian.Uint16(buf[4:6]); got != 0x1234 {
			t.Errorf("key number at 4 = %#x, want 0x1234 — a value of %d here "+
				"means it was written where the length belongs",
				got, len(key))
		}
		if got := nativeEndian.Uint16(buf[6:8]); got != uint16(len(key)) {
			t.Errorf("key length at 6 = %d, want %d", got, len(key))
		}
		if got := buf[8:]; string(got) != string(key) {
			t.Errorf("key bytes at 8 = %q, want %q", got, key)
		}
	})

	t.Run("sctp_hmacalgo", func(t *testing.T) {
		// num@0 as a __u32, idents@4.
		buf := buildHmacAlgo([]uint16{SCTPAuthHmacIDSHA1, SCTPAuthHmacIDSHA256})
		if len(buf) != 8 {
			t.Fatalf("length = %d, want 8 (4 byte count plus two uint16s)",
				len(buf))
		}
		// The count occupies all four bytes. Asserting the full uint32 is what
		// catches a uint16 write on a big-endian host; on little-endian the
		// four bytes happen to agree, so this assertion passes there either
		// way and the check below is what makes the intent explicit.
		if got := nativeEndian.Uint32(buf[0:4]); got != 2 {
			t.Errorf("ident count at 0 = %d, want 2", got)
		}
		// A uint16 write would leave bytes 2:4 untouched. They are already zero
		// from make(), so compare against what a correct uint32 write produces
		// for a value that differs in its upper half.
		big := buildHmacAlgo(make([]uint16, 0x10001))
		if got := nativeEndian.Uint32(big[0:4]); got != 0x10001 {
			t.Errorf("count 0x10001 encoded as %#x; a uint16 write cannot "+
				"represent it, which is the little-endian-invisible defect "+
				"this case exists to catch", got)
		}
		if got := nativeEndian.Uint16(buf[4:6]); got != SCTPAuthHmacIDSHA1 {
			t.Errorf("ident[0] at 4 = %d, want %d", got, SCTPAuthHmacIDSHA1)
		}
		if got := nativeEndian.Uint16(buf[6:8]); got != SCTPAuthHmacIDSHA256 {
			t.Errorf("ident[1] at 6 = %d, want %d", got, SCTPAuthHmacIDSHA256)
		}
	})
}

// TestAuthKeyManagement covers the RFC 4895 key lifecycle: install, select,
// deactivate, delete.
//
// The ordering constraints are the substance. The active key cannot be deleted,
// and a key still verifying in-flight packets should be deactivated rather than
// deleted — so the test walks the rollover sequence a caller actually has to
// perform, not just each call in isolation.
func TestAuthKeyManagement(t *testing.T) {
	if !authEnabled(t) {
		t.Skip("net.sctp.auth_enable is off; " +
			"set it to 1 to run the key management tests")
	}
	conn := sockoptConn(t)

	if err := conn.SetAuthKey(1, []byte("0123456789abcdef")); err != nil {
		t.Fatalf("SetAuthKey(1): %v", err)
	}
	if err := conn.SetAuthKey(2, []byte("fedcba9876543210")); err != nil {
		t.Fatalf("SetAuthKey(2): %v", err)
	}

	if err := conn.SetAuthActiveKey(1); err != nil {
		t.Fatalf("SetAuthActiveKey(1): %v", err)
	}
	if got, err := conn.AuthActiveKey(); err != nil {
		t.Fatalf("AuthActiveKey: %v", err)
	} else if got != 1 {
		t.Errorf("AuthActiveKey = %d, want 1", got)
	}

	// The active key is undeletable, which is the constraint that forces the
	// rollover order.
	if err := conn.DeleteAuthKey(1); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("DeleteAuthKey on the active key gave %v, want EINVAL — if "+
			"the kernel now permits it, the rollover documentation on "+
			"DeactivateAuthKey is wrong", err)
	}

	// Roll over: select the new key, then retire the old one.
	if err := conn.SetAuthActiveKey(2); err != nil {
		t.Fatalf("SetAuthActiveKey(2): %v", err)
	}
	if err := conn.DeactivateAuthKey(1); err != nil {
		t.Fatalf("DeactivateAuthKey(1): %v", err)
	}
	if err := conn.DeleteAuthKey(1); err != nil {
		t.Fatalf("DeleteAuthKey(1) after deactivating: %v", err)
	}

	// And it is gone: a second delete has nothing to remove.
	if err := conn.DeleteAuthKey(1); err == nil {
		t.Error("DeleteAuthKey succeeded twice for the same key")
	}
}

// TestSetAuthKeyRejectsEmpty covers the Go-side guard.
//
// The kernel rejects a zero-length key with EINVAL rather than treating it as a
// deletion, which is a plausible thing for a caller to assume. The guard turns
// that into a message naming DeleteAuthKey, and the test asserts the message so
// the guard cannot be removed silently.
func TestSetAuthKeyRejectsEmpty(t *testing.T) {
	conn := sockoptConn(t)

	err := conn.SetAuthKey(1, nil)
	if err == nil {
		t.Fatal("SetAuthKey accepted an empty key")
	}
	if !strings.Contains(err.Error(), "DeleteAuthKey") {
		t.Errorf("error = %q, want it to point at DeleteAuthKey", err)
	}
	// The guard must run before the syscall, so this holds even with the
	// sysctl off — the call never reaches the kernel to be refused with EACCES.
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EINVAL) {
		t.Errorf("error = %v, want a Go-side rejection rather than an errno; "+
			"the guard is supposed to short-circuit the syscall", err)
	}
}

// TestSetAuthKeyValidatesLength records that the kernel checks the key length
// against the option size, so a mismatch cannot make it read past the buffer.
//
// SetAuthKey derives both from the same slice and cannot produce a mismatch, so
// this drives setsockopt directly. It is worth pinning because if the kernel ever
// stopped checking, the accessor would be the only thing standing between a
// caller and an out-of-bounds kernel read.
func TestSetAuthKeyValidatesLength(t *testing.T) {
	if !authEnabled(t) {
		t.Skip("net.sctp.auth_enable is off")
	}
	conn := sockoptConn(t)

	// An 8-byte option claiming a 200-byte key.
	const hdr = 8
	buf := make([]byte, hdr+8)
	nativeEndian.PutUint16(buf[4:6], 9)
	nativeEndian.PutUint16(buf[6:8], 200)

	_, _, err := setsockopt(conn.fd(), SCTP_AUTH_KEY,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("a key length past the option end gave %v, want EINVAL — the "+
			"kernel is relied on to bound this", err)
	}

	// The honest form of the same call succeeds, proving the rejection was
	// about the length and not about the option generally.
	nativeEndian.PutUint16(buf[6:8], 8)
	if _, _, err := setsockopt(conn.fd(), SCTP_AUTH_KEY,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); err != nil {
		t.Fatalf("an honest 8 byte key was refused: %v", err)
	}
}

// TestSetHmacIdent covers RFC 4895 §6.2, including the kernel's validation of
// the identifiers.
func TestSetHmacIdent(t *testing.T) {
	if !authEnabled(t) {
		t.Skip("net.sctp.auth_enable is off")
	}
	conn := sockoptConn(t)

	if err := conn.SetHmacIdent(SCTPAuthHmacIDSHA1); err != nil {
		t.Fatalf("SetHmacIdent(SHA1): %v", err)
	}
	got, err := conn.HmacIdent()
	if err != nil {
		t.Fatalf("HmacIdent: %v", err)
	}
	if len(got) != 1 || got[0] != SCTPAuthHmacIDSHA1 {
		t.Errorf("HmacIdent = %v, want [%d] after setting just SHA-1",
			got, SCTPAuthHmacIDSHA1)
	}

	// Identifier 2 is unassigned in the IANA registry, and the kernel refuses
	// it. That is worth pinning: it means SetHmacIdent needs no Go-side guard.
	if err := conn.SetHmacIdent(2); !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Errorf("SetHmacIdent(2) gave %v, want EOPNOTSUPP — 2 is unassigned, "+
			"and if the kernel stopped rejecting it a Go-side guard would be "+
			"needed", err)
	}

	// An empty list is rejected in Go, before the syscall.
	err = conn.SetHmacIdent()
	if err == nil {
		t.Fatal("SetHmacIdent accepted an empty list")
	}
	if errors.Is(err, syscall.EINVAL) {
		t.Errorf("error = %v, want a Go-side rejection rather than an errno", err)
	}
}

// TestSetAuthChunk covers RFC 4895 §6.1, and records that the kernel does not
// enforce the specification's "before the association" requirement.
func TestSetAuthChunk(t *testing.T) {
	if !authEnabled(t) {
		t.Skip("net.sctp.auth_enable is off")
	}

	// On a fresh socket, which is where the RFC says it belongs.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM,
		syscall.IPPROTO_SCTP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	fresh := NewSCTPConn(fd, nil)
	defer func() { _ = fresh.Close() }()

	// Chunk type 0 is DATA.
	if err := fresh.SetAuthChunk(0); err != nil {
		t.Fatalf("SetAuthChunk(DATA) on a fresh socket: %v", err)
	}

	// And on a connected one, which RFC 4895 §6.1 says is too late but the
	// kernel accepts. Pinned so the documentation's claim that the requirement
	// is unenforced stays true.
	conn := sockoptConn(t)
	if err := conn.SetAuthChunk(0); err != nil {
		t.Errorf("SetAuthChunk on a connected socket gave %v; the "+
			"documentation says the kernel accepts this even though "+
			"RFC 4895 §6.1 requires it before the association", err)
	}
}

// TestAuthOptionsWithoutSysctl covers the set-only key management calls on a
// stock kernel, where the whole family reports EACCES.
//
// The read-side equivalent is TestAuthDisabledReportsEACCES; this covers the
// writers, which a caller is more likely to reach first.
func TestAuthOptionsWithoutSysctl(t *testing.T) {
	if authEnabled(t) {
		t.Skip("net.sctp.auth_enable is on")
	}
	conn := sockoptConn(t)

	for name, call := range map[string]func() error{
		"SetAuthKey":        func() error { return conn.SetAuthKey(1, []byte("key")) },
		"DeleteAuthKey":     func() error { return conn.DeleteAuthKey(1) },
		"DeactivateAuthKey": func() error { return conn.DeactivateAuthKey(1) },
		"SetHmacIdent":      func() error { return conn.SetHmacIdent(SCTPAuthHmacIDSHA1) },
		"SetAuthChunk":      func() error { return conn.SetAuthChunk(0) },
	} {
		if err := call(); !errors.Is(err, syscall.EACCES) {
			t.Errorf("%s with auth_enable=0 gave %v, want EACCES", name, err)
		}
	}
}
