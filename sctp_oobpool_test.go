//go:build linux && !386
// +build linux,!386

package sctp

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The pooled control-message buffer.
//
// SCTPReadFlags takes its 254-byte oob buffer from a sync.Pool instead of
// allocating one per call. That is only safe because parseSndRcvInfo copies:
// it used to return a pointer *into* this buffer and byte-swap PPID in place,
// so a pooled buffer would have been handed to the next reader while a caller
// still held a pointer into it. The aliasing fix is what unlocked the pooling,
// and these tests are what keep the two from drifting apart.
//
// A defect here is not a crash. It is one association's stream, PPID or context
// appearing on another's message — which is why the coverage is concurrent and
// checks the ancillary data rather than only the payload.

// TestPooledOobDoesNotCrossAssociations drives many readers through the pool at
// once and requires each to see only its own ancillary data.
//
// Each peer sends on a stream and PPID unique to itself and requires both back
// on the echo. A buffer returned to the pool while another reader still holds a
// pointer into it shows up here as a stream or PPID belonging to a different
// peer, which a payload-only check would miss entirely: the message bytes are
// copied out of a separate buffer and would still be correct.
func TestPooledOobDoesNotCrossAssociations(t *testing.T) {
	const (
		peers   = 24
		msgs    = 40
		streams = 8
	)

	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var srvWG sync.WaitGroup
	srvWG.Add(1)
	go func() {
		defer srvWG.Done()
		for {
			c, aerr := ln.AcceptSCTP()
			if aerr != nil {
				return
			}
			if serr := c.SubscribeEvents(SCTP_EVENT_DATA_IO); serr != nil {
				_ = c.Close()
				continue
			}
			srvWG.Add(1)
			go func(c *SCTPConn) {
				defer srvWG.Done()
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				for {
					n, info, rerr := c.SCTPRead(buf)
					if rerr != nil {
						return
					}
					// Echo the ancillary data back as received, so the client
					// can check it round-tripped intact.
					var out *SndRcvInfo
					if info != nil {
						out = &SndRcvInfo{Stream: info.Stream, PPID: info.PPID}
					}
					if werr := writeAll(c, buf[:n], out); werr != nil {
						return
					}
				}
			}(c)
		}
	}()

	var crosstalk int64
	var wg sync.WaitGroup
	errs := make(chan error, peers)
	for i := 0; i < peers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, derr := DialSCTPExt("sctp", nil, ln.Addr().(*SCTPAddr),
				InitMsg{NumOstreams: streams, MaxInstreams: streams})
			if derr != nil {
				errs <- fmt.Errorf("peer %d dial: %w", id, derr)
				return
			}
			defer func() { _ = c.Close() }()
			if serr := c.SubscribeEvents(SCTP_EVENT_DATA_IO); serr != nil {
				errs <- fmt.Errorf("peer %d subscribe: %w", id, serr)
				return
			}
			if derr := c.SetDeadline(time.Now().Add(60 * time.Second)); derr != nil {
				errs <- fmt.Errorf("peer %d deadline: %w", id, derr)
				return
			}

			stream := uint16(id % streams)
			ppid := uint32(0x1000 + id)
			buf := make([]byte, 4096)
			for j := 0; j < msgs; j++ {
				want := fmt.Sprintf("peer%02d-msg%03d", id, j)
				if werr := writeAll(c, []byte(want), &SndRcvInfo{Stream: stream, PPID: ppid}); werr != nil {
					errs <- fmt.Errorf("peer %d write %d: %w", id, j, werr)
					return
				}
				n, info, rerr := c.SCTPRead(buf)
				if rerr != nil {
					errs <- fmt.Errorf("peer %d read %d: %w", id, j, rerr)
					return
				}
				if got := string(buf[:n]); got != want {
					errs <- fmt.Errorf("peer %d msg %d: got %q, want %q", id, j, got, want)
					return
				}
				// The ancillary data is what the pooled buffer carries, so this
				// is the assertion that covers the pooling.
				if info == nil {
					errs <- fmt.Errorf("peer %d msg %d: no ancillary data", id, j)
					return
				}
				if info.Stream != stream || info.PPID != ppid {
					atomic.AddInt64(&crosstalk, 1)
					errs <- fmt.Errorf("peer %d msg %d: got stream=%d ppid=%#x, "+
						"want stream=%d ppid=%#x — the pooled control buffer "+
						"leaked another association's ancillary data",
						id, j, info.Stream, info.PPID, stream, ppid)
					return
				}
			}
			errs <- nil
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}

	_ = ln.Close()
	srvWG.Wait()

	if n := atomic.LoadInt64(&crosstalk); n > 0 {
		t.Errorf("%d of %d exchanges saw another association's ancillary data",
			n, peers*msgs)
	}
}

// TestPooledOobHoldsEveryInfoCmsgAtOnce sizes the pooled buffer against what
// the kernel actually delivers, rather than against one cmsg at a time.
//
// The buffer's size had no coverage at all: shrinking it from 254 bytes to 48
// left the whole suite green. 48 is not an innocent number — it is exactly
// CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)), so every existing assertion still
// found the one cmsg it was looking for and the truncation landed on the fields
// nothing read.
//
// Three can arrive on a single read, and the kernel emits them in this order,
// measured on 6.12 with all three subscribed and a message queued behind:
//
//	SCTP_NXTINFO   16 bytes of payload, CMSG_SPACE  32
//	SCTP_RCVINFO   28 bytes of payload, CMSG_SPACE  48
//	SCTP_SNDRCV    32 bytes of payload, CMSG_SPACE  48
//	                                         total 128
//
// SCTP_NXTINFO coming first is what makes an undersized buffer quiet. The
// truncation takes SCTP_SNDRCV — the last one written and the one SCTPRead
// reports as info — so a caller that asked for the next message's size still
// gets it, and loses the description of the message in their hand. The kernel
// sets MSG_CTRUNC to say so; nothing in this package looks at it.
func TestPooledOobHoldsEveryInfoCmsgAtOnce(t *testing.T) {
	// sndinfoPair already subscribes SCTP_EVENT_DATA_IO on the server, which is
	// what SCTP_SNDRCV depends on.
	client, server := sndinfoPair(t)

	if err := server.SetRecvRcvInfo(true); err != nil {
		t.Fatalf("SetRecvRcvInfo: %v", err)
	}
	if err := server.SetRecvNxtInfo(true); err != nil {
		t.Fatalf("SetRecvNxtInfo: %v", err)
	}

	// Two messages, because SCTP_NXTINFO describes the message queued behind
	// the one being read. With a single message the kernel emits no NXTINFO at
	// all, and the read fits in a buffer far smaller than the one under test.
	send := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := writeAll(client, []byte("payload"),
				&SndRcvInfo{Stream: uint16(i % 4)}); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		// The successor has to be queued before the read, or there is nothing
		// for the kernel to report and the coverage is vacuous.
		time.Sleep(200 * time.Millisecond)
	}
	send(2)

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 256)
	_, info, nxt, flags, err := server.SCTPReadNextInfo(buf)
	if err != nil {
		t.Fatalf("SCTPReadNextInfo: %v", err)
	}

	if flags&syscall.MSG_CTRUNC != 0 {
		t.Errorf("the kernel set MSG_CTRUNC: the pooled control buffer is too "+
			"small for the cmsgs this subscription asks for, and one of them "+
			"was dropped (flags=%#x)", flags)
	}
	if nxt == nil {
		t.Error("no NxtInfo with a second message queued and SetRecvNxtInfo on")
	}
	if info == nil {
		t.Error("no SndRcvInfo alongside the NxtInfo — SCTP_SNDRCV is written " +
			"last, so this is what an undersized control buffer costs, and it " +
			"is lost silently: the read itself succeeds")
	}

	// The sizing, measured rather than asserted. Reading the same subscription
	// into a buffer far larger than the pool's says what the kernel really
	// needs, so this keeps holding if a kernel starts sending more.
	send(2)
	oobp := oobPool.Get().(*[]byte)
	pooled := len(*oobp)
	oobPool.Put(oobp)

	_, oobn, _, err := recvmsg(server.fd(), buf, make([]byte, 4096), 0)
	if err != nil {
		t.Fatalf("recvmsg: %v", err)
	}
	if oobn > pooled {
		t.Errorf("one read carried %d bytes of control data; the pool hands "+
			"out %d, so the excess is truncated away", oobn, pooled)
	}
	t.Logf("kernel delivered %d control bytes for this subscription; the pool "+
		"holds %d", oobn, pooled)
}

// TestPooledOobSurvivesReuse pins the property the pooling depends on: the
// SndRcvInfo a read returns must stay valid after the buffer goes back to the
// pool and is handed to another read.
//
// This is the regression test for the aliasing bug the pooling would otherwise
// have turned into a use-after-free. Against an implementation where
// parseSndRcvInfo returned a pointer into the control buffer, the retained
// values change under the caller as later reads reuse it.
func TestPooledOobSurvivesReuse(t *testing.T) {
	client, server := sndinfoPair(t)

	const messages = 16
	type kept struct {
		stream uint16
		ppid   uint32
		info   *SndRcvInfo
	}
	held := make([]kept, 0, messages)

	if err := server.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	buf := make([]byte, 4096)
	for i := 0; i < messages; i++ {
		stream := uint16(i % 4)
		ppid := uint32(0x2000 + i)
		if err := writeAll(client, []byte(fmt.Sprintf("m%d", i)),
			&SndRcvInfo{Stream: stream, PPID: ppid}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		_, info, err := server.SCTPRead(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if info == nil {
			t.Fatalf("read %d: no ancillary data", i)
		}
		// Keep the returned struct. Every later read reuses the pooled buffer
		// this was parsed from.
		held = append(held, kept{stream, ppid, info})
	}

	// All the reads are done and the buffer has been recycled many times over.
	// Every retained struct must still describe the message it came from.
	for i, k := range held {
		if k.info.Stream != k.stream || k.info.PPID != k.ppid {
			t.Errorf("message %d: retained info now reads stream=%d ppid=%#x, "+
				"want stream=%d ppid=%#x — the returned struct aliases the "+
				"pooled control buffer",
				i, k.info.Stream, k.info.PPID, k.stream, k.ppid)
		}
	}
}
