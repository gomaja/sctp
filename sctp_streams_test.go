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
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	STREAM_TEST_CLIENTS = 128
	STREAM_TEST_STREAMS = 11
)

func TestStreams(t *testing.T) {
	var rMu sync.Mutex
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomStr := func(strlen int) string {
		const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		result := make([]byte, strlen)
		rMu.Lock()
		for i := range result {
			result[i] = chars[r.Intn(len(chars))]
		}
		rMu.Unlock()
		return string(result)
	}

	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTPExt("sctp", addr, InitMsg{NumOstreams: STREAM_TEST_STREAMS, MaxInstreams: STREAM_TEST_STREAMS})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr = ln.Addr().(*SCTPAddr)
	t.Logf("Listen on %s", ln.Addr())

	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				// Closing the listener is how this loop is meant to stop.
				// Close shuts the listening socket down before releasing it,
				// so accept4 reports EINVAL on a socket that has been shut
				// down and EBADF once the descriptor is gone. Either means
				// the listener is closing, not that accepting failed.
				if errors.Is(err, syscall.EBADF) || errors.Is(err, syscall.EINVAL) {
					return
				}
				t.Errorf("failed to accept: %v", err)
				return
			}
			// Assert only once err is known to be nil. Accept returns a nil
			// connection alongside its error, and asserting first yields a
			// nil *SCTPConn whose every call then fails with EBADF.
			sconn, ok := c.(*SCTPConn)
			if !ok || sconn == nil {
				t.Errorf("accept returned %T, want *SCTPConn", c)
				return
			}

			// This test asserts on info.Stream for every message, which only
			// arrives as ancillary data while this subscription holds. An
			// unreported failure here would make every read return nil info
			// and the stream checks would compare against zero.
			if err := sconn.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
				t.Errorf("server subscribe: %v", err)
				_ = sconn.Close()
				return
			}
			serverWG.Add(1)
			go func(sconn *SCTPConn) {
				// Close per connection, not per accept loop: the original
				// deferred this inside the loop, so nothing was released
				// until the loop itself ended.
				defer serverWG.Done()
				defer func() { _ = sconn.Close() }()
				totalrcvd := 0
				for {
					buf := make([]byte, 512)
					n, info, err := sconn.SCTPRead(buf)
					if err != nil {
						if err == io.EOF || err == io.ErrUnexpectedEOF {
							if n == 0 {
								break
							}
							t.Logf("EOF on server connection. Total bytes received: %d, bytes received: %d", totalrcvd, n)
						} else if errors.Is(err, syscall.ECONNRESET) {
							// The client has gone. Whether it shut down or
							// aborted is its business; this echo loop is done.
							t.Logf("peer reset after %d bytes", totalrcvd)
							return
						} else {
							t.Errorf("Server connection read err: %v. Total bytes received: %d, bytes received: %d", err, totalrcvd, n)
							return
						}
					}
					totalrcvd += n
					t.Logf("server read: info: %+v, payload: %s", info, string(buf[:n]))
					// Check what was written rather than discarding it: a short
					// write here would desynchronise the echo the client is
					// waiting on, and the client would report a payload
					// mismatch far from the cause.
					wn, err := sconn.SCTPWrite(buf[:n], info)
					if err != nil {
						t.Error(err)
						return
					}
					if wn != n {
						t.Errorf("echoed %d of %d bytes", wn, n)
						return
					}
				}
			}(sconn)
		}
	}()

	var clientWG sync.WaitGroup
	clientWG.Add(STREAM_TEST_CLIENTS)
	for i := 0; i < STREAM_TEST_CLIENTS; i++ {
		go func(test int) {
			defer clientWG.Done()
			conn, err := DialSCTPExt(
				"sctp", nil, addr, InitMsg{NumOstreams: STREAM_TEST_STREAMS, MaxInstreams: STREAM_TEST_STREAMS})
			if err != nil {
				t.Errorf("failed to dial address %s, test #%d: %v", addr.String(), test, err)
				return
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
				t.Errorf("client %d subscribe: %v", test, err)
				return
			}
			for ppid := uint16(0); ppid < STREAM_TEST_STREAMS; ppid++ {
				info := &SndRcvInfo{
					Stream: uint16(ppid),
					PPID:   uint32(ppid),
				}
				rMu.Lock()
				randomLen := r.Intn(255)
				rMu.Unlock()
				text := fmt.Sprintf("Test %s ***\n\t\t%d %d ***", randomStr(randomLen), test, ppid)
				n, err := conn.SCTPWrite([]byte(text), info)
				if err != nil {
					t.Errorf("failed to write %s, len: %d, err: %v, bytes written: %d", text, len(text), err, n)
					return
				}
				rn := 0
				cn := 0
				buf := make([]byte, 512)
				for {
					cn, info, err = conn.SCTPRead(buf[rn:])
					if err != nil {
						if err == io.EOF || err == io.ErrUnexpectedEOF {
							rn += cn
							break
						}
						t.Errorf("failed to read: %v", err)
						return
					}
					if info.Stream != ppid {
						t.Errorf("Mismatched PPIDs: %d != %d", info.Stream, ppid)
						return
					}
					rn += cn
					if rn >= n {
						break
					}
				}
				rtext := string(buf[:rn])
				if rtext != text {
					// Errorf, not Fatalf: this runs on a client goroutine,
					// and Fatalf may only be called from the test goroutine.
					t.Errorf("Mismatched payload: %s != %s", rtext, text)
					return
				}
			}
		}(i)
	}

	// Wait for every client before touching the listener. Closing it while
	// clients are still exchanging data tears down the associations they are
	// using, and each peer then reports ECONNRESET.
	clientDone := make(chan struct{})
	go func() {
		clientWG.Wait()
		close(clientDone)
	}()
	select {
	case <-clientDone:
	case <-time.After(time.Second * 30):
		t.Fatal("timed out waiting for clients")
	}

	// Now stop accepting. Without this the accept loop outlives the test and
	// its t.Errorf calls are attributed to whichever test is running when
	// they fire.
	if err := ln.Close(); err != nil {
		t.Errorf("listener close: %v", err)
	}

	serverDone := make(chan struct{})
	go func() {
		serverWG.Wait()
		close(serverDone)
	}()
	select {
	case <-serverDone:
	case <-time.After(time.Second * 30):
		t.Fatal("timed out waiting for the server goroutines")
	}
}
