//go:build linux

// Reproducer for the SCTPRead truncation defect, mirroring the reported
// M3UA-style failure: a length-prefixed framed protocol read into a
// fixed 1500-byte buffer.
//
// Pass -fixed to use the MSG_EOR-aware path instead of plain SCTPRead.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ishidawataru/sctp"
)

const bufSize = 1500

// frame is a minimal length-prefixed encoding, standing in for M3UA.
func frame(payload []byte) []byte {
	b := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(b[:4], uint32(len(payload)))
	copy(b[4:], payload)
	return b
}

func parseFrame(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("short frame: %d bytes", len(b))
	}
	n := binary.BigEndian.Uint32(b[:4])
	if int(n) != len(b)-4 {
		return nil, fmt.Errorf("length prefix says %d, have %d", n, len(b)-4)
	}
	return b[4:], nil
}

func main() {
	fixed := flag.Bool("fixed", false, "use the MSG_EOR-aware read path")
	flag.Parse()

	addr, err := sctp.ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	ln, err := sctp.ListenSCTP("sctp", addr)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	sizes := []int{1024, 1400, 1600, 4096, 16384}

	type result struct {
		size int
		ok   bool
		note string
	}
	results := make(chan result, len(sizes))

	go func() {
		conn, err := ln.AcceptSCTP()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		for range sizes {
			var (
				raw []byte
				err error
			)
			if *fixed {
				raw, _, err = conn.ReadMsg(1 << 20)
			} else {
				buf := make([]byte, bufSize)
				var n int
				n, _, err = conn.SCTPRead(buf)
				raw = buf[:n]
			}
			if err != nil {
				results <- result{0, false, "read error: " + err.Error()}
				continue
			}
			payload, perr := parseFrame(raw)
			if perr != nil {
				// This is the silent-loss case: the frame is discarded and
				// neither peer learns about it.
				results <- result{len(raw), false, "DROPPED: " + perr.Error()}
				continue
			}
			results <- result{len(payload), true, "delivered intact"}
		}
	}()

	client, err := sctp.DialSCTP("sctp", nil, ln.Addr().(*sctp.SCTPAddr))
	if err != nil {
		panic(err)
	}
	defer client.Close()

	for _, size := range sizes {
		if _, err := client.SCTPWrite(frame(bytes.Repeat([]byte{0x5A}, size)), nil); err != nil {
			panic(err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	mode := "plain SCTPRead"
	if *fixed {
		mode = "ReadMsg (MSG_EOR aware)"
	}
	fmt.Printf("mode: %s, read buffer: %d bytes\n", mode, bufSize)
	fmt.Printf("%-8s  %-8s  %s\n", "SENT", "GOT", "RESULT")

	lost := 0
	for i := 0; i < len(sizes); i++ {
		r := <-results
		status := "ok"
		if !r.ok {
			status = "LOST"
			lost++
		}
		fmt.Printf("%-8d  %-8d  %-5s %s\n", sizes[i], r.size, status, r.note)
	}

	fmt.Printf("\n%d/%d messages lost\n", lost, len(sizes))
	if *fixed && lost > 0 {
		os.Exit(1)
	}
}
