//go:build linux

// Drives the library's own notification path so a capture taken alongside it
// can be compared against what the API reported.
//
// The point is to correlate the two: the association teardown that tshark sees
// as SHUTDOWN / SHUTDOWN_ACK / SHUTDOWN_COMPLETE chunks on the wire is the same
// event the kernel reports up as SCTP_SHUTDOWN_EVENT and SCTP_ASSOC_CHANGE, and
// ParseNotification must agree with both.
package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/ishidawataru/sctp"
)

func main() {
	subscribe := flag.Bool("subscribe", true, "subscribe to association and shutdown events")
	abort := flag.Bool("abort", false, "tear the association down with ABORT instead of a graceful shutdown")
	flag.Parse()

	var (
		mu  sync.Mutex
		raw [][]byte
	)
	cfg := &sctp.SocketConfig{
		NotificationHandler: func(b []byte) error {
			mu.Lock()
			raw = append(raw, append([]byte(nil), b...))
			mu.Unlock()
			return nil
		},
	}

	addr, err := sctp.ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	ln, err := cfg.Listen("sctp", addr)
	if err != nil {
		panic(err)
	}
	defer func() { _ = ln.Close() }()

	type accepted struct {
		conn *sctp.SCTPConn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		c, err := ln.AcceptSCTP()
		accCh <- accepted{c, err}
	}()

	client, err := sctp.DialSCTP("sctp", nil, ln.Addr().(*sctp.SCTPAddr))
	if err != nil {
		panic(err)
	}
	acc := <-accCh
	if acc.err != nil {
		panic(acc.err)
	}
	server := acc.conn

	if *subscribe {
		if err := server.SubscribeEvents(
			sctp.SCTP_EVENT_ASSOCIATION | sctp.SCTP_EVENT_SHUTDOWN); err != nil {
			panic(err)
		}
		fmt.Println("subscribed: SCTP_EVENT_ASSOCIATION | SCTP_EVENT_SHUTDOWN")
	} else {
		fmt.Println("NOT subscribed to any events")
	}

	// Send one message so there is DATA on the wire to anchor the capture.
	if _, err := client.SCTPWrite([]byte("hello"), nil); err != nil {
		panic(err)
	}
	buf := make([]byte, sctp.NotificationMaxSize)
	if _, _, err := server.SCTPRead(buf); err != nil {
		panic(err)
	}

	// Tear the association down. A graceful Close puts SHUTDOWN on the wire;
	// Abort puts an ABORT chunk there instead.
	if *abort {
		fmt.Println("tearing down with ABORT")
		if err := client.Abort(); err != nil {
			panic(err)
		}
	} else {
		fmt.Println("tearing down with graceful shutdown")
		if err := client.Close(); err != nil {
			panic(err)
		}
	}

	// Drain so the notifications are delivered to the handler.
	for i := 0; i < 16; i++ {
		if _, _, err := server.SCTPRead(buf); err != nil {
			break
		}
	}
	_ = server.Abort()

	mu.Lock()
	captured := raw
	mu.Unlock()

	fmt.Printf("notifications delivered to the API: %d\n", len(captured))
	for i, b := range captured {
		n, err := sctp.ParseNotification(b)
		if err != nil {
			fmt.Printf("  [%d] %d bytes: ParseNotification failed: %v\n", i, len(b), err)
			os.Exit(1)
		}
		if n == nil {
			fmt.Printf("  [%d] %d bytes: type %d not modelled\n", i, len(b), b[0])
			continue
		}
		switch v := n.(type) {
		case *sctp.AssocChange:
			fmt.Printf("  [%d] ASSOC_CHANGE  len=%d state=%v assoc=%d in=%d out=%d\n",
				i, n.Length(), v.State, v.AssocID, v.InboundStreams, v.OutboundStreams)
		case *sctp.Shutdown:
			fmt.Printf("  [%d] SHUTDOWN      len=%d assoc=%d\n", i, n.Length(), v.AssocID)
		default:
			fmt.Printf("  [%d] %T len=%d\n", i, v, n.Length())
		}
		if int(n.Length()) != len(b) {
			fmt.Printf("      MISMATCH: header says %d bytes, kernel delivered %d\n",
				n.Length(), len(b))
			os.Exit(1)
		}
	}
}
