package main

// Proves SubscribeEvent changes what the kernel delivers, not merely what the
// option struct contains.
//
// Three cases run against a real association, each tearing it down the same way
// and differing only in the subscription:
//
//	subscribed   via SubscribeEvent   -> a notification must arrive
//	unsubscribed via SubscribeEvent   -> no notification may arrive
//	bulk         via SubscribeEvents  -> a notification must arrive
//
// The unsubscribed case is the one that gives the others meaning: a build that
// delivered notifications unconditionally would pass the first and third and
// fail only this one.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/ishidawataru/sctp"
)

type outcome struct {
	name          string
	wantNotify    bool
	gotNotify     bool
	notifyType    uint16
	err           error
}

// pair brings up one association and returns both ends.
func pair() (*sctp.SCTPConn, *sctp.SCTPConn, func(), error) {
	addr, err := sctp.ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, nil, err
	}
	ln, err := sctp.ListenSCTP("sctp", addr)
	if err != nil {
		return nil, nil, nil, err
	}
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, aerr := ln.Accept()
		ch <- res{c, aerr}
	}()
	client, err := sctp.DialSCTP("sctp", nil, ln.Addr().(*sctp.SCTPAddr))
	if err != nil {
		_ = ln.Close()
		return nil, nil, nil, err
	}
	r := <-ch
	if r.err != nil {
		_ = ln.Close()
		_ = client.Close()
		return nil, nil, nil, r.err
	}
	srv, ok := r.c.(*sctp.SCTPConn)
	if !ok {
		_ = ln.Close()
		_ = client.Close()
		return nil, nil, nil, fmt.Errorf("accepted %T, want *sctp.SCTPConn", r.c)
	}
	cleanup := func() {
		_ = srv.Close()
		_ = client.Close()
		_ = ln.Close()
	}
	return client, srv, cleanup, nil
}

// run subscribes per mode, aborts from the peer, and reports whether a
// notification was delivered to the surviving side.
func run(mode string) outcome {
	o := outcome{name: mode}
	switch mode {
	case "subscribed", "bulk":
		o.wantNotify = true
	}

	client, srv, cleanup, err := pair()
	if err != nil {
		o.err = err
		return o
	}
	defer cleanup()

	switch mode {
	case "subscribed":
		// ASSOC_CHANGE is what an abort surfaces as.
		if err := srv.SubscribeEvent(sctp.SCTP_ASSOC_CHANGE, true); err != nil {
			o.err = fmt.Errorf("SubscribeEvent: %w", err)
			return o
		}
	case "unsubscribed":
		if err := srv.SubscribeEvent(sctp.SCTP_ASSOC_CHANGE, false); err != nil {
			o.err = fmt.Errorf("SubscribeEvent(off): %w", err)
			return o
		}
	case "bulk":
		if err := srv.SubscribeEvents(sctp.SCTP_EVENT_ASSOCIATION); err != nil {
			o.err = fmt.Errorf("SubscribeEvents: %w", err)
			return o
		}
	}

	// Abort from the client so the server sees a terminal association change.
	if err := client.Abort(); err != nil {
		o.err = fmt.Errorf("abort: %w", err)
		return o
	}

	// Read with a bounded deadline; MSG_NOTIFICATION distinguishes a
	// notification from ordinary data or an error.
	if err := srv.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		o.err = fmt.Errorf("deadline: %w", err)
		return o
	}
	buf := make([]byte, 512)
	for {
		n, _, flags, rerr := srv.SCTPReadFlags(buf)
		if rerr != nil {
			if errors.Is(rerr, syscall.EAGAIN) || errors.Is(rerr, syscall.EWOULDBLOCK) ||
				errors.Is(rerr, syscall.ECONNRESET) || errors.Is(rerr, syscall.ETIMEDOUT) {
				return o // nothing delivered
			}
			return o
		}
		if flags&sctp.MSG_NOTIFICATION != 0 && n >= 2 {
			o.gotNotify = true
			nt, perr := sctp.ParseNotification(buf[:n])
			if perr == nil {
				o.notifyType = uint16(nt.Type())
			}
			return o
		}
		// Ordinary data: keep reading until the notification or the deadline.
	}
}

func main() {
	fail := false
	for _, mode := range []string{"subscribed", "unsubscribed", "bulk"} {
		o := run(mode)
		if o.err != nil {
			fmt.Printf("%-13s ERROR %v\n", o.name+":", o.err)
			fail = true
			continue
		}
		status := "ok"
		if o.gotNotify != o.wantNotify {
			status = "MISMATCH"
			fail = true
		}
		fmt.Printf("%-13s notification=%-5v want=%-5v type=0x%04x  %s\n",
			o.name+":", o.gotNotify, o.wantNotify, o.notifyType, status)
	}
	if fail {
		fmt.Println("FAIL")
		os.Exit(1)
	}
	fmt.Println("OK: SubscribeEvent controls what the kernel delivers")
}
