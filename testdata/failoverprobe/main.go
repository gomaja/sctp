// Command failoverprobe drives one multi-homed association across two real
// interfaces so a path can be cut underneath it.
//
// It runs as either end of the association. The client sends a numbered message
// every 250ms and requires the echo back, reporting how many round trips
// succeeded and how many failed, so cutting a path mid-run shows up as a
// count rather than as something to eyeball.
//
// This cannot be a Go test. Failover needs two hosts on two networks with a
// firewall between them: a container's own interfaces route through loopback,
// so a DROP rule on one of them is not a path failure and the kernel never
// marks the path down. testdata/failover.sh sets up the two containers and the
// networks and runs this on both.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ishidawataru/sctp"
)

// addrOf builds an SCTPAddr from a comma-separated list of addresses, which is
// how the script passes each end its own set and its peer's.
func addrOf(csv string, port int) *sctp.SCTPAddr {
	a := &sctp.SCTPAddr{Port: port}
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			a.IPAddrs = append(a.IPAddrs, net.IPAddr{IP: net.ParseIP(s)})
		}
	}
	return a
}

func main() {
	server := flag.Bool("server", false, "run as the echo server")
	local := flag.String("local", "", "comma-separated local addresses")
	remote := flag.String("remote", "", "comma-separated remote addresses")
	port := flag.Int("port", 15000, "port")
	secs := flag.Int("secs", 30, "how long the client keeps sending")
	flag.Parse()

	if *server {
		runServer(*local, *port)
		return
	}
	runClient(*local, *remote, *port, *secs)
}

func runServer(local string, port int) {
	ln, err := sctp.ListenSCTP("sctp", addrOf(local, port))
	if err != nil {
		fmt.Println("listen:", err)
		os.Exit(1)
	}
	// The script waits for this line before starting the client.
	fmt.Println("SERVER-READY")
	for {
		c, err := ln.AcceptSCTP()
		if err != nil {
			return
		}
		go func(c *sctp.SCTPConn) {
			defer func() { _ = c.Close() }()
			buf := make([]byte, 2048)
			for {
				n, _, rerr := c.SCTPRead(buf)
				if rerr != nil {
					return
				}
				if _, werr := c.SCTPWrite(buf[:n], nil); werr != nil {
					return
				}
			}
		}(c)
	}
}

func runClient(local, remote string, port, secs int) {
	c, err := sctp.DialSCTP("sctp", addrOf(local, 0), addrOf(remote, port))
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	defer func() { _ = c.Close() }()

	// Report the paths the association actually negotiated. With one address
	// on either side this prints a single entry, which is what makes the
	// single-homed control run distinguishable from the multi-homed one.
	if pa, perr := c.SCTPRemoteAddr(0); perr == nil {
		fmt.Printf("PEER-PATHS=%v\n", pa.IPAddrs)
	}
	fmt.Println("CLIENT-UP")

	buf := make([]byte, 2048)
	var sent, ok, failed int
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	for time.Now().Before(deadline) {
		msg := fmt.Sprintf("hb-%d", sent)
		sent++

		// A deadline per round trip, so a dead path surfaces as a timeout
		// rather than hanging the probe until the script's own timeout.
		if derr := c.SetDeadline(time.Now().Add(10 * time.Second)); derr != nil {
			fmt.Printf("DEADLINE-FAIL %d: %v\n", sent, derr)
			return
		}
		if _, werr := c.SCTPWrite([]byte(msg), nil); werr != nil {
			failed++
			fmt.Printf("WRITE-FAIL %d: %v\n", sent, werr)
			time.Sleep(250 * time.Millisecond)
			continue
		}
		n, _, rerr := c.SCTPRead(buf)
		if rerr != nil {
			failed++
			fmt.Printf("READ-FAIL %d: %v\n", sent, rerr)
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if string(buf[:n]) == msg {
			ok++
		} else {
			failed++
			fmt.Printf("MISMATCH %d: got %q\n", sent, buf[:n])
		}
		time.Sleep(250 * time.Millisecond)
	}

	fmt.Printf("RESULT sent=%d ok=%d failed=%d\n", sent, ok, failed)
	if ok == 0 {
		os.Exit(1)
	}
}
