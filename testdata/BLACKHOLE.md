# Detecting an unreachable peer (the "black hole")

When a peer stops responding without tearing the association down — a route
withdrawn, a firewall starting to drop, a host that vanished — SCTP does not
report anything for a long time. Writes keep being accepted into the send
queue, the queue fills, the socket sits in `CLOSE_WAIT`, and rebinding the same
local address fails with `EADDRINUSE`. Nothing surfaces to the application.

## Why it takes so long

Two association parameters decide it, and their defaults are conservative:

| Parameter | Default | Effect |
|---|---|---|
| `RtoInfo.Max` (`SCTP_RTOINFO`) | 60000 ms | Retransmissions back off exponentially up to this cap. |
| `AssocInfo.AsocMaxRxt` (`SCTP_ASSOCINFO`) | 10 | Consecutive failed retransmissions before the association is declared failed. |

`AsocMaxRxt` is `Association.Max.Retrans` from RFC 9260 section 8.1 (RFC 9260
obsoleted RFC 4960; section 8.2 is the per-path counter, not this one). Ten
retransmissions backing off toward a sixty second ceiling is several minutes
before anything is reported.

## Measured

A reproduction with traffic between the two endpoints dropped by an iptables
rule, writing continuously throughout:

```
mode=DEFAULT  rto(initial=3000 max=60000 min=1000) asocMaxRxt=10
  writes=286  elapsed=25.09s
  status: state=4 peerState=0 unackdata=84 penddata=0
  RESULT: no failure reported within 25s - the black hole is still silent

mode=TUNED    rto(initial=500 max=1000 min=200)    asocMaxRxt=3
  writes=29   elapsed=1.483s
  RESULT: failure reported after 1.483s: connection timed out
```

Note `peerState=0` in the untuned run: that is `SCTP_INACTIVE`, so the kernel
had already given up on the path while the association as a whole had not.

## Tuning it

```go
conn, err := sctp.DialSCTP("sctp", laddr, raddr)
// ...

// Cap the retransmission backoff.
if err := conn.SetRtoInfo(&sctp.RtoInfo{
    Initial: 500,  // ms
    Max:     1000,
    Min:     200,
}); err != nil {
    return err
}

// Bound the retry budget.
if err := conn.SetAssocInfo(&sctp.AssocInfo{AsocMaxRxt: 3}); err != nil {
    return err
}
```

Pick the values against the link, not from this example. Too aggressive and a
brief congestion event tears down a healthy association; the numbers above are
chosen to make the failure obvious in a test, not to be a recommendation.

## Watching for it without waiting

Polling `GetStatus` shows the problem before the association is formally
declared dead:

```go
st, err := conn.GetStatus()
if err != nil {
    // The association may already be gone.
}
switch {
case st.PrimaryPeerAddr.State == sctp.SCTP_INACTIVE:
    // The path has failed Path.Max.Retrans; the peer is unreachable.
case st.PrimaryPeerAddr.State == sctp.SCTP_PF:
    // RFC 7829 potentially-failed: retransmissions are failing.
case st.Unackdata > threshold:
    // Data is accumulating unacknowledged: sends are not getting through.
}
```

`AssocInfo.PeerRwnd` is a useful companion — it stops moving once the peer
stops acknowledging.

## SO_REUSEADDR does not help here

A reasonable guess is that `SO_REUSEADDR` would let the address be rebound
while the old association is still lingering. It does not — but the reason is
narrower than "it changes nothing", which is what this section used to say.

The kernel's test in `sctp_get_port_local` is

```c
reuse && (sk2->sk_reuse || sp2->reuse) && sk2->sk_state != SCTP_SS_LISTENING
```

so the flag has to be on **both** sockets, and the incumbent must not be
listening. All four combinations, for each kind of incumbent:

```
incumbent is LISTENING:
  incumbent reuse=0 | rebinder reuse=0 -> Address already in use
  incumbent reuse=0 | rebinder reuse=1 -> Address already in use
  incumbent reuse=1 | rebinder reuse=0 -> Address already in use
  incumbent reuse=1 | rebinder reuse=1 -> Address already in use

incumbent is BOUND but not listening:
  incumbent reuse=0 | rebinder reuse=0 -> Address already in use
  incumbent reuse=0 | rebinder reuse=1 -> Address already in use
  incumbent reuse=1 | rebinder reuse=0 -> Address already in use
  incumbent reuse=1 | rebinder reuse=1 -> ALLOWED
```

So there is exactly one cell where it makes a difference, and the wedged-address
scenario is not it: the incumbent there is a listener or a live association, and
this package never sets `SO_REUSEADDR` on anything, so the incumbent's flag is
always clear — the case where reuse changes nothing.

Unlike TCP there is no TIME_WAIT state to bypass either, so rebinding after a
clean close already works without it.

## Reproducing it

`iptables` inside a privileged container, dropping traffic between two loopback
addresses in both directions:

```sh
iptables -A INPUT -s 127.0.0.1 -d 127.0.0.2 -j DROP
iptables -A INPUT -s 127.0.0.2 -d 127.0.0.1 -j DROP
```

Watch it with `netstat -an | grep sctp`. The established association becomes
`CLOSE_WAIT` on the sending side and eventually disappears, and the address
stays occupied until it does. Remove the rules with the same commands and `-D`.

The container needs `--privileged --cap-add=NET_ADMIN` and `iptables`
installed.
