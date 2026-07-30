#!/usr/bin/env bash
# Runs the Go test suite inside the container against a real SCTP stack.
set -euo pipefail

modprobe sctp 2>/dev/null || true

if [ ! -e /proc/net/sctp/snmp ]; then
    echo "SCTP not available in this kernel; cannot run the suite." >&2
    exit 1
fi
echo "SCTP stack present."

# Blackhole SCTP to TEST-NET-1 so an INIT sent there goes unanswered rather than
# drawing an ICMP unreachable from the gateway. Without this the connect fails
# immediately with ECONNREFUSED, no association is left in COOKIE_WAIT, and
# TestSCTPConnectEALREADYOnBlockingSocketMidHandshake skips — which would hide
# whether the EALREADY handling in SCTPConnect works at all.
if command -v iptables >/dev/null 2>&1; then
    if iptables -C OUTPUT -d 192.0.2.1 -j DROP 2>/dev/null; then
        echo "TEST-NET-1 already blackholed."
    elif iptables -A OUTPUT -d 192.0.2.1 -j DROP 2>/dev/null; then
        echo "Blackholed TEST-NET-1 for the EALREADY tests."
    else
        echo "Could not add the iptables DROP rule; the blocking EALREADY test" \
             "will skip. The container needs --privileged." >&2
    fi
else
    echo "iptables not installed; the blocking EALREADY test will skip." >&2
fi

go build ./...
go vet ./... 2>&1 | grep -v 'non-test goroutine' || true

exec go test "$@"
