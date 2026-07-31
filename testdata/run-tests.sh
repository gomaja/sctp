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

# AUTH (RFC 4895) is off by default in Linux, and the whole AUTH group skips
# without it: the key management tests, the SCTP_AUTHINFO send path, and the
# cmsg padding test — a 2-byte AuthInfo is the only cmsg whose padding bytes are
# non-zero, so nothing else can prove the padding is written correctly. Skipping
# them reads as a clean run while leaving those paths entirely unexercised.
if sysctl -w net.sctp.auth_enable=1 >/dev/null 2>&1; then
    echo "Enabled net.sctp.auth_enable for the AUTH tests."
else
    echo "Could not enable net.sctp.auth_enable; the AUTH tests will skip." >&2
fi

# Extra loopback addresses. TestKernelAddrsRoundTrip needs a second one to prove
# the kernel's multi-address reply is decoded per entry — with one address the
# loop body runs once and a per-entry decoding bug cannot show. The multi-homing
# tests need more: an association with two addresses on each side, which is
# SCTP's defining feature over TCP and cannot be exercised at all on a host with
# a single address.
added=""
for a in 127.0.0.2 127.0.0.3 127.0.0.4; do
    if ip addr show dev lo 2>/dev/null | grep -q "inet $a"; then
        continue
    fi
    if ip addr add "$a/8" dev lo 2>/dev/null; then
        added="$added $a"
    fi
done
have=$(ip -4 addr show dev lo 2>/dev/null | grep -cE 'inet 127\.0\.0\.[0-9]+')
if [ -n "$added" ]; then
    echo "Added loopback addresses:$added (now $have total)."
else
    echo "Loopback addresses already configured ($have total)."
fi
if [ "${have:-0}" -lt 3 ]; then
    echo "Fewer than 3 loopback addresses; the multi-homing tests will skip." \
         "The container needs --privileged." >&2
fi

go build ./...

# `go vet ... | grep -v ... || true` used to be here, which discarded vet's exit
# status: the pipeline's status is grep's, and the `|| true` swallowed even
# that, so `set -e` never saw a failure. The step ran and could not fail. Keep
# the filter but take the status from vet itself.
vet_out=$(go vet ./... 2>&1) || {
    echo "$vet_out" | grep -v 'non-test goroutine' >&2
    echo "go vet failed" >&2
    exit 1
}
echo "$vet_out" | grep -v 'non-test goroutine' || true

go test "$@"
status=$?

# Two AUTH tests assert the errno a caller gets on a stock kernel — EACCES, not
# EOPNOTSUPP, which is the first surprise anyone using AUTH hits. They skip
# when net.sctp.auth_enable is on, and the setup above turns it on for the other
# seven, so in the documented harness they had never run once: the suite read
# green with that contract entirely unexercised.
#
# So they get their own pass with the sysctl back at its default. Restore it
# afterwards either way, or a second run in the same container inherits the
# wrong value.
if [ -w /proc/sys/net/sctp/auth_enable ]; then
    echo "Second pass: the AUTH-disabled contract, with net.sctp.auth_enable=0."
    sysctl -w net.sctp.auth_enable=0 >/dev/null 2>&1 || true
    go test -run 'TestAuthDisabledReportsEACCES|TestAuthOptionsWithoutSysctl' \
        -count=1 -v . || status=1
    sysctl -w net.sctp.auth_enable=1 >/dev/null 2>&1 || true
fi

exit $status
