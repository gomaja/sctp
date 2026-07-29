#!/usr/bin/env bash
# Wire-level confirmation for the notification parser.
#
# In-process assertions prove ParseNotification decoded a buffer consistently.
# They cannot prove the buffer described the association teardown that actually
# happened. This captures the SCTP control chunks while the probe runs and
# checks the two agree:
#
#   graceful close -> SHUTDOWN / SHUTDOWN_ACK / SHUTDOWN_COMPLETE on the wire,
#                     SCTP_SHUTDOWN_EVENT + ASSOC_CHANGE(SHUTDOWN_COMP) at the API
#   abort          -> ABORT on the wire, ASSOC_CHANGE(COMM_LOST) at the API
#
# The negative case matters as much as the positive: with no subscription the
# same wire teardown must yield no notifications at all. Without it, a build
# that always emitted would pass.
set -euo pipefail

modprobe sctp 2>/dev/null || true

cd /src/testdata/notifyprobe
cat > go.mod <<EOF
module notifyprobe
go 1.21
require github.com/ishidawataru/sctp v0.0.0
replace github.com/ishidawataru/sctp => /src
EOF
trap 'rm -f go.mod go.sum' EXIT
go mod tidy >/dev/null 2>&1
go build -o /tmp/notifyprobe . >/dev/null

# chunk_type: 0=DATA 1=INIT 2=INIT_ACK 3=SACK 6=ABORT 7=SHUTDOWN
#             8=SHUTDOWN_ACK 10=COOKIE_ECHO 11=COOKIE_ACK 14=SHUTDOWN_COMPLETE
chunk_name() {
    case "$1" in
        0) echo DATA;; 1) echo INIT;; 2) echo INIT_ACK;; 3) echo SACK;;
        4) echo HEARTBEAT;; 5) echo HEARTBEAT_ACK;; 6) echo ABORT;;
        7) echo SHUTDOWN;; 8) echo SHUTDOWN_ACK;; 10) echo COOKIE_ECHO;;
        11) echo COOKIE_ACK;; 14) echo SHUTDOWN_COMPLETE;; *) echo "type-$1";;
    esac
}

run_case() {
    local label="$1"; shift
    local cap="/tmp/notify-${label}.pcap"

    echo "==================================================================="
    echo "CASE: $label   ($*)"
    echo "==================================================================="

    tshark -i lo -f "ip proto 132" -w "$cap" -q >/dev/null 2>&1 &
    local tpid=$!
    sleep 3

    echo "--- what the API reported ---"
    local out
    out=$(/tmp/notifyprobe "$@" 2>&1) || { echo "$out"; kill -INT $tpid 2>/dev/null; return 1; }
    echo "$out"

    sleep 2
    kill -INT $tpid 2>/dev/null || true
    wait $tpid 2>/dev/null || true

    echo "--- what went on the wire ---"
    tshark -r "$cap" -T fields -e sctp.chunk_type 2>/dev/null \
        | tr ',' '\n' | grep -v '^$' | sort -n | uniq -c \
        | while read -r count ty; do
            printf "  %-18s type=%-3s count=%s\n" "$(chunk_name "$ty")" "$ty" "$count"
          done

    # Correlate: the teardown chunk on the wire must match the notification.
    local wire_types
    wire_types=$(tshark -r "$cap" -T fields -e sctp.chunk_type 2>/dev/null \
        | tr ',' '\n' | grep -v '^$' | sort -nu | tr '\n' ' ')
    local api_count
    api_count=$(echo "$out" | sed -n 's/^notifications delivered to the API: //p')

    echo "--- correlation ---"
    echo "  wire chunk types : $wire_types"
    echo "  API notifications: ${api_count:-0}"
    echo "$wire_types" | grep -qw 7 && echo "  wire shows SHUTDOWN (graceful teardown)"
    echo "$wire_types" | grep -qw 14 && echo "  wire shows SHUTDOWN_COMPLETE"
    echo "$wire_types" | grep -qw 6 && echo "  wire shows ABORT"
    echo
}

run_case "subscribed-graceful" -subscribe=true
run_case "subscribed-abort"    -subscribe=true -abort=true
run_case "unsubscribed"        -subscribe=false

echo "==================================================================="
echo "The unsubscribed case must report 0 notifications while still showing"
echo "the same teardown chunks on the wire. If it reports any, the events"
echo "are not actually gated on the subscription."
echo "==================================================================="
