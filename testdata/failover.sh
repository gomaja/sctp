#!/usr/bin/env bash
# Path failover: does a multi-homed association survive losing a path?
#
# This is the one thing the multi-homing tests in the Go suite cannot cover.
# They bind several loopback aliases, which proves the addresses are negotiated,
# but a loopback path cannot be taken down: traffic between two of a host's own
# addresses is routed through lo, so an iptables DROP on one of them is not a
# path failure and the kernel never marks the path unreachable.
#
# Real failover needs two hosts on two networks with a firewall between them,
# so this runs OUTSIDE the container the rest of the suite uses. It builds two
# containers, attaches each to two docker networks, establishes an association
# across both, and cuts one path underneath it.
#
# Two cases run, and the second is what gives the first its meaning:
#
#   multi-homed   two paths, one cut mid-association  -> traffic must continue
#   single-homed  one path, cut mid-association       -> traffic must fail
#
# Without the control run, a cut that silently did nothing would look identical
# to successful failover.
#
# Run from the repository root:
#     bash testdata/failover.sh
set -euo pipefail

IMAGE=sctp-test
NET_A=sctp-failover-a
NET_B=sctp-failover-b
SRV=sctp-failover-srv
CLI=sctp-failover-cli
SRV_A=172.30.0.10 SRV_B=172.31.0.10
CLI_A=172.30.0.20 CLI_B=172.31.0.20

cleanup() {
    docker rm -f "$SRV" "$CLI" >/dev/null 2>&1 || true
    docker network rm "$NET_A" "$NET_B" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "The $IMAGE image is missing. Build it first:" >&2
    echo "    docker build -t $IMAGE -f testdata/Dockerfile testdata/" >&2
    exit 1
fi

echo "Creating two networks..."
docker network create "$NET_A" --subnet 172.30.0.0/24 >/dev/null
docker network create "$NET_B" --subnet 172.31.0.0/24 >/dev/null

# Each container joins network A at creation and network B afterwards, which is
# what gives it two real interfaces on two different subnets.
start_container() {
    local name=$1 ip_a=$2 ip_b=$3
    docker run -d --name "$name" --privileged \
        --network "$NET_A" --ip "$ip_a" \
        -v "$PWD":/src -w /src "$IMAGE" sleep 900 >/dev/null
    docker network connect --ip "$ip_b" "$NET_B" "$name"
    docker exec "$name" bash -c 'modprobe sctp 2>/dev/null || true'
}

echo "Starting containers..."
start_container "$SRV" "$SRV_A" "$SRV_B"
start_container "$CLI" "$CLI_A" "$CLI_B"

echo "Building the probe..."
for c in "$SRV" "$CLI"; do
    docker exec "$c" bash -c '
        set -e
        mkdir -p /tmp/fo && cp /src/testdata/failoverprobe/main.go /tmp/fo/
        cd /tmp/fo
        cat > go.mod <<EOM
module failoverprobe
go 1.21
require github.com/ishidawataru/sctp v0.0.0
replace github.com/ishidawataru/sctp => /src
EOM
        go mod tidy >/dev/null 2>&1
        go build -o /tmp/failoverprobe .' >/dev/null
done

# cut_path installs DROP rules on the client for one of the server's addresses,
# in both directions, so the path is dead rather than half-open.
cut_path() {
    docker exec "$CLI" iptables -A OUTPUT -d "$1" -j DROP
    docker exec "$CLI" iptables -A INPUT -s "$1" -j DROP
}

# dropped_packets reports how many packets the DROP rules matched. A cut that
# matched nothing did not test anything, so the run is only meaningful if this
# is non-zero.
dropped_packets() {
    docker exec "$CLI" iptables -L -n -v -x 2>/dev/null \
        | awk '/DROP/ {sum += $1} END {print sum+0}'
}

run_case() {
    local label=$1 port=$2 srv_addrs=$3 cli_addrs=$4 expect=$5
    echo
    echo "=== $label ==="
    docker exec "$CLI" iptables -F >/dev/null 2>&1 || true

    docker exec -d "$SRV" bash -c \
        "/tmp/failoverprobe -server -local $srv_addrs -port $port > /tmp/srv-$port.log 2>&1"
    for _ in $(seq 1 30); do
        docker exec "$SRV" grep -q SERVER-READY "/tmp/srv-$port.log" 2>/dev/null && break
        sleep 0.5
    done

    docker exec -d "$CLI" bash -c \
        "/tmp/failoverprobe -local $cli_addrs -remote $srv_addrs -port $port -secs 30 > /tmp/cli-$port.log 2>&1"
    for _ in $(seq 1 30); do
        docker exec "$CLI" grep -q CLIENT-UP "/tmp/cli-$port.log" 2>/dev/null && break
        sleep 0.5
    done
    docker exec "$CLI" grep PEER-PATHS "/tmp/cli-$port.log" || true

    echo "Cutting $SRV_A ..."
    sleep 3
    cut_path "$SRV_A"

    while docker exec "$CLI" pgrep -f /tmp/failoverprobe >/dev/null 2>&1; do sleep 2; done

    local dropped result
    dropped=$(dropped_packets)
    result=$(docker exec "$CLI" grep RESULT "/tmp/cli-$port.log" || echo "RESULT missing")
    echo "$result"
    echo "packets dropped by the cut: $dropped"

    if [ "$dropped" -eq 0 ]; then
        echo "FAIL: the cut matched no packets, so this case proved nothing." >&2
        return 1
    fi

    local failed
    failed=$(echo "$result" | sed -n 's/.*failed=\([0-9]*\).*/\1/p')
    case "$expect" in
    survive)
        if [ "${failed:-1}" -eq 0 ]; then
            echo "PASS: every round trip succeeded across the cut."
        else
            echo "FAIL: $failed round trips failed; the association did not fail over." >&2
            return 1
        fi
        ;;
    break)
        if [ "${failed:-0}" -gt 0 ]; then
            echo "PASS: traffic failed as expected with no second path."
        else
            echo "FAIL: nothing failed, so the cut is not being applied and the" \
                 "multi-homed case above proves nothing." >&2
            return 1
        fi
        ;;
    esac
}

rc=0
run_case "Multi-homed: two paths, primary cut" 15000 \
    "$SRV_A,$SRV_B" "$CLI_A,$CLI_B" survive || rc=1
run_case "Single-homed control: one path, cut" 15001 \
    "$SRV_A" "$CLI_A" break || rc=1

echo
if [ $rc -eq 0 ]; then
    echo "FAILOVER RESULT: PASS"
else
    echo "FAILOVER RESULT: FAIL" >&2
fi
exit $rc
