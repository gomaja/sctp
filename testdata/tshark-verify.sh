#!/usr/bin/env bash
# Wire-level confirmation that the truncated messages are transmitted in full
# by the sender, i.e. that the loss is a receive-side API defect rather than
# anything happening on the network.
#
# Captures loopback SCTP while the reproducer runs, then uses tshark to total
# the DATA chunk payload bytes actually put on the wire.
set -euo pipefail

modprobe sctp 2>/dev/null || true
CAP=/tmp/sctp-capture.pcap

cd /src/testdata/repro
cat > go.mod <<EOF
module repro
go 1.21
require github.com/ishidawataru/sctp v0.0.0
replace github.com/ishidawataru/sctp => /src
EOF
trap 'rm -f go.mod go.sum' EXIT
go mod tidy >/dev/null 2>&1
go build -o /tmp/repro . >/dev/null

echo "Capturing loopback SCTP..."
tshark -i lo -f "ip proto 132" -w "$CAP" -q >/dev/null 2>&1 &
TPID=$!
sleep 3

/tmp/repro || true

sleep 2
kill -INT $TPID 2>/dev/null || true
wait $TPID 2>/dev/null || true

echo
echo "=== SCTP chunk types on the wire ==="
# 0=DATA 1=INIT 2=INIT_ACK 3=SACK 4=HEARTBEAT 10=COOKIE_ECHO 11=COOKIE_ACK
tshark -r "$CAP" -T fields -e sctp.chunk_type 2>/dev/null \
    | tr ',' '\n' | grep -v '^$' | sort -n | uniq -c \
    | awk '{
        name = "other";
        if ($2==0) name="DATA"; else if ($2==1) name="INIT";
        else if ($2==2) name="INIT_ACK"; else if ($2==3) name="SACK";
        else if ($2==4) name="HEARTBEAT"; else if ($2==5) name="HEARTBEAT_ACK";
        else if ($2==7) name="SHUTDOWN"; else if ($2==10) name="COOKIE_ECHO";
        else if ($2==11) name="COOKIE_ACK";
        printf "  %-14s type=%-3s count=%s\n", name, $2, $1
    }'

echo
echo "=== DATA chunk payload totals ==="
# Each DATA chunk's payload is (chunk length - 16 byte header). Sum only the
# lengths whose matching chunk_type is 0, since one frame may carry several
# chunks of different types.
tshark -r "$CAP" -T fields -e sctp.chunk_type -e sctp.chunk_length 2>/dev/null \
    | awk -F'\t' '
    {
        n = split($1, ty, ","); split($2, len, ",");
        for (i = 1; i <= n; i++) if (ty[i] == 0) { c++; total += len[i] - 16 }
    }
    END {
        printf "  DATA chunks: %d\n  payload bytes on wire: %d\n", c, total;
        printf "  expected payload:      %d\n", 1024+1400+1600+4096+16384 + 5*4;
        printf "  %s\n", (total == 1024+1400+1600+4096+16384 + 5*4) \
            ? "MATCH - the sender put every byte on the wire" \
            : "MISMATCH - investigate";
    }'
echo "  (frames of 1024+1400+1600+4096+16384, each with a 4-byte length prefix)"

echo
echo "=== Per-message DATA chunks (B/E fragment bits) ==="
echo "  B=1 begins a message, E=1 ends it. A message whose chunks are not"
echo "  all B=1,E=1 was fragmented; that is what MSG_EOR reports to the"
echo "  receiver, and what plain SCTPRead discards."
tshark -r "$CAP" -T fields \
    -e sctp.chunk_type -e sctp.chunk_length -e sctp.data_b_bit -e sctp.data_e_bit \
    2>/dev/null | awk -F'\t' '
    $1 ~ /(^|,)0(,|$)/ {
        n = split($2, len, ",");
        split($3, b, ","); split($4, e, ",");
        split($1, ty, ",");
        for (i = 1; i <= n; i++) {
            if (ty[i] != 0) continue;
            c++;
            printf "  chunk %-3d payload=%-6d B=%-3s E=%s\n", c, len[i] - 16, b[i], e[i];
        }
    }'
