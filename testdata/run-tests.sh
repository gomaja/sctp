#!/usr/bin/env bash
# Runs the Go test suite inside the container against a real SCTP stack.
set -euo pipefail

modprobe sctp 2>/dev/null || true

if [ ! -e /proc/net/sctp/snmp ]; then
    echo "SCTP not available in this kernel; cannot run the suite." >&2
    exit 1
fi
echo "SCTP stack present."

go build ./...
go vet ./... 2>&1 | grep -v 'non-test goroutine' || true

exec go test "$@"
