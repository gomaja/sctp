# Test image for running the SCTP suite against a real Linux kernel stack.
# Local testing only - not part of the published module.
FROM golang:1.23-bookworm

# tshark's postinst asks whether non-root users may capture, which stalls a
# non-interactive build; DEBIAN_FRONTEND answers it. iptables is needed to
# blackhole TEST-NET-1 for the EALREADY tests — see run-tests.sh.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libsctp1 \
        lksctp-tools \
        tshark \
        iproute2 \
        iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
