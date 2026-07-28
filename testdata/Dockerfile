# Test image for running the SCTP suite against a real Linux kernel stack.
# Local testing only - not part of the published module.
FROM golang:1.23-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        libsctp1 \
        lksctp-tools \
        tshark \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
