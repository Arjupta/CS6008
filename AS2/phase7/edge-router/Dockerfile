# Phase 7 -- edge-router's own image: same as ../../common/Dockerfile.base,
# PLUS iptables baked in at BUILD time (see client-image/Dockerfile for
# why this has to happen at build time, not in entrypoint.sh, in this
# particular phase).
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    dnsutils \
    knot-dnsutils \
    curl \
    tcpdump \
    python3 \
    net-tools \
    ca-certificates \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
