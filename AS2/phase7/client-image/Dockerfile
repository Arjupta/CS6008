# Phase 7 -- shared image for client-strict and client-permissive.
#
# Same packages as ../../common/Dockerfile.base, PLUS stubby baked in at
# BUILD time. This matters specifically in this phase: client_net,
# resolver_net and authoritative_net are all declared `internal: true`
# in compose.yml, so a container has NO internet access once it's
# running -- only `docker build` itself (which runs on the host's own
# network) can reach the package archive. Phase 6's entrypoints got away
# with a runtime "apt-get install if missing" fallback only because the
# package in question (bind9-dnsutils/delv) was already pulled in
# transitively by dnsutils, so that fallback path never actually had to
# run. stubby isn't pulled in by anything else here, so it has to be
# baked in here instead.
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
    stubby \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
