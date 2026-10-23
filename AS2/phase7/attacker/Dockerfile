FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    pkg-config \
    python3 \
    python3-pip \
    python3-dev \
    iproute2 \
    iptables \
    iputils-ping \
    net-tools \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages --no-cache-dir NetfilterQueue scapy

WORKDIR /opt/attacker
COPY interceptor.c .
RUN gcc -O2 -Wall -o interceptor interceptor.c -lpcap
COPY corrupt.py rogue_tls_server.py ./
COPY rogue-cert ./rogue-cert
