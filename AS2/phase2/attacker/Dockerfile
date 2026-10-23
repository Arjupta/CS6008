FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    iproute2 \
    iputils-ping \
    net-tools \
    dnsutils \
    curl \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/attacker
COPY interceptor.c .
RUN gcc -O2 -Wall -o interceptor interceptor.c -lpcap
