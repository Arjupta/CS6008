#!/bin/bash
set -e
ip route add 172.16.2.0/24 via 172.16.1.2

# ca-certificates and stubby are both baked into this image at build
# time (see client-image/Dockerfile) -- NOT installed here at runtime,
# because client_net is an `internal: true` compose network with no
# outbound access once the container is actually running.
cp /root/ca.crt /usr/local/share/ca-certificates/cs6008-lab-ca.crt
update-ca-certificates >/dev/null

mkdir -p /etc/stubby
cp /root/ca.crt /etc/stubby/ca.crt
cp /root/stubby.yml /etc/stubby/stubby.yml

# PERMISSIVE client: stubby (DoT-only, same strict TLS auth as the
# strict client) listens on 127.0.0.1:5353, NOT 53.
# /root/permissive-resolver.py is what actually listens on
# 127.0.0.1:53 -- what /etc/resolv.conf points at -- and it is the one
# that decides, per query, whether to fall back to the resolver's plain
# port 53. That is this client's explicit permission to use the
# unauthenticated Phase 6 leg, which is exactly what 7.3's three
# attempts are testing against.
echo "nameserver 127.0.0.1" > /etc/resolv.conf

pkill stubby 2>/dev/null || true
stubby -C /etc/stubby/stubby.yml -l &
sleep 1

rm -f /var/log/permissive-resolver.log
python3 /root/permissive-resolver.py >> /var/log/permissive-resolver.log 2>&1 &
sleep 1

tail -f /dev/null
