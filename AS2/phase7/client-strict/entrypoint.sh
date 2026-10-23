#!/bin/bash
set -e
ip route add 172.16.2.0/24 via 172.16.1.2

# Install the private CA into the real OS trust store -- no -k /
# insecure bypass anywhere in this phase. stubby's tls_ca_file points at
# the same file, so both the "normal TLS stack" path and stubby's own
# check go through this one trusted root. ca-certificates and stubby
# are both baked into this image at build time (see
# client-image/Dockerfile) -- NOT installed here at runtime, because
# client_net is an `internal: true` compose network with no outbound
# access once the container is actually running.
cp /root/ca.crt /usr/local/share/ca-certificates/cs6008-lab-ca.crt
update-ca-certificates >/dev/null

mkdir -p /etc/stubby
cp /root/ca.crt /etc/stubby/ca.crt
cp /root/stubby.yml /etc/stubby/stubby.yml

# STRICT client: stubby (DoT-only per stubby.yml) is the ENTIRE
# resolution path. /etc/resolv.conf points straight at it; nothing else
# in this container can answer a DNS query, so there is nowhere for a
# cleartext fallback to come from.
echo "nameserver 127.0.0.1" > /etc/resolv.conf

pkill stubby 2>/dev/null || true
stubby -C /etc/stubby/stubby.yml -l &
sleep 1

rm -f /var/log/strict-resolver.log
python3 /root/strict-resolver.py >> /var/log/strict-resolver.log 2>&1 &
sleep 1

tail -f /dev/null
