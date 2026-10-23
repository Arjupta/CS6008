#!/bin/bash
set -e
ip route add 172.16.2.0/24 via 172.16.1.2

# Point the client's OS resolver at our lab resolver -- this is ordinary
# baseline configuration (same as any real end host would have its
# resolver set), done once at deploy time, NOT part of the attack
# mechanism itself. The attack (interception + forgery) is purely
# router-side per 6.1 -- no ARP spoofing, no touching this file at attack
# time, the client's configuration stays exactly as deployed throughout
# 6.2's transparent-relay verify and 6.3's attack.
echo "nameserver 172.16.2.10" > /etc/resolv.conf

# dnsutils (already in Dockerfile.base) normally pulls in bind9-dnsutils
# as a dependency, but install it explicitly and defensively so `delv`
# (Client B, the locally-validating stub) is guaranteed present.
command -v delv >/dev/null 2>&1 || {
  apt-get update -qq && apt-get install -y -qq --no-install-recommends bind9-dnsutils
}

tail -f /dev/null
