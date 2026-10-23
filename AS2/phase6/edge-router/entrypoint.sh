#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1
# Diversion route: traffic bound for the CLIENT's specific address is sent
# via the attacker instead of delivered directly, even though the
# attacker sits on the same directly-connected (client) subnet. A /32
# host route is more specific than the subnet's connected route, so it
# wins -- same mechanism as Phase 2's core-router diversion, just facing
# the other direction (resolver -> client replies, not
# authoritative -> resolver replies).
ip route add 172.16.1.10/32 via 172.16.1.100
tail -f /dev/null
