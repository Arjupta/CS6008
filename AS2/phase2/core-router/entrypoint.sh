#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1
# Diversion route: traffic bound for the resolver's specific address is sent
# via the attacker instead of delivered directly, even though the attacker
# sits on the same directly-connected subnet. A /32 host route is more
# specific than the subnet's connected route, so it wins.
ip route add 172.16.2.10/32 via 172.16.2.100
tail -f /dev/null
