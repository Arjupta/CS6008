#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1
# iptables is baked into this image at build time (see
# edge-router/Dockerfile) -- NOT installed here at runtime, because
# this compose network is `internal: true` and has no outbound access
# once the container is actually running.

# Same reply-side diversion as Phase 6: anything destined to the client
# is sent via the attacker instead of straight across (even though the
# attacker sits on the same directly-connected client subnet -- a /32
# host route is more specific than the subnet's connected route, same
# mechanism as every earlier phase). This is always on, independent of
# which (if any) of 7.3's attempts is currently toggled: it's what feeds
# attack (i)'s NFQUEUE hook and the bonus chained demo on the attacker
# container.
ip route add 172.16.1.10/32 via 172.16.1.100
ip route add 172.16.1.11/32 via 172.16.1.100

# Invoked via `bash`, not executed directly -- this file is bind-mounted
# read-only (:ro in compose.yml), so chmod'ing it from inside the
# container would fail outright regardless of the host-side file's own
# permission bits.
bash /root/set-attack.sh none

tail -f /dev/null