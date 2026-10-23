#!/bin/bash
# Phase 3: capture evidence for the report (baseline validation + attack
# rejection), same approach as Phase 2's capture -- tcpdump on core-router
# for the resolver<->authoritative exchange, plus dig/delv output and the
# attacker's own log, all written to timestamped files under evidence/.
#
# Must be run from inside phase3/, with all containers already up and the
# chain already signed (see README's "Deploy" section). Safe to re-run --
# each run gets its own timestamped subdirectory, nothing is overwritten.

set -e

OUTDIR="evidence/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
echo "== Writing evidence to $OUTDIR =="

# ---- 0. Make sure forging starts OFF and the resolver cache is clean ------
docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'
docker compose restart resolver >/dev/null
sleep 3

# ---- 1. Baseline: start the capture, then prove the chain validates -------
echo "== [1/3] Baseline capture (tcpdump on core-router) =="
docker exec -d core-router sh -c \
  "tcpdump -i any -w /tmp/baseline.pcap udp port 53 &
   sleep 8"
sleep 1

docker exec client dig +dnssec example.com @172.16.2.10 \
  > "$OUTDIR/baseline_dig.txt" 2>&1
docker exec resolver delv -a /etc/bind/trust-anchor.conf example.com @172.16.2.10 \
  > "$OUTDIR/baseline_delv.txt" 2>&1

sleep 7   # let the background tcpdump finish its window
docker cp core-router:/tmp/baseline.pcap "$OUTDIR/baseline.pcap" 2>/dev/null || \
  echo "  (no baseline.pcap -- check core-router has tcpdump installed)"

echo "  dig flags:  $(grep -o 'flags: [a-z ]*' "$OUTDIR/baseline_dig.txt" | head -1)"
echo "  delv tail:  $(tail -1 "$OUTDIR/baseline_delv.txt")"

# ---- 2. Attack: forge on, flush cache, capture + trigger -------------------
echo "== [2/3] Attack capture (forging ON) =="
docker exec attacker sh -c 'echo 1 > /tmp/forge_enabled'
docker compose restart resolver >/dev/null
sleep 3

docker exec -d core-router sh -c \
  "tcpdump -i any -w /tmp/attack.pcap udp port 53 &
   sleep 8"
sleep 1

docker exec client dig example.com @172.16.2.10 > "$OUTDIR/attack_dig.txt" 2>&1

# IMPORTANT: do NOT use `curl --resolve` here -- it skips DNS lookup
# entirely and connects straight to whatever IP you hand it, which
# proves nothing about DNS behavior (it will "succeed" even when the
# resolver is correctly returning SERVFAIL). To actually exercise DNS
# through our lab resolver, point the client's real resolver at
# 172.16.2.10 and let curl do its own, unforced lookup.
docker exec client sh -c 'echo "nameserver 172.16.2.10" > /etc/resolv.conf'
docker exec client curl -s -o /dev/null -w "http_code=%{http_code}\n" --max-time 5 \
  http://example.com \
  > "$OUTDIR/attack_curl.txt" 2>&1 || echo "http_code=(curl failed/timed out -- expected: DNS resolution failed)" \
  >> "$OUTDIR/attack_curl.txt"

sleep 7
docker cp core-router:/tmp/attack.pcap "$OUTDIR/attack.pcap" 2>/dev/null || \
  echo "  (no attack.pcap -- check core-router has tcpdump installed)"

docker logs attacker --tail 30 > "$OUTDIR/attacker_log.txt" 2>&1

echo "  dig status: $(grep -i status "$OUTDIR/attack_dig.txt")"
echo "  curl result: $(cat "$OUTDIR/attack_curl.txt")"

# ---- 3. Clean up: forging back off, cache flushed --------------------------
echo "== [3/3] Resetting to clean baseline state =="
docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'
docker compose restart resolver >/dev/null
sleep 3

cat > "$OUTDIR/SUMMARY.txt" <<EOF
Phase 3 evidence capture — $(date)

Baseline (DNSSEC validation, forging off):
  dig:  $(grep -i status "$OUTDIR/baseline_dig.txt")
        $(grep -o 'flags: [a-z ]*' "$OUTDIR/baseline_dig.txt" | head -1)
  delv: $(tail -1 "$OUTDIR/baseline_delv.txt")

Attack (same Phase 2 forged-rdata interceptor, forging on, resolver validates):
  dig:  $(grep -i status "$OUTDIR/attack_dig.txt")
  curl: $(cat "$OUTDIR/attack_curl.txt")
  attacker log (last lines, shows forging still attempted):
$(tail -5 "$OUTDIR/attacker_log.txt" | sed 's/^/    /')

Files in this directory:
  baseline_dig.txt, baseline_delv.txt, baseline.pcap  -- chain validates cleanly
  attack_dig.txt, attack_curl.txt, attacker_log.txt, attack.pcap -- forged
    answer rejected (SERVFAIL), attacker log shows the forge was attempted
EOF

echo
echo "== Done. See $OUTDIR/SUMMARY.txt =="
cat "$OUTDIR/SUMMARY.txt"
