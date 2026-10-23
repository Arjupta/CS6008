#!/bin/bash
# Phase 2 evidence capture: runs the verify + attack sequence and collects
# logs/captures into evidence/<timestamp>/ for the report.
#
# Run from inside the phase2/ directory, after `docker compose up -d`.

set -e

TS=$(date +%Y%m%d_%H%M%S)
OUT="evidence/${TS}"
mkdir -p "$OUT"
echo "Writing evidence to $OUT"

PARSE_PCAP="./parse_pcap.py"
if [ ! -f "$PARSE_PCAP" ]; then
  echo "WARNING: parse_pcap.py not found in current directory — pcap annotation will be skipped."
  echo "         Place it at phase2/parse_pcap.py (it was sent alongside this script)."
  PARSE_PCAP=""
fi

run() { echo "+ $*" | tee -a "$OUT/commands.log"; "$@"; }

echo "== 1. Ensure forging is OFF and cache is clean =="
# Restart (not `rndc flush`) to clear resolver's cache: named.conf here has no
# controls/key block, so plain rndc can't authenticate to the auto-generated
# session key. A restart clears the in-memory cache just as reliably.
docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled' || true
docker compose restart resolver
sleep 3

echo "== 2. Start capture on core-router (background) =="
docker exec -d core-router sh -c "tcpdump -i any -w /root/core-router.pcap udp port 53"
sleep 1

echo "== 3. Verify: forging disabled, transparent relay =="
docker exec client dig +short example.com @172.16.2.10 | tee "$OUT/01_verify_relay_dig.txt"
docker exec client curl -s http://example.com --resolve example.com:80:172.16.1.20 \
  | tee "$OUT/01_verify_relay_curl.txt" > /dev/null
echo "  -> saved $OUT/01_verify_relay_dig.txt (expect 172.16.1.20) and _curl.txt (real page)"

echo "== 4. Enable forging and clear cache =="
docker exec attacker sh -c 'echo 1 > /tmp/forge_enabled'
docker compose restart resolver
sleep 3

echo "== 5. Attack: poisoned lookup and defaced fetch =="
docker exec client dig +short example.com @172.16.2.10 | tee "$OUT/02_attack_dig.txt"
docker exec client curl -s http://example.com --resolve example.com:80:172.16.1.30 \
  | tee "$OUT/02_attack_curl.txt" > /dev/null
echo "  -> saved $OUT/02_attack_dig.txt (expect 172.16.1.30) and _curl.txt (defaced page)"

echo "== 6. Non-target name is unaffected =="
docker exec client dig +short www.example.com @172.16.2.10 | tee "$OUT/03_nontarget_dig.txt"
echo "  -> saved $OUT/03_nontarget_dig.txt (expect 172.16.1.20, unchanged)"

echo "== 7. Stop capture, pull logs and pcaps =="
sleep 1
docker exec core-router pkill tcpdump || true
sleep 1
docker cp core-router:/root/core-router.pcap "$OUT/core-router.pcap"
docker cp attacker:/tmp/injected.pcap "$OUT/injected.pcap"
docker logs attacker > "$OUT/attacker.log" 2>&1

echo "== 8. Turn forging back off =="
docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'

if [ -n "$PARSE_PCAP" ]; then
  echo "== 9. Annotate pcaps =="
  python3 "$PARSE_PCAP" "$OUT/core-router.pcap"  > "$OUT/core-router_annotated.txt" || true
  python3 "$PARSE_PCAP" "$OUT/injected.pcap"     > "$OUT/injected_annotated.txt"    || true
fi

echo
echo "Done. Evidence in: $OUT"
ls -la "$OUT"

