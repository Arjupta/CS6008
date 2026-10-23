#!/bin/bash
# Phase 6: capture evidence for the transparent-relay verify, then the
# attack against both clients.
#
# Client A (ordinary stub -- curl using the OS resolver) should land on
# the rogue page. Client B (delv, validating independently against its
# own copy of the root trust anchor) should reject the forged answer,
# exactly as the Phase 3 resolver did -- the forgery never touches any
# RRSIG, so a real independent re-validation catches the rdata/signature
# mismatch every time, regardless of what the resolver or an on-path
# attacker between it and the client claims.
#
# Must be run from inside phase6/. Builds and tears down the stack
# itself, so no containers need to be up beforehand. Safe to re-run; each
# run's evidence goes into its own timestamped subdirectory under
# evidence/ (.gitignore'd, not committed).

set -e

TS=$(date +%Y%m%d-%H%M%S)
OUTDIR="evidence/$TS"
mkdir -p "$OUTDIR"
echo "== Writing evidence to $OUTDIR =="

echo
echo "########## Deploying ##########"
./sign-zones.sh
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build >/dev/null
sleep 5

echo "== [1/3] Verify: forging OFF, relay should be transparent =="
docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'
docker exec client curl -s -o /dev/null -w "http_code=%{http_code}\n" --max-time 5 \
  http://example.com > "$OUTDIR/verify_curl.txt" 2>&1
docker exec client dig +short example.com @172.16.2.10 > "$OUTDIR/verify_dig.txt" 2>&1
echo "  curl: $(cat "$OUTDIR/verify_curl.txt")"
echo "  dig:  $(cat "$OUTDIR/verify_dig.txt")"

echo
echo "== [2/3] Attack on Client A (ordinary stub -- curl via the OS resolver) =="
docker exec attacker sh -c 'echo 1 > /tmp/forge_enabled'
docker exec client curl -s -o /dev/null -w "http_code=%{http_code}\n" --max-time 5 \
  http://example.com > "$OUTDIR/clientA_curl.txt" 2>&1
docker exec client dig example.com @172.16.2.10 > "$OUTDIR/clientA_dig.txt" 2>&1
echo "  curl: $(cat "$OUTDIR/clientA_curl.txt")"
echo "  dig status/flags:"
grep -E "status:|flags:" "$OUTDIR/clientA_dig.txt"

echo
echo "== [3/3] Attack on Client B (delv, validating independently) =="
docker exec client delv -a /root/trust-anchor.conf example.com @172.16.2.10 \
  > "$OUTDIR/clientB_delv.txt" 2>&1 || true
cat "$OUTDIR/clientB_delv.txt"

docker logs attacker --tail 20 > "$OUTDIR/attacker_log.txt" 2>&1

docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'

cat > "$OUTDIR/SUMMARY.txt" <<EOF
Phase 6 evidence capture -- $(date)

Verify (forging off): curl $(cat "$OUTDIR/verify_curl.txt") | dig +short -> $(cat "$OUTDIR/verify_dig.txt")

Client A (ordinary stub, curl via OS resolver), forging on:
  curl: $(cat "$OUTDIR/clientA_curl.txt")
  dig:  $(grep -i status "$OUTDIR/clientA_dig.txt")
        $(grep -o 'flags: [a-z ]*' "$OUTDIR/clientA_dig.txt" | head -1)
  expected: curl lands on the rogue page (172.16.1.30), dig shows the
  forged A record with the 'ad' flag set by the ATTACKER (not earned --
  see interceptor.c's header comment and the README).

Client B (delv, independently validating against its own trust anchor):
  $(tail -3 "$OUTDIR/clientB_delv.txt")
  expected: validation fails -- the forged rdata doesn't match the real,
  untouched RRSIG the resolver forwarded, so Client B's own re-validation
  (not the resolver's, not the 'ad' flag) catches it.

Files: verify_curl.txt, verify_dig.txt, clientA_curl.txt, clientA_dig.txt,
clientB_delv.txt, attacker_log.txt.
EOF

echo
echo "== Done. See $OUTDIR/SUMMARY.txt =="
cat "$OUTDIR/SUMMARY.txt"
