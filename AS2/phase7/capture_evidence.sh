#!/bin/bash
# Phase 7: capture evidence for 7.2 (verify) and all three of 7.3's
# attempts against both clients, plus one bonus chained run used only
# for 7.4's "what does this still not protect" discussion.
#
# Must be run from inside phase7/. Builds and tears down the stack
# itself (via make-pki.sh + sign-zones.sh + docker compose), so no
# containers need to be up beforehand. Safe to re-run; each run's
# evidence goes into its own timestamped subdirectory under evidence/
# (.gitignore'd, not committed). Leaves every attack toggle off when it
# finishes.

set -e

TS=$(date +%Y%m%d-%H%M%S)
OUTDIR="evidence/$TS"
mkdir -p "$OUTDIR"
echo "== Writing evidence to $OUTDIR =="

run_q() {
  # run_q <client> <label>  -- queries example.com via the client's own
  # /etc/resolv.conf (stubby for client-strict, permissive-resolver.py
  # for client-permissive) and via curl, bounded so a denial doesn't
  # hang the script.
  local client="$1" label="$2"
  docker exec "$client" dig +time=4 +tries=1 example.com \
    > "$OUTDIR/${label}_dig.txt" 2>&1 || true
  docker exec "$client" curl -s -o /dev/null -w "http_code=%{http_code}\n" --max-time 8 \
    http://example.com > "$OUTDIR/${label}_curl.txt" 2>&1 || true
  echo "  [$client] curl: $(cat "$OUTDIR/${label}_curl.txt")"
  echo "  [$client] dig status/answer:"
  grep -E "status:|^example" "$OUTDIR/${label}_dig.txt" || true
}

echo
echo "########## Deploying ##########"
./make-pki.sh
./sign-zones.sh
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build >/dev/null
sleep 6
docker exec edge-router bash /root/set-attack.sh none >/dev/null

echo
echo "== [1/5] Verify: no attack toggled, encrypted transport should be clean =="
echo "-- capturing 5s of edge-router traffic on udp/853/443 while client-strict queries --"
docker exec edge-router timeout 5 tcpdump -i any -n 'udp port 53' -w /tmp/verify.pcap >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
run_q client-strict verify_strict
wait $TCPDUMP_PID 2>/dev/null || true
docker cp edge-router:/tmp/verify.pcap "$OUTDIR/verify_edge-router.pcap" 2>/dev/null || true
PKT_COUNT=$(docker exec edge-router sh -c "tcpdump -r /tmp/verify.pcap 2>/dev/null | wc -l" || echo "?")
echo "  cleartext (udp/53) packets seen on edge-router during the DoT lookup: $PKT_COUNT  (expect 0)"
echo "udp/53 packet count during verify: $PKT_COUNT (expect 0 -- transport is DoT, no cleartext DNS)" \
  > "$OUTDIR/verify_cleartext_packet_count.txt"
run_q client-permissive verify_permissive

echo
echo "== [2/5] Attack (i): alter the (encrypted) answer in transit =="
docker exec attacker sh -c 'echo 1 > /tmp/forge_enabled'
run_q client-strict attack_i_strict
run_q client-permissive attack_i_permissive
docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'
docker logs attacker --tail 30 2>&1 | grep -i corrupt > "$OUTDIR/attack_i_attacker_log.txt" || true

echo
echo "== [3/5] Attack (ii): impersonate the resolver with a rogue certificate =="
docker exec edge-router bash /root/set-attack.sh roguecert
run_q client-strict attack_ii_strict
run_q client-permissive attack_ii_permissive
docker exec edge-router bash /root/set-attack.sh none
docker logs attacker --tail 30 2>&1 | grep -i rogue > "$OUTDIR/attack_ii_attacker_log.txt" || true

echo
echo "== [4/5] Attack (iii): deny the encrypted transport (block TCP 853) =="
docker exec edge-router bash /root/set-attack.sh deny
run_q client-strict attack_iii_strict
run_q client-permissive attack_iii_permissive
docker exec edge-router bash /root/set-attack.sh none

echo
echo "== [5/5] Bonus (not one of the six required combos): attack (iii) CHAINED with =="
echo "         the Phase 6 cleartext forger, against the permissive client only --"
echo "         demonstrates 7.4's point that an encrypted last mile doesn't protect"
echo "         a client that is willing to fall back to the leg Phase 6 broke."
docker exec edge-router bash /root/set-attack.sh deny
docker exec attacker sh -c 'echo 1 > /tmp/forge_cleartext_enabled'
run_q client-permissive bonus_chained_permissive
docker exec attacker sh -c 'echo 0 > /tmp/forge_cleartext_enabled'
docker exec edge-router bash /root/set-attack.sh none

docker logs client-permissive --tail 0 >/dev/null 2>&1 || true
docker cp client-permissive:/var/log/permissive-resolver.log \
  "$OUTDIR/permissive_resolver_fallback_log.txt" 2>/dev/null || true

verdict() {
  # verdict <dig file> <curl file> -- prints landed/real-IP/blocked based
  # on the captured A record and http_code, for the SUMMARY.
  local digf="$1" curlf="$2"
  local ip code
  ip=$(grep -oE '172\.16\.1\.(10|20|30)' "$OUTDIR/$digf" | tail -1)
  code=$(grep -oE 'http_code=[0-9]+' "$OUTDIR/$curlf" | tail -1)
  echo "A=${ip:-none} ${code:-http_code=timeout}"
}

cat > "$OUTDIR/SUMMARY.txt" <<EOF
Phase 7 evidence capture -- $(date)

[1] Verify (no attack): cleartext udp/53 packets seen = $PKT_COUNT (expect 0)
  client-strict:     $(verdict verify_strict_dig.txt verify_strict_curl.txt)      (expect A=172.16.1.20, 200 -- real page, over DoT)
  client-permissive: $(verdict verify_permissive_dig.txt verify_permissive_curl.txt)  (expect A=172.16.1.20, 200 -- real page, over DoT, no fallback needed)

[2] Attack (i) -- alter answer in transit (TLS payload byte-flip):
  client-strict:     $(verdict attack_i_strict_dig.txt attack_i_strict_curl.txt)
  client-permissive: $(verdict attack_i_permissive_dig.txt attack_i_permissive_curl.txt)
  expected: NEITHER lands as a forgery. TLS's AEAD integrity check
  detects the corrupted ciphertext and the connection is torn down --
  strict gets no answer (DoS only); permissive's stubby attempt also
  fails the same way, so permissive-resolver.py falls back to cleartext
  and gets the REAL answer (172.16.1.20), not a forged one, because
  nothing is forging the cleartext leg in this attempt.

[3] Attack (ii) -- impersonate the resolver with a rogue certificate:
  client-strict:     $(verdict attack_ii_strict_dig.txt attack_ii_strict_curl.txt)
  client-permissive: $(verdict attack_ii_permissive_dig.txt attack_ii_permissive_curl.txt)
  expected: NEITHER lands. Both clients' TLS stacks reject the rogue
  cert (self-signed, untrusted CA) during the handshake -- see
  attack_ii_attacker_log.txt for the rejected-handshake log. Strict gets
  no answer; permissive falls back to cleartext and gets the REAL
  answer, same reasoning as attack (i).

[4] Attack (iii) -- deny the encrypted transport (block TCP 853):
  client-strict:     $(verdict attack_iii_strict_dig.txt attack_iii_strict_curl.txt)
  client-permissive: $(verdict attack_iii_permissive_dig.txt attack_iii_permissive_curl.txt)
  expected: strict gets NO answer at all (DoS -- it has nowhere else to
  go). permissive falls back to cleartext and gets the REAL answer,
  because -- in this attempt alone -- nothing is forging that cleartext
  leg either.

[BONUS, not one of the six required combos] Attack (iii) chained with
the Phase 6 cleartext forger, permissive client only:
  client-permissive: $(verdict bonus_chained_permissive_dig.txt bonus_chained_permissive_curl.txt)
  expected: THIS one DOES land -- A=172.16.1.30 (rogue-web), 200. Denying
  the encrypted transport forces the fallback permissive-resolver.py was
  configured to use, and an attacker already positioned on that
  cleartext leg (same technique as Phase 6, nothing new) can now forge
  it. See permissive_resolver_fallback_log.txt for the "FALLING BACK TO
  CLEARTEXT" line proving which path actually answered.

Files: verify_*, attack_i_*, attack_ii_*, attack_iii_*, bonus_chained_*
(each with _dig.txt/_curl.txt per client), verify_edge-router.pcap,
attack_ii_attacker_log.txt, attack_i_attacker_log.txt,
permissive_resolver_fallback_log.txt.
EOF

echo
echo "== Done. See $OUTDIR/SUMMARY.txt =="
cat "$OUTDIR/SUMMARY.txt"
