#!/bin/bash
# Phase 4: capture evidence for both runs.
#
# Run A: full chain of trust intact (DS published at every level), attacker
#        strips RRSIG/DNSKEY/DS off the wire for example.com and forges the
#        A record anyway -- expected to still fail (SERVFAIL), because
#        deleting bytes in flight isn't the same as a real signed proof of
#        "this name is unsigned".
# Run B: example.com stays fully signed, but com never publishes its DS --
#        the same strip-and-forge attacker config now succeeds, because the
#        resolver itself decided (correctly, per protocol) that example.com
#        is insecure before it ever asked domain-ns for anything.
#
# Must be run from inside phase4/. Builds and tears down the stack itself
# for each run, so no containers need to be up beforehand. Safe to re-run;
# each run's evidence goes into its own timestamped subdirectory under
# evidence/ (.gitignore'd, not committed).

set -e

TS=$(date +%Y%m%d-%H%M%S)
OUTDIR="evidence/$TS"
mkdir -p "$OUTDIR/runA" "$OUTDIR/runB"
echo "== Writing evidence to $OUTDIR =="

wait_for_stack() {
  sleep 5
}

reset_client_resolver() {
  # Same fix as Phase 3's capture_evidence.sh: the client's default
  # /etc/resolv.conf is Docker's own embedded DNS, not our lab resolver, so
  # curl without an explicit override wouldn't exercise our resolver at
  # all. Point it at 172.16.2.10 before any curl-based check.
  docker exec client sh -c 'echo "nameserver 172.16.2.10" > /etc/resolv.conf'
}

run_attack_capture() {
  local label="$1" outsub="$2"
  echo "== [$label] cache flush, forging+stripping ON, capture =="
  docker exec attacker sh -c 'echo 1 > /tmp/forge_enabled'
  docker exec attacker sh -c 'echo 1 > /tmp/strip_enabled'
  docker compose restart resolver >/dev/null
  sleep 3
  reset_client_resolver

  docker exec -d core-router sh -c \
    "tcpdump -i any -w /tmp/${label}.pcap udp port 53 &
     sleep 8"
  sleep 1

  docker exec client dig example.com @172.16.2.10 > "$outsub/dig.txt" 2>&1
  docker exec client curl -s -o /dev/null -w "http_code=%{http_code}\n" --max-time 5 \
    http://example.com > "$outsub/curl.txt" 2>&1 || \
    echo "http_code=(curl failed/timed out)" >> "$outsub/curl.txt"

  sleep 7
  docker cp "core-router:/tmp/${label}.pcap" "$outsub/${label}.pcap" 2>/dev/null || \
    echo "  (no ${label}.pcap -- check core-router has tcpdump installed)"

  docker logs attacker --tail 30 > "$outsub/attacker_log.txt" 2>&1

  echo "  dig status: $(grep -i status "$outsub/dig.txt")"
  echo "  curl:       $(cat "$outsub/curl.txt")"

  docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'
  docker exec attacker sh -c 'echo 0 > /tmp/strip_enabled'
}

# ============================================================ Run A =======
echo
echo "########## RUN A -- full chain, DS published everywhere ##########"
./sign-zones.sh
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build >/dev/null
wait_for_stack

echo "-- Run A verify (before attacking): should authenticate --"
docker exec client dig +dnssec example.com @172.16.2.10 > "$OUTDIR/runA/verify_dig.txt" 2>&1
grep -E "flags:|status:" "$OUTDIR/runA/verify_dig.txt"

run_attack_capture "runA_attack" "$OUTDIR/runA"

# ============================================================ Run B =======
echo
echo "########## RUN B -- example.com signed, but com publishes no DS ##########"
./sign-zones-runB.sh
docker compose restart root-ns tld-ns domain-ns resolver >/dev/null
sleep 3

echo "-- Run B verify (before attacking): resolver treats example.com as insecure --"
docker exec client dig +dnssec example.com @172.16.2.10 > "$OUTDIR/runB/verify_dig.txt" 2>&1
grep -E "flags:|status:" "$OUTDIR/runB/verify_dig.txt"

run_attack_capture "runB_attack" "$OUTDIR/runB"

# ============================================================ summary =====
cat > "$OUTDIR/SUMMARY.txt" <<EOF
Phase 4 evidence capture -- $(date)

RUN A (full chain, DS published at every level; strip+forge attack):
  pre-attack dig: $(grep -i status "$OUTDIR/runA/verify_dig.txt")
                  $(grep -o 'flags: [a-z ]*' "$OUTDIR/runA/verify_dig.txt" | head -1)
  attack dig:     $(grep -i status "$OUTDIR/runA/dig.txt")
  attack curl:    $(cat "$OUTDIR/runA/curl.txt")
  expected: dig SERVFAIL, curl fails -- stripping bytes off a real signed
  zone is not the same as a genuine unsigned/insecure proof; resolver
  notices data is missing where it expected signed data and rejects it.

RUN B (example.com signed, com publishes NO DS for it; same strip+forge attack):
  pre-attack dig: $(grep -i status "$OUTDIR/runB/verify_dig.txt")
                  $(grep -o 'flags: [a-z ]*' "$OUTDIR/runB/verify_dig.txt" | head -1)
  attack dig:     $(grep -i status "$OUTDIR/runB/dig.txt")
  attack curl:    $(cat "$OUTDIR/runB/curl.txt")
  expected: dig returns 172.16.1.30 (the forged address), no 'ad' flag even
  pre-attack -- the resolver already treats example.com as insecure before
  the attacker does anything, because com never published its DS. Once a
  zone is insecure, the resolver doesn't demand or check signatures on it
  at all, so the Phase-2-style forged A record is simply accepted.

Files: runA/ and runB/, each with verify_dig.txt, dig.txt, curl.txt,
<run>_attack.pcap, attacker_log.txt.
EOF

echo
echo "== Done. See $OUTDIR/SUMMARY.txt =="
cat "$OUTDIR/SUMMARY.txt"
