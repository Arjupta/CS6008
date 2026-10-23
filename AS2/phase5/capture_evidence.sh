#!/bin/bash
# Phase 5: capture evidence for both the walkable (NSEC) and fixed (NSEC3)
# deployments.
#
# Walkable: domain-ns signs example.com with NSEC (the default). The
#           zonewalk tool, starting from knowledge of "example.com." alone,
#           recovers the complete set of owner names -- including the 5
#           internal names that are linked from nowhere -- using only
#           ordinary DNS queries.
# Fixed:    the exact same zone content, re-signed with NSEC3 instead
#           (same keys, nothing upstream changes). The exact same
#           zonewalk procedure now recovers nothing, while an ordinary
#           query for a genuinely nonexistent name still gets a valid,
#           authenticated denial.
#
# Must be run from inside phase5/. Builds and tears down the stack itself,
# so no containers need to be up beforehand. Safe to re-run; each run's
# evidence goes into its own timestamped subdirectory under evidence/
# (.gitignore'd, not committed).

set -e

TS=$(date +%Y%m%d-%H%M%S)
OUTDIR="evidence/$TS"
mkdir -p "$OUTDIR/walkable" "$OUTDIR/fixed"
echo "== Writing evidence to $OUTDIR =="

# ============================================================ deploy ======
echo
echo "########## Deploying: walkable (NSEC) ##########"
./sign-zones.sh
docker compose down -v >/dev/null 2>&1 || true
docker compose up -d --build >/dev/null
sleep 5

echo "-- Verify: query a name that genuinely does not exist --"
docker exec attacker dig +dnssec nosuchname.example.com @172.16.3.30 \
  > "$OUTDIR/walkable/verify_nxdomain.txt" 2>&1
grep -E "status:|NSEC" "$OUTDIR/walkable/verify_nxdomain.txt" || true

echo
echo "-- Attack: walk the zone from domain-ns directly --"
docker exec attacker ./zonewalk eth0 172.16.3.30 example.com. \
  > "$OUTDIR/walkable/walk.txt" 2>&1
cat "$OUTDIR/walkable/walk.txt"

# ============================================================ switch ======
echo
echo "########## Switching to: fixed (NSEC3) ##########"
./resign-domain-ns-nsec3.sh
docker compose restart domain-ns resolver >/dev/null
sleep 3

echo "-- Verify: the SAME nonexistent-name query still gets an authenticated denial --"
docker exec attacker dig +dnssec nosuchname.example.com @172.16.3.30 \
  > "$OUTDIR/fixed/verify_nxdomain.txt" 2>&1
grep -E "status:|NSEC3" "$OUTDIR/fixed/verify_nxdomain.txt" || true

echo
echo "-- Attack (same procedure, same binary): walk should now fail --"
docker exec attacker ./zonewalk eth0 172.16.3.30 example.com. \
  > "$OUTDIR/fixed/walk.txt" 2>&1
cat "$OUTDIR/fixed/walk.txt"

# ============================================================ summary =====
WALK_COUNT=$(grep -c "\-> next:" "$OUTDIR/walkable/walk.txt" || true)
FIXED_COUNT=$(grep -c "\-> next:" "$OUTDIR/fixed/walk.txt" || true)

cat > "$OUTDIR/SUMMARY.txt" <<EOF
Phase 5 evidence capture -- $(date)

WALKABLE (example.com signed with NSEC):
  verify (nonexistent name): $(grep -i status "$OUTDIR/walkable/verify_nxdomain.txt")
  walk: $WALK_COUNT names recovered via the NSEC chain (see walkable/walk.txt
  for the full step-by-step list -- expect the apex, www, the domain-ns
  glue name, and all 5 internal names: vpn, db1, mail, dev, staging).

FIXED (example.com signed with NSEC3, same keys, nothing upstream changed):
  verify (nonexistent name): $(grep -i status "$OUTDIR/fixed/verify_nxdomain.txt")
  (still NXDOMAIN with a valid NSEC3-based authenticated denial -- the fix
  does not break ordinary negative responses, only enumeration.)
  walk: $FIXED_COUNT names recovered -- expect 0 (or 1 if the very first
  NSEC query at the apex returns NODATA immediately, see fixed/walk.txt).

Files: walkable/ and fixed/, each with verify_nxdomain.txt and walk.txt.
EOF

echo
echo "== Done. See $OUTDIR/SUMMARY.txt =="
cat "$OUTDIR/SUMMARY.txt"
