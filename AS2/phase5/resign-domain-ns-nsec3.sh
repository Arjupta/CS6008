#!/bin/bash
# Phase 5: switch to the FIXED deployment -- re-sign ONLY domain-ns's zone,
# using NSEC3 instead of NSEC for authenticated denial, reusing the exact
# same KSK/ZSK keypair sign-zones.sh already generated for it.
#
# Nothing else in the chain needs to change: a DS record is derived from
# the child's DNSKEY RDATA, which doesn't depend on whether that zone uses
# NSEC or NSEC3 for denial. Since we keep domain-ns's keys unchanged, the
# DS tld-ns already published for example.com (back when sign-zones.sh ran)
# is still correct -- root-ns, tld-ns, and the resolver's trust anchor are
# completely unaffected by this switch.
#
# NSEC3 parameters follow RFC 9276's current best practice: an empty salt
# and zero extra hash iterations. A salt only helps against a *single*
# precomputed rainbow table being reused across zones, which stopped being
# the realistic threat model years ago (attackers now just compute hashes
# on demand, and modern hardware makes iteration count essentially free to
# brute past); both knobs mainly cost validators CPU for no real benefit
# today, which is why the BIND/IETF guidance moved to recommending neither.
#
# Run from inside phase5/, AFTER ./sign-zones.sh has already run at least
# once (it needs domain-ns/keys/ to exist). Safe to re-run any time to
# switch back and forth -- it only ever touches domain-ns's signed zone
# file, nothing under tld-ns/, root-ns/, or resolver/.

set -e

IMG=cs6008-bindtools

if [ ! -d domain-ns/keys ] || [ -z "$(ls -A domain-ns/keys 2>/dev/null)" ]; then
  echo "domain-ns/keys/ is empty -- run ./sign-zones.sh first (it generates" >&2
  echo "the keypair this script re-signs with)." >&2
  exit 1
fi

echo "== Building signing-tool image (if not already built) =="
docker build -q -t "$IMG" -f ../common/Dockerfile.bind ../common >/dev/null

run_in() {
  local dir="$1"; shift
  docker run --rm -v "$(pwd)/$dir:/work" -w /work "$IMG" bash -c "$*"
}

echo "== Re-signing example.com with NSEC3 (domain-ns), same keys, no re-chaining needed =="
run_in domain-ns "
  set -e
  cd build
  dnssec-signzone -S -N keep -K ../keys -o example.com. -3 - -H 0 \
      -f db.example.com.signed db.example.com >/dev/null
"
cp domain-ns/build/db.example.com.signed domain-ns/db.example.com.signed

echo
echo "Done (FIXED -- example.com now signed with NSEC3, salt='', iterations=0)."
echo "  domain-ns/db.example.com.signed  (only this file changed)"
echo
echo "Now run: docker compose restart domain-ns resolver"
echo "(root-ns, tld-ns, and the trust anchor are untouched -- the chain above"
echo " domain-ns did not need to change at all.)"
