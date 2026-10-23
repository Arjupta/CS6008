# Phase 3 — DNSSEC Chain of Trust

## Prerequisites (Windows + WSL2)
Run everything from inside your WSL2 Linux distro's terminal (not PowerShell/cmd), same as Phases 1-2.

## What's new vs Phase 2

- `root-ns` signs `.`, `tld-ns` signs `com`, `domain-ns` signs `example.com`,
  chained via DS records (child's DS published in the parent zone).
- `resolver` validates (`dnssec-validation yes;`) against a trust anchor
  generated from the root zone's own freshly-generated KSK.
- `attacker`'s binary is **unchanged** from Phase 2 — same `interceptor.c`,
  same build. It still rewrites `example.com`'s A-record rdata in place; it
  does not (and architecturally cannot, without the zone's private key)
  re-sign the RRSIG to match. That mismatch is exactly what Phase 3 is
  testing: whether the validating resolver catches it.

Keys and signed zones are **generated at deploy time**, not committed to
git — see `.gitignore`. `db.root`, `db.com`, `db.example.com` (the plain,
unsigned source zone files) are the only zone data checked in; everything
with `.signed` in its name, every `keys/` directory, and
`resolver/trust-anchor.conf` are produced fresh by `sign-zones.sh` every run.

## Deploy

    cd phase3
    ./sign-zones.sh
    docker compose build
    docker compose up -d
    docker compose ps          # all containers should be "Up"

`sign-zones.sh` must run **before** `docker compose up` — it's what
produces the `*.signed` zone files and `resolver/trust-anchor.conf` that
`compose.yml` bind-mounts into the containers; without it the DNS
containers will fail to start (no zone file to load). It signs in
dependency order (`domain-ns` → `tld-ns` → `root-ns`) since each parent
needs its child's DS before it can be signed itself, then derives the
resolver's trust anchor from the root zone's own DS. It's safe to re-run
any time — it wipes and regenerates everything from the plain source zone
files.

**Every re-run needs all four DNS containers restarted together**, not
just `resolver`: BIND only reads a zone file at container startup, it
doesn't notice the file changed on disk. Since `sign-zones.sh` generates
brand-new keys on every run, restarting only `resolver` leaves it holding
a trust anchor for a *different* signing generation than whatever
`root-ns`/`tld-ns`/`domain-ns` are still actually serving from their last
startup — which validates as broken ("no valid signature found (DS)"),
even though neither side is individually wrong. So after any re-run:

    ./sign-zones.sh
    docker compose restart root-ns tld-ns domain-ns resolver
    sleep 3

## Verify (before attacking — prove the chain actually validates)

    docker exec client dig +dnssec +short example.com @172.16.2.10
    # expect: the A record, PLUS an RRSIG line -- and with `+dnssec` (not
    # `+short`) you'd also see the `ad` (authenticated-data) flag in the
    # header, confirming the resolver validated the full chain itself:
    docker exec client dig +dnssec example.com @172.16.2.10 | grep -E "flags:|RRSIG"

    # Full chain validation with delv, pointed at the same trust anchor
    # the resolver itself uses:
    docker exec resolver delv -a /etc/bind/trust-anchor.conf example.com @172.16.2.10
    # expect: "; fully validated" at the end, not "; unsigned answer" or an error

## Attack (re-run Phase 2's attack, unchanged)

    # 1. Turn forging on (same toggle file, same attacker binary as Phase 2)
    docker exec attacker sh -c 'echo 1 > /tmp/forge_enabled'

    # 2. Clear the resolver's cache (restart, not rndc -- see Phase 2's README
    #    for why rndc doesn't work against this named.conf)
    docker compose restart resolver
    sleep 3

    # 3. Trigger the exact same lookup and fetch as Phase 2
    docker exec client dig +short example.com @172.16.2.10
    # expect: EMPTY / SERVFAIL -- NOT 172.16.1.30. Check the rcode explicitly:
    docker exec client dig example.com @172.16.2.10 | grep -i status
    # expect: status: SERVFAIL
    docker exec client curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 \
      http://example.com --resolve example.com:80:172.16.1.30
    # expect: curl fails/times out resolving (no address), the client never
    # even reaches rogue-web, because the resolver itself refused to hand out
    # the forged record

    # 4. Turn forging back off
    docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'

**Why this is expected, not a bug**: the interceptor only overwrites the
4-byte A-record rdata in the captured, already-signed response. It doesn't
hold `domain-ns`'s private ZSK, so it cannot produce a valid RRSIG over the
*tampered* rdata. The resolver recomputes/validates the signature over what
it actually received, finds it doesn't match, and treats the whole response
as Bogus -- rejecting it rather than falling back to an unsigned answer
(that fallback-to-insecure behavior is exactly what Phase 4 attacks instead).

## Capturing evidence

Same approach as Phase 2 -- `tcpdump` on `core-router` for the resolver↔
authoritative exchange, `docker logs attacker` to show forging is still
being attempted (`forged` counter still increments -- the attack is
*attempted*, just rejected downstream), and the `dig`/`delv` output above.
A `capture_evidence.sh` matching Phase 2's can be added once the base
sequence above is confirmed working on your setup -- say the word and I'll
write it against your real evidence like we did for Phase 2.

## Report notes (for `report.pdf` §3.4)

- **What the resolver does with the forged response**: validates its RRSIG
  against the (tampered) rdata, fails, marks the record Bogus, and returns
  SERVFAIL to the client rather than serving the forged (or any) answer.
  Contrast with Phase 2, where the same forged packet was accepted outright.
- **What the on-path attacker can still read**: everything. DNSSEC signs
  responses, it does not encrypt them -- the query and the real signed
  answer both still cross the wire in cleartext, exactly as in the Phase 1
  capture. An attacker in this position can still see every query and
  response; it just can no longer successfully *alter* one without
  detection. (Confidentiality of the last mile is Phase 7's problem, not
  DNSSEC's.)
- **Signing algorithm**: `ECDSAP256SHA256` (algorithm 13). Chosen over
  RSASHA256 for much smaller keys and signatures (64-byte ECDSA signatures
  vs. ~256+ bytes for 2048-bit RSA), which matters for response sizes/UDP
  fragmentation in a DNSSEC chain with multiple RRSIGs per response; the
  trade-off is slightly lower universal support in very old validators,
  which is irrelevant inside this closed lab.
- **Private keys in the repo**: no. `sign-zones.sh` generates fresh KSK/ZSK
  pairs for all three zones on every run, under `*/keys/`, which is
  `.gitignore`'d along with every `*.signed` zone file and
  `resolver/trust-anchor.conf`. Only the plain source zone files and the
  signing script itself are committed; a grader regenerates everything
  locally by running `./sign-zones.sh`.

## Teardown

    docker compose down -v
    