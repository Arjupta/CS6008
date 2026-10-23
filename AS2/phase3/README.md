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

    # For the HTTP-level check, do NOT use `curl --resolve` -- it skips DNS
    # lookup entirely and connects straight to the IP you give it, so it
    # "succeeds" even when DNS is correctly blocking the attack (it tells
    # you nothing). The client's default /etc/resolv.conf points at
    # Docker's own embedded DNS (127.0.0.11), not our lab resolver -- that's
    # why every dig command above says `@172.16.2.10` explicitly. Point the
    # client's real resolver at our resolver first, then let curl do an
    # unforced lookup:
    docker exec client sh -c 'echo "nameserver 172.16.2.10" > /etc/resolv.conf'
    docker exec client curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 \
      http://example.com
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

    ./capture_evidence.sh

Same approach as Phase 2 -- `tcpdump` on `core-router` for the resolver↔
authoritative exchange, `docker logs attacker` to show forging is still
being attempted (`forged` counter still increments -- the attack is
*attempted*, just rejected downstream), and the `dig`/`delv` output above.
Writes everything to a timestamped `evidence/<timestamp>/` directory
(`.gitignore`'d, not committed): baseline dig/delv output and pcap, attack
dig/curl output, attacker log, and pcap, plus a `SUMMARY.txt`. Leaves
forging off and the resolver cache flushed when it finishes, so the
environment is back in its clean baseline state afterward.

## Known issue found and fixed: out-of-bailiwick glue stripped by signing

Earlier versions of `db.root`, `db.com`, and `db.example.com` named every
nameserver under a shared, fictional `cs6008.local` suffix (e.g.
`tld-ns.cs6008.local.`, `domain-ns.cs6008.local.`) instead of under the
zone each one actually serves. Those names are "out-of-bailiwick" relative
to the delegations they were glue for: `tld-ns.cs6008.local.` isn't a
subdomain of `com.`, and `domain-ns.cs6008.local.` isn't a subdomain of
`example.com.`.

Plain, unsigned BIND (Phases 1-2) tolerates this -- it logs a warning
(`ignoring out-of-zone data (...)`) but still serves the glue A records as
literal zone content. `dnssec-signzone`, however, actually drops
out-of-bailiwick data from the *signed* zone it produces. The effect:
`tld-ns`'s signed referral for `example.com` carried the NS record but no
glue, forcing the resolver to resolve `domain-ns.cs6008.local` on its own --
which fails outright, since `cs6008.local` was never delegated from `.`
anywhere in this hierarchy. Resolution broke below the root, which masked
whether DNSSEC validation itself was doing anything at all (you can't test
"does the resolver reject a bad signature" when it can't even reach the
authoritative server to get an answer, forged or not).

**Fix**: renamed every nameserver to an in-bailiwick name relative to the
zone it's glue for -- `tld-ns.com.` (under `com.`, delegated by `root-ns`)
and `domain-ns.example.com.` (under `example.com.`, delegated by `tld-ns`).
`root-ns`'s own apex name (`root-ns.cs6008.local.`) was left unchanged: the
root zone's authority covers the entire namespace, so nothing is
out-of-bailiwick relative to it -- confirmed by the fact that root-ns never
logged the warning and its glue was never stripped. After the fix, both
`tld-ns` and `domain-ns` stopped logging the warning, and
`dig example.com @172.16.2.10` (no `+cd`) returns `NOERROR` with the `ad`
flag set, confirming full chain-of-trust validation -- and the attack test
below now correctly returns `SERVFAIL` on the forged answer, which it could
not have reliably demonstrated before this fix.

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
    