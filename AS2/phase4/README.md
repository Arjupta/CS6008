# Phase 4 — Signature Stripping & Downgrade

## Prerequisites (Windows + WSL2)
Run everything from inside your WSL2 Linux distro's terminal (not PowerShell/cmd), same as Phases 1-3.

## What's new vs Phase 3

- Reuses Phase 3's signed hierarchy and validating resolver unchanged (same
  `named.conf`s, same `dnssec-validation yes;`).
- `attacker`'s interceptor is **extended**, not replaced: it keeps Phase 2/3's
  rdata-only forge (overwrite an A record's 4-byte rdata in place, leave
  everything else byte-for-byte as captured), and adds an independent
  **strip mode** (`/tmp/strip_enabled`, alongside the existing
  `/tmp/forge_enabled`). When strip mode is on, for any response whose
  question name is `example.com.`, every `RRSIG` (type 46), `DNSKEY` (type
  48) and `DS` (type 43) record anywhere in the message — ANSWER,
  AUTHORITY, or ADDITIONAL — is physically removed (owner name, type,
  class, TTL, rdlength and rdata all excised; the IP/UDP lengths and both
  checksums are recomputed) before the forge step runs. One type-driven
  rule this way covers all three exchanges a signed `example.com`
  resolution produces, since they all share that same question name:
  `domain-ns`'s answer to `example.com A` (strips `RRSIG(A)`), its answer to
  `example.com DNSKEY` (strips `DNSKEY`+`RRSIG(DNSKEY)`), and `tld-ns`'s
  referral for `example.com` (strips the `DS`+`RRSIG(DS)` riding in its
  AUTHORITY section). See `attacker/interceptor.c`'s header comment for the
  full design note, including the one documented simplification it shares
  with Phase 2/3 (name-compression pointers are assumed to target the
  question name, which is true for every response this lab's BIND
  instances produce).
- Two deployments, selected by which signing script you last ran:
  `sign-zones.sh` (**Run A** — identical full chain to Phase 3, every DS
  published) and `sign-zones-runB.sh` (**Run B** — `example.com` is fully,
  correctly signed by `domain-ns`, but `tld-ns`'s `com` zone is signed
  *without* ever being given `example.com`'s DS — the one-line operator
  mistake the assignment asks for).

Keys and signed zones are **generated at deploy time**, not committed to
git (see `.gitignore`), exactly as in Phase 3.

## Deploy

### Run A — full chain, attack should still fail

    cd phase4
    ./sign-zones.sh
    docker compose up -d --build
    docker compose ps          # all containers should be "Up"

### Run B — switch to the broken-delegation deployment

    ./sign-zones-runB.sh
    docker compose restart root-ns tld-ns domain-ns resolver
    sleep 3

Same container-restart caveat as Phase 3: BIND only reads its zone file at
startup, and every re-sign generates brand-new keys, so **all four DNS
containers** (`root-ns tld-ns domain-ns resolver`) must restart together
after every re-run of either sign script — restarting only `resolver`
leaves it holding a trust anchor for a signing generation the
authoritative servers aren't actually serving.

Switch back to Run A any time with `./sign-zones.sh` + the same four-way
restart.

## Verify (before attacking)

    # Run A: should authenticate normally, same as Phase 3
    docker exec client dig +dnssec example.com @172.16.2.10 | grep -E "flags:|status:"
    # expect: status: NOERROR, flags include ad

    # Run B (after switching): resolver no longer validates example.com at
    # all -- it's "insecure", not "bogus". Still resolves, just without ad.
    docker exec client dig +dnssec example.com @172.16.2.10 | grep -E "flags:|status:"
    # expect: status: NOERROR, flags do NOT include ad (no RRSIG requested/checked)

## Attack (same attacker config for both runs; only the deployment differs)

    # 1. Turn on forging AND stripping together
    docker exec attacker sh -c 'echo 1 > /tmp/forge_enabled'
    docker exec attacker sh -c 'echo 1 > /tmp/strip_enabled'

    # 2. Clear the resolver's cache (restart, not rndc)
    docker compose restart resolver
    sleep 3

    # 3. Point the client's real resolver at our lab resolver before using
    #    curl -- its default /etc/resolv.conf is Docker's own embedded DNS,
    #    not 172.16.2.10 (see Phase 3's README for why `curl --resolve`
    #    must NOT be used here: it skips DNS lookup entirely).
    docker exec client sh -c 'echo "nameserver 172.16.2.10" > /etc/resolv.conf'

    # 4. Trigger the lookup and fetch
    docker exec client dig example.com @172.16.2.10 | grep -i status
    docker exec client curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 http://example.com

    # 5. Turn forging/stripping back off
    docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'
    docker exec attacker sh -c 'echo 0 > /tmp/strip_enabled'

**Run A expectation**: `status: SERVFAIL`, curl fails/times out. The
resolver was expecting signed data for `example.com` at every step (it has
a real DS for it from a real parent) and instead got silence where a
signature, key, or DS should have been — that's indistinguishable from
corruption/attack, not from "this is legitimately unsigned", so it's
treated as Bogus.

**Run B expectation**: `dig` returns `172.16.1.30` (the forged address,
`NOERROR`, no `ad`), curl lands on the rogue page. Nothing about the wire
exchange with `domain-ns` needs to look suspicious for this to work — the
resolver already stopped expecting anything signed for `example.com`
*before* the attacker touched a single byte, simply because `com` never
gave it a DS to chain through.

## Capturing evidence

    ./capture_evidence.sh

Runs both deployments back-to-back (re-signing and restarting the stack
between them), capturing `dig`/`curl` output, `core-router` pcaps, and the
attacker's log for each, into a timestamped `evidence/<timestamp>/{runA,runB}/`
directory with a `SUMMARY.txt`. Leaves the stack on Run B's deployment with
forging/stripping off when it finishes; run `./sign-zones.sh` + the restart
again afterward if you want to leave things on the Run A baseline.

## Report notes (for `report.pdf` §4.4)

- **Run A — why stripping fails**: the attacker can delete bytes in
  transit, but it cannot *add* a valid, signed proof that `example.com` is
  unsigned. A genuinely insecure delegation is provable precisely because
  the **parent** zone's own signature vouches for the absence of a DS (an
  authenticated denial, e.g. via NSEC/NSEC3 — see Phase 5) — something only
  the parent's private key can produce. Deleting the DS off the wire
  mid-flight doesn't manufacture that proof; it just leaves the resolver
  expecting data it never receives, which it correctly treats as a
  validation failure (Bogus → SERVFAIL), not as "this zone turned out to be
  unsigned after all." The same logic applies one level down: deleting
  `RRSIG`/`DNSKEY` from `example.com`'s own answers doesn't erase the fact
  that the resolver already knows (via the DS it *did* get) that
  `example.com` is supposed to be signed.
- **Run B — the actual operator mistake, and why it reopens the attack**:
  the single change is that `tld-ns`'s `com` zone is signed without
  `example.com`'s DS record ever being appended to it (see
  `sign-zones-runB.sh` step 2, the one diff from `sign-zones.sh`). The
  resolver, walking down from a fully-valid root→com chain, asks `com` for
  a secure delegation to `example.com` and — correctly, per DNSSEC's own
  rules — finds none. It can prove no DS exists (com's own `NSEC`/`NSEC3`
  denial, nothing stripped, nothing forged), so it legitimately concludes
  `example.com` is an **island with no secure link to it**, i.e.
  provably-insecure from the resolver's point of view, and stops expecting
  or checking any signature under it. `example.com` being *actually* fully
  signed by `domain-ns` is irrelevant at that point — the resolver never
  asks it to prove anything, because the chain was already severed one
  level up.
- **Where downgrade resistance actually comes from**: not from the child
  zone's own diligence, and not from anything the resolver can infer from
  a response's shape — it comes entirely from an unbroken, continuously
  signed, parent-published DS chain from the resolver's trust anchor down
  to the name in question. Breaking that chain at any single link (an
  unpublished DS) is functionally equivalent, from the resolver's
  perspective, to the zone never having been signed at all — regardless of
  how carefully everything below that break is signed.

## Teardown

    docker compose down -v
