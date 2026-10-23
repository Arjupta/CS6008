# Phase 5 — Zone Walking

## Prerequisites (Windows + WSL2)
Run everything from inside your WSL2 Linux distro's terminal (not PowerShell/cmd), same as Phases 1-4.

## What's new vs Phase 3

- Reuses Phase 3's signed, validating deployment, with one addition:
  `domain-ns`'s `example.com` zone now carries **five internal names that
  are linked from nowhere** — `vpn`, `db1`, `mail`, `dev`, `staging` (see
  `domain-ns/db.example.com`). Nothing else in the zone references them;
  the only way to learn they exist, short of guessing, is from the zone's
  own authenticated-denial mechanism.
- `attacker`'s tool here is **not** an on-path interceptor (no diversion
  route on `core-router`, unlike Phases 2/3/4/6/7) — zone walking needs no
  privileged network position at all, just the ability to send ordinary
  DNS queries to the authoritative server. `attacker` gets a plain static
  route to the authoritative subnet instead, and `attacker/zonewalk.c`
  (C++, built against libpcap per the assignment's tooling policy — see
  its header comment for why/how) sends hand-crafted `QTYPE=NSEC` queries
  over a raw socket and reads the replies with libpcap.
- Two deployments, selected by which signing step you last ran:
  `sign-zones.sh` produces the **walkable** zone (`domain-ns` signs
  `example.com` with NSEC, `dnssec-signzone`'s default), and
  `resign-domain-ns-nsec3.sh` switches to the **fixed** zone (NSEC3
  instead, reusing the exact same keys — see that script's header for why
  nothing upstream of `domain-ns` needs to change).
- `allow-transfer { none; };` is set explicitly on every authoritative
  server, so AXFR is genuinely blocked, not just avoided by convention —
  the NSEC chain has to be the only way in.

Keys and signed zones are **generated at deploy time**, not committed to
git (see `.gitignore`), exactly as in Phase 3/4.

## Deploy

### Walkable deployment

    cd phase5
    ./sign-zones.sh
    docker compose up -d --build
    docker compose ps          # all containers should be "Up"

### Switch to the fixed deployment

    ./resign-domain-ns-nsec3.sh
    docker compose restart domain-ns resolver
    sleep 3

Only `domain-ns`'s signed zone file actually changes between the two —
`root-ns`, `tld-ns`, and the resolver's trust anchor are completely
unaffected, because a DS record depends on the child's DNSKEY, not on
whether that child uses NSEC or NSEC3. Switch back any time with
`./sign-zones.sh` + `docker compose restart root-ns tld-ns domain-ns resolver`
(the full four-way restart, since that script *does* regenerate every key).

## Verify

    # Any genuinely nonexistent name gets a proper denial, before and
    # after the fix -- query domain-ns directly (client has no route to
    # the authoritative subnet, by Phase 1's own isolation design, so use
    # the attacker container, which does have one).
    docker exec attacker dig +dnssec nosuchname.example.com @172.16.3.30
    # walkable deployment -- expect: status NXDOMAIN, an NSEC RR in the
    #   AUTHORITY section covering the queried name, with its RRSIG
    # fixed deployment    -- expect: status NXDOMAIN, an NSEC3 RR instead,
    #   with its RRSIG -- still a valid authenticated denial, just hashed

## Attack

    # Build happens automatically with `docker compose up -d --build`.
    # To run the walk again later without rebuilding:
    docker exec attacker ./zonewalk eth0 172.16.3.30 example.com.

**Walkable deployment expectation**: the tool prints one line per step,
each showing the current name and the "next" name taken straight from
that name's own NSEC record, until the ring closes back at `example.com.`.
Recovered names should be: the apex itself, `domain-ns.example.com.` (the
in-bailiwick NS glue), `www.example.com.`, and all five internal names
(`vpn`, `db1`, `mail`, `dev`, `staging`) — 8 total owner names, in
canonical sort order, using exactly 8 queries (well inside the
assignment's `(number of names + 2)` budget for recovering the zone's
*complete* owner set).

**Fixed deployment expectation**: the very first query (`NSEC
example.com.`) comes back `NODATA` — there is no NSEC RRset at that
literal owner name anymore, because NSEC3 owns its records by a *hash* of
each name, not the name itself. The walk prints that single line and
stops immediately, having recovered nothing.

## Capturing evidence

    ./capture_evidence.sh

Runs both deployments back-to-back (re-signing and restarting between
them), capturing the nonexistent-name verify query and the full walk
output for each into a timestamped `evidence/<timestamp>/{walkable,fixed}/`
directory with a `SUMMARY.txt`. Leaves the stack on the fixed (NSEC3)
deployment when it finishes; run `./sign-zones.sh` + the four-way restart
afterward if you want to leave things on the walkable baseline.

## Report notes (for `report.pdf` §5.4)

- **Recovered names**: `example.com.`, `domain-ns.example.com.`,
  `www.example.com.`, `vpn.example.com.`, `db1.example.com.`,
  `mail.example.com.`, `dev.example.com.`, `staging.example.com.` — see
  `evidence/<timestamp>/walkable/walk.txt` for the exact step-by-step
  queries and the "next" name each one revealed.
- **Which configuration made the walk possible, and why signed denial
  leaks content that plain DNS doesn't**: NSEC, dnssec-signzone's default.
  Plain (unsigned) DNS can say "no such name" for a single queried name
  without revealing anything about any *other* name in the zone — a
  one-off negative answer needs no supporting data beyond the fact of its
  own nonexistence. Signed denial can't do that: the server has to be able
  to *prove*, with a signature computed in advance (offline, since the
  signing key normally isn't kept online), that no record exists for
  whatever name gets asked — including names nobody has thought to ask
  about yet. The only way to pre-compute a proof like that for every
  possible nonexistent name is to describe a *range* with no names in it,
  bounded by two names that genuinely do exist and sign that range
  statement ahead of time. NSEC does this in the most direct way
  possible: it chains every real owner name to its immediate successor in
  sorted order, in plaintext, so proving "nothing exists between X and Y"
  is the same record as revealing that X's very next neighbor is,
  verbatim, Y. The chain that proves absence is, structurally, identical
  to an index of everything present.
- **What the fix (NSEC3) costs the operator, and what an enumerator can
  still learn afterward**: NSEC3 keeps the same offline-signed-range
  mechanism, but indexes by a hash of each owner name instead of the name
  itself, so the "next" field in any given record is unreadable without
  reversing that hash. The operator pays for this in a few ways: slightly
  larger zone files and responses (an extra hash field, and NSEC3's
  opt-out/flags byte), a small amount of CPU at signing time to compute
  the hashes, and — this is the part that matters for anyone reusing
  this configuration outside a lab — the hash is only as strong as the
  resistance to being brute-forced back to plaintext. This phase follows
  RFC 9276's current guidance (empty salt, zero extra iterations) because
  for a *resolver population* an attacker only has to compute a dictionary
  of hashes once and reuse it everywhere the salt matches; modern hardware
  makes that cheap enough that extra iterations barely slow a targeted
  attacker down while still costing every validating resolver real CPU on
  every single validation, forever. What NSEC3 does *not* hide: the
  **count** of owner names in the zone (each NSEC3 record is still one
  record per name, so an enumerator can walk the hash ring exactly as
  before and learn "this zone has exactly 8 owner names," just not what
  any of them are spelled), and any name an enumerator already suspects
  can still be *confirmed* in a single ordinary query — NSEC3 defeats
  blind enumeration of a zone's contents, not verification of a specific
  guess. Given enough guesses (e.g. a wordlist of common internal
  hostnames) an attacker can still eventually hash-match a name into the
  revealed ring, which is exactly the lower level of risk NSEC3 is meant
  to leave: forcing a guess-and-check approach instead of a free,
  wordlist-less sweep of the entire zone.

## Teardown

    docker compose down -v
