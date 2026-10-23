# Phase 6 — Last-Mile Response Forgery

## Prerequisites (Windows + WSL2)
Run everything from inside your WSL2 Linux distro's terminal (not PowerShell/cmd), same as Phases 1-5.

## What's new vs Phase 3

- Upstream of the resolver (root-ns/tld-ns/domain-ns, the signed
  hierarchy, the resolver's own validation) is **completely untouched** —
  same full chain as Phase 3/4, reused as-is.
- The `attacker` moves from the resolver subnet to the **client subnet**
  (`172.16.1.100`), and attacks the opposite leg: `edge-router` diverts
  **resolver → client** replies through it (`ip route add 172.16.1.10/32
  via 172.16.1.100`), the mirror image of Phase 2's core-router diversion
  of authoritative → resolver replies. No ARP spoofing, and the client's
  routing/resolver configuration is set once at deploy time and never
  touched by the attack itself (see `client/entrypoint.sh`).
- `attacker/interceptor.c` is the same forge-only technique as Phase 2
  (overwrite the A record's rdata, leave everything else untouched —
  critically, it does **not** strip any RRSIG, unlike Phase 4: there's
  nothing to downgrade here, the resolver→client leg was never signed in
  the first place). The one addition: it explicitly sets the `ad` flag on
  every forged reply, to make concrete that the bit is just attacker-
  settable data, not a cryptographic property of the reply.
- Two clients query through the same forged traffic simultaneously:
  - **Client A** — an ordinary stub: `curl` via the client's own OS
    resolver (`/etc/resolv.conf` pointed at `172.16.2.10`, set once at
    deploy time). Trusts whatever the resolver (or whoever is impersonating
    it) hands back, `ad` flag included.
  - **Client B** — `delv -a client/trust-anchor.conf`, holding its own
    copy of the exact same root trust anchor the resolver uses, and
    validating the DNSSEC chain itself rather than taking the resolver's
    word for it.

Keys and signed zones are **generated at deploy time**, not committed to
git (see `.gitignore`), exactly as in Phase 3/4/5. `sign-zones.sh` also
writes `client/trust-anchor.conf` — an exact copy of the resolver's trust
anchor, for Client B.

## Deploy

    cd phase6
    ./sign-zones.sh
    docker compose up -d --build
    docker compose ps          # all containers should be "Up"

Re-running `./sign-zones.sh` regenerates every key; restart all four DNS
containers together afterward, same caveat as every earlier phase:

    docker compose restart root-ns tld-ns domain-ns resolver

## Verify (forging off — relay should be transparent)

    docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'
    docker exec client curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 http://example.com
    docker exec client dig +short example.com @172.16.2.10
    # expect: 200, and 172.16.1.20 -- the real page, through the diverted-
    # but-not-forged attacker, proving the relay itself is transparent

## Attack

    # Turn forging on
    docker exec attacker sh -c 'echo 1 > /tmp/forge_enabled'

    # Client A: ordinary stub, via the OS resolver
    docker exec client curl -s -o /dev/null -w "%{http_code}\n" --max-time 5 http://example.com
    docker exec client dig example.com @172.16.2.10 | grep -E "status:|flags:"
    # expect: 200 (landed on rogue-web), dig shows the forged
    # 172.16.1.30 with 'ad' in the flags -- set by the attacker, not earned

    # Client B: locally-validating, against its own trust anchor
    docker exec client delv -a /root/trust-anchor.conf example.com @172.16.2.10
    # expect: validation failure (something like "no valid RRSIG" /
    # "resolution failed"), NOT "; fully validated" -- Client B's own
    # signature check catches the rdata/RRSIG mismatch regardless of what
    # the wire claims

    # Turn forging back off afterward
    docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'

## Capturing evidence

    ./capture_evidence.sh

Runs the verify step, then the attack against both clients, writing
`verify_curl.txt`, `verify_dig.txt`, `clientA_curl.txt`, `clientA_dig.txt`,
`clientB_delv.txt`, `attacker_log.txt`, and a `SUMMARY.txt` into a
timestamped `evidence/<timestamp>/` directory. Leaves forging off when it
finishes.

## Report notes (for `report.pdf` §6.4)

- **Outcome per client**: Client A lands on the rogue page (`curl` returns
  `200` from `rogue-web`, `dig` shows `172.16.1.30` with `ad` set). Client
  B's independent validation fails and it refuses to treat the answer as
  good, reporting the signature check failure rather than silently
  returning (or worse, "successfully" returning) the forged address.
- **Why upstream DNSSEC validation doesn't stop this; where validation
  happens vs. where trust is placed**: the resolver genuinely did validate
  the real answer against the real chain of trust — that part of DNSSEC
  worked exactly as designed, same as Phase 3. But validation happening
  *at the resolver* only protects data *up to the resolver*. The
  resolver→client leg is a separate, distinct hop, carrying plain
  unauthenticated UDP, and the client's only connection to "the resolver
  validated this" is trusting whichever packet shows up claiming to be
  from `172.16.2.10:53` in response to its query. That's not a chain of
  cryptographic custody reaching the client, it's one hop of implicit
  network trust (the client trusts *whatever arrives on this link*, the
  exact same assumption Phase 2 broke on the *other* side of the
  resolver). DNSSEC's trust anchor lives in the resolver's configuration,
  not in anything that reaches the client, so nothing the client receives
  is itself proof of anything unless the client does its own validation.
- **The `ad` flag, and why an attacker can set it at will; what Client B
  does differently**: `ad` is one bit in a plaintext header, set by
  whoever answers — originally meant as the resolver's own claim to a
  *downstream client that trusts that resolver completely* ("I checked
  this"), not as a verifiable, tamper-evident signal. It carries no
  signature, no binding to the rest of the message's contents, nothing a
  recipient without its own trust anchor can check independently. An
  on-path attacker between the resolver and the client can set it, clear
  it, or leave it exactly as easily as it can rewrite an A record's rdata
  -- it's just more bytes in an unauthenticated packet. Client B doesn't
  read or trust that bit at all: it re-derives the result itself, fetching
  the actual `RRSIG`/`DNSKEY` material in the response and checking the
  signature against its own, independently-held copy of the root key.
  Since the attacker can change the A record's rdata but cannot produce a
  valid signature over that changed data (same structural limit as every
  signed-zone attack in this lab, now enforced by the client instead of
  the resolver), Client B's check fails and it correctly refuses the
  answer — proving that what actually protects a DNSSEC-aware client
  isn't being told "this was validated," it's validating the data itself.

## Teardown

    docker compose down -v
