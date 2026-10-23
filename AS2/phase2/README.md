# Phase 2 — On-Path Response Forgery

## Prerequisites (Windows + WSL2)
Run everything from inside your WSL2 Linux distro's terminal (not PowerShell/cmd), same as Phase 1.

## Deploy

    cd phase2
    docker compose build
    docker compose up -d
    docker compose ps          # all 12 containers should be "Up"

The `attacker` (172.16.2.100) sits on the resolver subnet. `core-router` installs a
`/32` host route (`172.16.2.10 via 172.16.2.100`) that diverts resolver-bound traffic
through the attacker instead of delivering it directly, even though both are on the
same connected subnet — a more specific route beats the connected one. The resolver
and nameservers are untouched from Phase 1.

## Verify (forging disabled — transparent relay)

Forging is off by default (`interceptor` starts with no `/tmp/forge_enabled` toggle
file, which it treats as disabled).

    docker compose restart resolver
    docker exec client dig +short example.com @172.16.2.10
    # expect: 172.16.1.20  (the real webserver)
    docker exec client curl -s http://example.com --resolve example.com:80:172.16.1.20
    # expect: the real "example.com" page, not the defaced one

This proves the interceptor is on-path (all DNS traffic routes through it — see
`docker logs attacker`, which logs every packet it relays) but passes everything
through unmodified when forging is off.

## Attack (forging enabled)

    # 1. Turn forging on inside the attacker container
    docker exec attacker sh -c 'echo 1 > /tmp/forge_enabled'

    # 2. Clear the resolver's cache so it re-resolves from the authoritative chain
    #    (otherwise it would just serve the real answer it already cached above).
    #    Restarting the container is used instead of `rndc flush`: the image's
    #    named.conf defines no controls/key block, so named falls back to an
    #    auto-generated session key that the plain `rndc` CLI doesn't know to
    #    use, and it isn't worth wiring up a real rndc key just for this.
    #    A restart clears BIND's in-memory cache just as reliably.
    docker compose restart resolver

    # 3. Trigger the poisoned lookup
    docker exec client dig +short example.com @172.16.2.10
    # expect: 172.16.1.30  (rogue-web, NOT the real server)
    docker exec client curl -s http://example.com --resolve example.com:80:172.16.1.30
    # expect: the defaced rogue-web page

    # 4. Confirm the attack is scoped to the one target name only
    docker exec client dig +short www.example.com @172.16.2.10
    # expect: 172.16.1.20  (unaffected — interceptor only rewrites "example.com.")

    # 5. Turn forging back off when done
    docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'

## Confirmed results (from `evidence/20261023_182237/`)

A full run of `capture_evidence.sh` produced:
- `01_verify_relay_dig.txt` → `172.16.1.20`, `01_verify_relay_curl.txt` → real
  "This is the REAL example.com" page.
- `02_attack_dig.txt` → `172.16.1.30`, `02_attack_curl.txt` → rogue-web's
  defaced page ("DEFACED — this is rogue-web, not the real site.").
- `03_nontarget_dig.txt` → `172.16.1.20` (unchanged, confirming the relay is
  scoped to the target name only).
- `attacker.log` → `[FORGE]` lines appear only for responses sourced from
  `172.16.3.30:53` (domain-ns, the authority for `example.com`) matching the
  target query; every other relayed packet logs `[relay]`.
- `injected.pcap`, packet 34: a `RESPONSE` with `id=48285`, `flags=aa`,
  from `172.16.3.30:53` (domain-ns's spoofed source address) to the resolver,
  `ANSWER: example.com. A 172.16.1.30` — this is the forged packet actually
  injected onto the wire. Use this frame for the report's annotated-capture
  screenshot.

## Capturing evidence

A single script automates the full verify + attack sequence above and collects
logs/captures into `phase2/evidence/`:

    cd phase2
    ./capture_evidence.sh

This produces, inside `evidence/<timestamp>/`:
- `01_verify_relay_dig.txt`, `01_verify_relay_curl.txt` — forging-off baseline
- `02_attack_dig.txt`, `02_attack_curl.txt` — the poisoned lookup and defaced fetch
- `03_nontarget_dig.txt` — proof `www.example.com` is untouched
- `attacker.log` — full `interceptor` stderr log for the run (per-packet
  `relay`/`FORGE` lines with running seen/relayed/forged counters)
- `core-router.pcap` — capture taken on `core-router` (sees all
  resolver↔authoritative traffic, the only path between those subnets)
- `injected.pcap` — the interceptor's own dump of every packet it relayed or
  forged (written by `pcap_dump` inside `interceptor.c` itself — direct evidence
  of what left the attacker's raw socket)
- `*_annotated.txt` — human-readable decode of each pcap (via `parse_pcap.py`)
  showing query/response, transaction IDs, and answer records per packet

Open the `.pcap` files in Wireshark for the report screenshots; use the
`*_annotated.txt` files to identify exactly which frame numbers to screenshot
(look for the `example.com` A-record answer where `rdata` is `172.16.1.30`
instead of `172.16.1.20`, and compare the forged response's transaction ID
against the legitimate `domain-ns` response's ID — they must match the
client's original query for BIND to accept it).

## Notes

- Clearing the resolver's cache is required before the attack run: `resolver`
  caches whatever it resolved in the verify step, so without clearing it the
  attack dig would just return the already-cached real answer regardless of
  what the attacker sends. We restart the `resolver` container to clear it
  rather than use `rndc flush`, since the stock `named.conf` here defines no
  control-channel key.
- The interceptor relays **every** DNS packet it sees (not just forged ones) —
  it recomputes the UDP checksum unconditionally before re-injecting each
  packet via a raw `IP_HDRINCL` socket, since the kernel does not supply a
  checksum for raw sockets and captured bytes can carry a stale/offloaded one
  that is only valid for the original transmission, not a re-injected copy.
- The toggle file (`/tmp/forge_enabled`) lives inside the `attacker` container
  and is checked on every matching DNS response, so forging can be flipped on
  and off mid-session without restarting the container.

## Teardown

    docker compose down -v
