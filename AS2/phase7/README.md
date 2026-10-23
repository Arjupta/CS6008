# Phase 7 — Encrypting the Last Mile (DoT / DoH)

## Prerequisites (Windows + WSL2)
Run everything from inside your WSL2 Linux distro's terminal (not PowerShell/cmd), same as Phases 1-6. This phase additionally needs `openssl` on the host (already present on Ubuntu/WSL2 by default).

## What's new vs Phase 6

- Reuses the Phase 6 deployment (same three subnets, same signed hierarchy, same `attacker` position on the client subnet at `172.16.1.100`, same always-on reply-side route diversion at `edge-router`). Upstream of the resolver is still completely untouched.
- Phase 6 had one ordinary client and one independently-validating client (`delv`). Phase 7 instead has **two ordinary clients that differ only in fallback policy**:
  - **`client-strict`** (`172.16.1.10`) — `stubby` configured with `dns_transport_list: [GETDNS_TRANSPORT_TLS]` and nothing else. There is no cleartext path anywhere in this container's resolution chain, full stop.
  - **`client-permissive`** (`172.16.1.11`) — the same DoT-only `stubby`, but listening on `127.0.0.1:5353` instead of `:53`. `permissive-resolver.py` is what actually answers on `:53` (what `/etc/resolv.conf` points at): it tries the DoT leg first and only falls back to the resolver's plain port 53, in cleartext, if that attempt fails. That fallback is this client's explicit permission to re-expose itself to exactly what Phase 6 broke.
- A private CA (`make-pki.sh`) issues the resolver's certificate with **only** a DNS subject-alternative-name, `resolver.cs6008.local` — no IP SAN. Both clients get `extra_hosts: resolver.cs6008.local -> 172.16.2.10` and trust only this CA (installed via `update-ca-certificates`, no `-k`/insecure bypass anywhere).
- `resolver/named.conf` adds a `tls` block and `listen-on port 853 tls local-tls` — BIND 9.18+ native DoT, no separate proxy. Plain port 53 is deliberately still open: it's what `client-permissive`'s fallback (and attacks ii/iii) exercise on purpose. The resolver isn't insecure for offering it; a client *choosing* to fall back to it is the thing under test.
- `edge-router` keeps Phase 6's always-on reply-diversion route (now for both clients) and adds `set-attack.sh`, which toggles between `none`, `roguecert` (a DNAT rule redirecting `client->172.16.2.10:853` to the attacker) and `deny` (drops all forwarded TCP:853). `attacker` adds an NFQUEUE-based TLS-payload corruptor (`corrupt.py`, attack i) and a rogue TLS listener (`rogue_tls_server.py`, attack ii), toggled the same `/tmp/forge_enabled`-file way as every earlier phase. The Phase 6 `interceptor.c` binary is reused unchanged for one bonus/chained demonstration only (see Attack section and `README`'s report notes).

Keys, certs and signed zones are **generated at deploy time**, not committed to git (see `.gitignore`), exactly as in Phases 3-6.

## Deploy

    cd phase7
    ./make-pki.sh
    ./sign-zones.sh
    docker compose up -d --build
    docker compose ps          # all containers should be "Up"

Re-running either script regenerates its material; restart the affected containers afterward (same caveat as every earlier phase):

    docker compose restart resolver client-strict client-permissive   # after make-pki.sh
    docker compose restart root-ns tld-ns domain-ns resolver          # after sign-zones.sh

## Verify (7.2 — encrypted, authenticated, and no cleartext leakage)

    docker exec edge-router bash /root/set-attack.sh none

    docker exec client-strict dig example.com | grep -E "status:|^example"
    docker exec client-strict curl -s -o /dev/null -w "%{http_code}\n" --max-time 8 http://example.com
    # expect: NOERROR, A 172.16.1.20, http 200 -- resolved entirely over DoT,
    # cert validated against resolver.cs6008.local (no IP SAN, so this can
    # only have worked by name), upstream DNSSEC chain still intact.

    docker exec client-permissive dig example.com | grep -E "status:|^example"
    docker exec client-permissive curl -s -o /dev/null -w "%{http_code}\n" --max-time 8 http://example.com
    # expect: same result -- the DoT leg succeeds on its own merits here,
    # so the permissive client's fallback is never even exercised.

    # confirm no cleartext DNS crosses edge-router for this lookup:
    docker exec edge-router timeout 5 tcpdump -i any -n 'udp port 53' &
    docker exec client-strict dig example.com >/dev/null
    # expect: zero packets captured

## Attack (7.3 — three attempts, six combinations)

    # (i) alter the answer in transit
    docker exec attacker sh -c 'echo 1 > /tmp/forge_enabled'
    docker exec client-strict     dig +time=4 +tries=1 example.com | grep status:
    docker exec client-permissive dig +time=4 +tries=1 example.com | grep status:
    docker exec attacker sh -c 'echo 0 > /tmp/forge_enabled'

    # (ii) impersonate the resolver with a rogue certificate
    docker exec edge-router bash /root/set-attack.sh roguecert
    docker exec client-strict     dig +time=4 +tries=1 example.com | grep status:
    docker exec client-permissive dig +time=4 +tries=1 example.com | grep status:
    docker exec edge-router bash /root/set-attack.sh none

    # (iii) deny the encrypted transport
    docker exec edge-router bash /root/set-attack.sh deny
    docker exec client-strict     dig +time=4 +tries=1 example.com | grep status:
    docker exec client-permissive dig +time=4 +tries=1 example.com | grep status:
    docker exec edge-router bash /root/set-attack.sh none

    # bonus (not one of the six required combos): (iii) chained with the
    # Phase 6 cleartext forger, permissive client only -- see report notes
    docker exec edge-router bash /root/set-attack.sh deny
    docker exec attacker sh -c 'echo 1 > /tmp/forge_cleartext_enabled'
    docker exec client-permissive dig +time=4 +tries=1 example.com
    docker exec attacker sh -c 'echo 0 > /tmp/forge_cleartext_enabled'
    docker exec edge-router bash /root/set-attack.sh none

## Capturing evidence

    ./capture_evidence.sh

Redeploys cleanly, runs the verify step, all three attacks against both clients, and the one bonus chained run, writing everything into a timestamped `evidence/<timestamp>/` directory with a `SUMMARY.txt`. Leaves every attack toggle off when it finishes.

## Report notes (for `report.pdf` §7.4)

### Per attempt, per client — did it land, and why

| Attempt | client-strict | client-permissive |
|---|---|---|
| (i) alter answer in transit | No answer (see caveat below) | **Correct answer**, via cleartext fallback |
| (ii) rogue certificate | No answer (see caveat below) | **Correct answer**, via cleartext fallback |
| (iii) deny transport | No answer (see caveat below) | **Correct answer**, via cleartext fallback — **unless** an attacker is *also* forging that fallback leg (see bonus run), in which case it lands |

**Caveat on `client-strict`'s results:** in this deployment, `client-strict`'s Stubby process (v0.3.0, the version packaged for Ubuntu 24.04) failed to come up reliably even in the clean, no-attack baseline — a container-specific startup failure that did not reproduce for `client-permissive` under an otherwise byte-identical TLS/cert/network configuration, and that time did not permit root-causing further. Its "no answer" rows above are therefore **not evidence that any attack succeeded or failed** against it — the client never resolved anything at all, attacks included. What *is* still a valid, by-construction claim is that `client-strict`'s refusal of cleartext is structural, not behavioral: its `stubby.yml` declares `dns_transport_list: [GETDNS_TRANSPORT_TLS]` and nothing else, so even a fully working instance would have had no transport to fall back to — there is no code path, config option, or process in this container capable of sending or accepting a plaintext DNS query. That property was verified by inspection, not by a live attack run.

**`client-permissive` is never deceived by attempts (i) or (ii) or (iii) *on their own*.** Each one defeats the DoT leg (corrupting it, impersonating it, or blocking it) but none of them, by itself, touches the cleartext fallback leg — so `permissive-resolver.py` falls back and gets the *real* answer from the real resolver over plain port 53, just more slowly and without the privacy/authentication DoT would have given that one query. The attacks succeed at breaking encryption; they do not succeed at forging content, because forging content on the fallback leg is a *different* attack — the one Phase 6 already demonstrated — and none of (i)/(ii)/(iii) include it.

That is also exactly why the bonus run exists: chain attempt (iii) with the unmodified Phase 6 cleartext forger, and the permissive client *does* land on the rogue page. Denying the encrypted transport doesn't itself forge anything — it just forces the client down to the one leg that was never authenticated in the first place, and if an attacker is sitting on that leg too (trivially true for the same on-path position that could deny the encrypted transport to begin with), the downgrade completes the attack. The six required combinations are honestly "no forgery lands from (i)/(ii)/(iii) alone against either client"; the bonus run is what shows *why permitting the fallback at all is still a real exposure*, not a merely theoretical one.

### DoT or DoH — which, and what are its drawbacks relative to the other

This phase deploys **DoT** (BIND's native `tls`/`listen-on port 853 tls` support). Relative to DoH:
- **Less firewall-friendly, by design.** DoT runs on its own dedicated port (853), which is precisely what made attack (iii) in this phase trivial — one `iptables --dport 853 -j DROP` rule and the encrypted transport is gone. DoH shares port 443 with ordinary HTTPS traffic, so blocking it without also blocking the web generally is far harder for a network operator (or an on-path attacker) to do surgically.
- **Easier to recognize and manage, for exactly the same reason.** An enterprise network that *wants* to see "this is DNS" for monitoring, filtering, or policy enforcement can do so cheaply with DoT (distinct port), whereas DoH deliberately blends DNS queries into generic HTTPS, which is good for resisting censorship/surveillance but bad for anyone who wants legitimate visibility into what's being resolved.
- **Lighter weight.** DoT is a direct TLS session carrying DNS message framing; DoH adds an HTTP/2 (or HTTP/1.1) layer on top of TLS, with its own framing and request/response semantics, for a small but real overhead increase per query.
- DoH's upside we're not exercising here is exactly the blocking-resistance property above, and that it can reuse any existing HTTPS client library/stack rather than requiring dedicated DNS-over-TLS support — which is also why, in this lab, letting ordinary tools (`curl`) resolve transparently required a local stub (`stubby`) regardless of which transport was chosen; neither transport is "free" to retrofit under an unmodified resolver library.

### What an encrypted, authenticated last mile still does *not* protect

- **It does not protect against the client's own fallback policy.** This is the whole point of having two clients: encrypting and authenticating the DoT leg does nothing for a client that is configured to accept an *unencrypted, unauthenticated* answer whenever the encrypted one isn't available. `client-permissive` is cryptographically no better defended than Phase 6's plain client the moment its preferred transport is unavailable — see the bonus run.
- **It does not protect against denial of service.** Blocking TCP 853 can't forge an answer for `client-strict`, but it can silence it completely. DoT/DoH give you integrity and authenticity, not availability; an attacker who can't lie to you can often still stop you from hearing anything at all.
- **It does not protect anything past the resolver.** Exactly as in Phase 6's analysis, encrypting resolver->client only moves the "last mile" problem one hop closer to the client — it says nothing about whether the resolver *itself* is trustworthy, or about the client->resolver->authoritative chain's own soundness (which is still just Phase 3-5's DNSSEC doing its job, unchanged). Authenticating *which resolver you're talking to* is not the same as trusting what that resolver tells you.
- **It does not protect the trust anchor's own custody.** Both the DNSSEC root key (Phase 3-5) and this phase's private CA are only as good as how they're provisioned and stored. A compromised CA private key, or a client tricked into installing the wrong CA certificate at setup time, defeats the entire mechanism before a single attacker packet is ever sent — none of 7.3's three attempts needed to go anywhere near that, because they didn't have to.

## Troubleshooting

This phase pulls in more new moving parts than Phases 1-6 (BIND's native DoT support, `stubby`, and a pip-installed `NetfilterQueue`/`scapy` combo for attack (i)), none of which this environment could build-test before handing it to you. If something doesn't come up clean:

- **`resolver` fails to start / complains about the `tls`/`listen-on port 853 tls` block.** Check `docker compose logs resolver`. Ubuntu 24.04's `bind9` package (9.18.x) supports DoT out of the box; if your actual package differs, `named -V` inside the container will show whether `--with-openssl`-style TLS support is compiled in.
- **`stubby` fails to install or start.** `docker compose logs client-strict` / `client-permissive`. It's in Ubuntu's universe repo as `stubby`; if `apt-get install stubby` 404s, your container's `apt` sources may need `universe` enabled.
- **Attack (i) doesn't seem to do anything.** `docker compose logs attacker` and check for `NetfilterQueue`/`scapy` import errors — the Dockerfile pip-installs both against `libnetfilter-queue-dev`, which occasionally needs a `pkg-config`/header version nudge on a different base image. Confirm the iptables rule exists: `docker exec attacker iptables -L FORWARD -n` should show the `NFQUEUE` target on `tcp spt:853`.
- **Attack (ii)'s rogue server never gets hit.** Confirm the DNAT rule landed: `docker exec edge-router iptables -t nat -L PREROUTING -n`, and that `attacker`'s `rogue_tls_server.py` is actually listening: `docker exec attacker ss -tlnp | grep 853`.
- **A query just hangs instead of failing fast.** That's expected for `client-strict` under attacks (ii)/(iii) — it has nowhere to fall back to, so it waits out stubby's own timeout. `capture_evidence.sh` bounds this with `+time=4 +tries=1` / `--max-time 8`; use the same bounds if testing by hand.

## Teardown

    docker compose down -v
    