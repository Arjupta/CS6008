# Phase 1 — Building the DNS Hierarchy

## Prerequisites
Ubuntu Linux with Docker Engine + Compose plugin installed:
```bash
docker --version
docker compose version
docker run hello-world   # sanity check daemon is reachable without sudo
```

## 1. Build the two shared base images

```bash
cd common
docker build -t dns-base      -f Dockerfile.bind .   # BIND 9.20.x (root-ns, tld-ns, domain-ns, resolver)
docker build -t dns-netbase   -f Dockerfile.base .    # plain networking tools (client, webserver, routers)
cd ..
```

Sanity checks:
```bash
docker run --rm dns-base named -v        # expect BIND 9.20.x
docker run --rm dns-netbase python3 --version
```

## 2. Deploy the full topology

```bash
cd phase1
docker compose build
docker compose up -d
docker compose ps        # all 8 containers should show "Up"
```

## 3. Verify — resolution and fetch

```bash
docker exec client dig +short example.com @172.16.2.10
# expect: 172.16.1.20

docker exec client curl -s --resolve example.com:80:172.16.1.20 http://example.com
# expect: the real example.com HTML page
```

## 4. Verify — subnet isolation

```bash
docker exec client dig +time=2 +tries=1 example.com @172.16.3.10
# expect: "network unreachable" (no route to the authoritative subnet at all) —
# this is the correct, required result, not a failure of the setup.
```

## 5. Verify — capture the referral chain on core-router

Identify which interface on `core-router` faces the authoritative subnet (172.16.3.3):
```bash
docker exec core-router ip addr
# note which ethN has inet 172.16.3.3/24
```

Capture on that single interface only (no NAT means both directions are
fully visible from either side, so one interface is sufficient and avoids
duplicate packets from capturing on "any"):
```bash
docker exec -d core-router tcpdump -i <ethN> -w /root/phase1.pcap udp port 53
docker compose restart resolver      # clear resolver cache so it performs a real walk
sleep 3
docker exec client dig example.com @172.16.2.10
sleep 2
docker exec core-router pkill tcpdump
docker cp core-router:/root/phase1.pcap .
```

Open `phase1.pcap` in Wireshark, filter `udp.port==53`. Expected sequence:
1. resolver → root-ns: `com. NS?` → referral (AUTHORITY: com NS tld-ns.com.,
   ADDITIONAL: tld-ns.com. A 172.16.3.20)
2. resolver → tld-ns: `example.com. A?` → referral (AUTHORITY: example.com NS
   domain-ns.example.com., ADDITIONAL: domain-ns.example.com. A 172.16.3.30)
3. resolver → domain-ns: `example.com. A?` → authoritative answer (aa flag set,
   ANSWER: example.com. A 172.16.1.20)

(You will also see a `. NS` priming query and opportunistic `AAAA` lookups for
discovered nameservers — this is normal recursive-resolver behavior, not
something configured deliberately.)

## 6. Teardown

```bash
docker compose down -v
```

## Known issue: `rndc` is not usable in this phase

Startup logs show:
```
open: /etc/bind/rndc.key: permission denied
```
This is because `named.conf`/zone files are bind-mounted read-only directly
into `/etc/bind/`, and `named` cannot write a new `rndc.key` into that same
read-only directory tree at first boot. `rndc`-based commands (e.g. `rndc
flush`) will fail authentication as a result. Workaround used throughout
Phase 1: `docker compose restart <service>` to clear cache/reload state
instead of `rndc`. This does not affect DNS serving or resolution — only
remote administrative control. To be fixed properly before Phase 2, since
Phase 2 explicitly requires cache flushing via `rndc` before each attack
attempt (a writable directory will be mounted in for BIND's runtime state
instead of pointing `rndc` at the read-only config directory).
