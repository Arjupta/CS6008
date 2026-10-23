#!/bin/bash
# Phase 7: stand up a tiny private CA and issue the resolver's DoT
# certificate from it -- generated at deploy time, never committed (see
# .gitignore), exactly like Phase 3-6's DNSSEC keys.
#
# The resolver's certificate carries EXACTLY ONE name: the DNS
# subject-alternative-name resolver.cs6008.local -- no IP SAN, on
# purpose (per 7.1), so that validating by name is the only way a
# client's certificate check can ever succeed. Also issues a second,
# deliberately UNTRUSTED certificate for the SAME name (self-signed, no
# relation to the real CA) -- attack (ii)'s rogue_tls_server.py uses it
# to impersonate the resolver.
#
# Run from inside phase7/, before `docker compose up`. Requires openssl
# on the host (already on Ubuntu/WSL2 by default -- this is the one
# script in this assignment that does NOT need Docker, since the
# resolver's own cert/key just need to exist on disk before its
# container starts).

set -e
RESOLVER_NAME="resolver.cs6008.local"

echo "== Cleaning previous generated PKI material =="
rm -rf ca resolver/certs attacker/rogue-cert client-strict/ca.crt client-permissive/ca.crt
mkdir -p ca resolver/certs attacker/rogue-cert

echo "== [1/3] Private CA -- the one thing BOTH clients will trust =="
openssl genrsa -out ca/ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca/ca.key -sha256 -days 3650 \
  -subj "/O=CS6008 Lab/CN=CS6008 Lab Private CA" \
  -out ca/ca.crt 2>/dev/null

echo "== [2/3] Resolver's real certificate -- DNS SAN only, no IP SAN =="
openssl genrsa -out resolver/certs/resolver.key 2048 2>/dev/null
openssl req -new -key resolver/certs/resolver.key \
  -subj "/CN=$RESOLVER_NAME" \
  -out resolver/certs/resolver.csr 2>/dev/null
cat > resolver/certs/resolver.ext <<EOF
subjectAltName = DNS:$RESOLVER_NAME
EOF
openssl x509 -req -in resolver/certs/resolver.csr \
  -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
  -out resolver/certs/resolver.crt -days 825 -sha256 \
  -extfile resolver/certs/resolver.ext 2>/dev/null
rm -f resolver/certs/resolver.csr ca/ca.srl resolver/certs/resolver.ext

# openssl writes the key 600 (owner-read-only). resolver/certs/ is
# bind-mounted read-only into the resolver container, so whatever UID
# named actually runs/reads as there -- which doesn't necessarily match
# the host UID that owns this file -- has to be able to read it; there
# is no way to fix this from inside a :ro mount after the fact. This is
# a lab private key, not a production secret, so world-readable is an
# acceptable trade for "it actually starts".
chmod 644 resolver/certs/resolver.key resolver/certs/resolver.crt

echo "== [3/3] Rogue certificate for attack (ii) -- same name, self-signed, NOT issued by the real CA =="
openssl genrsa -out attacker/rogue-cert/rogue.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key attacker/rogue-cert/rogue.key -sha256 -days 825 \
  -subj "/O=Not The Real CA/CN=$RESOLVER_NAME" \
  -addext "subjectAltName=DNS:$RESOLVER_NAME" \
  -out attacker/rogue-cert/rogue.crt 2>/dev/null

cp ca/ca.crt client-strict/ca.crt
cp ca/ca.crt client-permissive/ca.crt

echo
echo "Done."
echo "  ca/ca.crt                       -- installed in BOTH clients' trust stores, no -k bypass"
echo "  resolver/certs/resolver.crt     -- CN/SAN=$RESOLVER_NAME, issued by ca/ca.crt"
echo "  attacker/rogue-cert/rogue.crt   -- CN/SAN=$RESOLVER_NAME, self-signed, untrusted by either client"
echo
echo "Now run: ./sign-zones.sh && docker compose up -d --build"
