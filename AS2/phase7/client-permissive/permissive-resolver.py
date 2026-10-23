#!/usr/bin/env python3
"""
Phase 7 -- the "permissive" client's actual resolver-facing listener.

Ordinary applications (curl, plain `dig`) only know how to speak plain
DNS to whatever /etc/resolv.conf points at -- they can't do DoT
themselves. This tiny proxy IS that nameserver for the permissive
client: every query from /etc/resolv.conf's "nameserver 127.0.0.1"
lands here first.

Policy (this is the entire point of the "permissive" client, per 7.3):
try the encrypted leg first -- stubby, DoT-only, listening on
127.0.0.1:5353. Only if that attempt produces no usable answer within
STUBBY_TIMEOUT seconds do we fall back to asking the resolver's plain
port 53 directly, in cleartext, over the exact same resolver->client leg
Phase 6 attacked -- including whatever a Phase-6-style on-path attacker
hands back on that leg. A client configured this way is choosing
convenience over assurance; 7.3/7.4 are about measuring what that choice
costs, and this script's stdout log (redirected to a file by
entrypoint.sh) is the evidence of which path actually answered each
query.
"""
import socket

LISTEN = ("127.0.0.1", 53)
STUBBY = ("127.0.0.1", 5353)
RESOLVER_PLAIN = ("172.16.2.10", 53)
STUBBY_TIMEOUT = 2.5
PLAIN_TIMEOUT = 3.0


def ask(upstream, query, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, upstream)
        data, _ = s.recvfrom(65535)
        return data
    except socket.timeout:
        return None
    finally:
        s.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    print(f"[permissive-resolver] listening on {LISTEN}; "
          f"DoT via stubby first ({STUBBY}), "
          f"cleartext fallback PERMITTED ({RESOLVER_PLAIN})", flush=True)
    while True:
        query, client_addr = srv.recvfrom(65535)
        answer = ask(STUBBY, query, STUBBY_TIMEOUT)
        path = "DoT"
        if answer is None:
            print("[permissive-resolver] DoT attempt failed/timed out -- "
                  "FALLING BACK TO CLEARTEXT", flush=True)
            answer = ask(RESOLVER_PLAIN, query, PLAIN_TIMEOUT)
            path = "cleartext-fallback"
        if answer is not None:
            print(f"[permissive-resolver] answered via {path}", flush=True)
            srv.sendto(answer, client_addr)
        else:
            print("[permissive-resolver] no answer from either path -- "
                  "giving up on this query", flush=True)


if __name__ == "__main__":
    main()
