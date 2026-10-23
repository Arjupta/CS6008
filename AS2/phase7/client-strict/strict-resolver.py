#!/usr/bin/env python3
import socket

LISTEN = ("127.0.0.1", 53)
STUBBY = ("127.0.0.1", 5353)
STUBBY_TIMEOUT = 4.0

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    print(f"[strict-resolver] listening on {LISTEN}; DoT via stubby only ({STUBBY}) -- no cleartext fallback exists in this process", flush=True)
    while True:
        query, client_addr = srv.recvfrom(65535)
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.settimeout(STUBBY_TIMEOUT)
        try:
            up.sendto(query, STUBBY)
            answer, _ = up.recvfrom(65535)
            print("[strict-resolver] answered via DoT", flush=True)
            srv.sendto(answer, client_addr)
        except socket.timeout:
            print("[strict-resolver] DoT attempt failed/timed out -- no fallback, giving up on this query", flush=True)
        finally:
            up.close()

if __name__ == "__main__":
    main()
