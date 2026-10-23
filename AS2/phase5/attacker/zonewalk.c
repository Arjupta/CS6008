/*
 * Phase 5 zone walker.
 *
 * Unlike Phases 2/4/6/7's interceptors, this tool is not on-path and does
 * not intercept or forge anything: it is an ordinary (if hand-crafted)
 * DNS client that sends real queries straight to domain-ns and reads real
 * replies. Zone walking needs no privileged network position at all --
 * that's the point. It still satisfies the assignment's C/C++-with-libpcap
 * requirement for every attack tool in this lab: the query packet is
 * built and sent by hand over a raw IP_HDRINCL socket (same technique
 * Phase 2/3/4's interceptor.c uses for its own sends), and every reply is
 * read with libpcap rather than a convenience socket API.
 *
 * The technique: every existing owner name in an NSEC-signed zone has its
 * own NSEC record, and that record's first RDATA field is the *next*
 * owner name in canonical (sorted) order -- in plaintext, uncompressed
 * (RFC 4034 requires this). So querying an existing name's own NSEC
 * RRset directly (QTYPE=NSEC) hands you the very next name in the zone,
 * whether or not that name is linked or advertised anywhere. Starting
 * from the zone apex and repeatedly querying "whatever name the last
 * answer just gave us" walks the entire zone in canonical order and
 * closes back on itself at the apex -- one query per owner name, with no
 * guessing, no AXFR, and no wordlist.
 *
 * Against an NSEC3-signed zone, the exact same procedure fails outright:
 * NSEC3 records are owned by a *hash* of each name, not the name itself,
 * so "QTYPE=NSEC at <a name I know>" simply returns NODATA -- there's no
 * NSEC RRset at that literal owner to find. That failure mode is the
 * fix's evidence (see the README's Run B / "fixed zone" section);
 * confirming the fixed zone still produces a valid *authenticated denial*
 * for a genuinely nonexistent name is done separately with plain dig
 * (the NSEC3 proof rides on ordinary NXDOMAIN responses, which this
 * walker doesn't need to touch).
 *
 * Build: g++ -O2 -Wall -o zonewalk zonewalk.c -lpcap
 *   (plain C, compiles fine as C++ too; g++ avoids depending on which of
 *   gcc/g++ happens to be the image's default cc)
 * Run:   ./zonewalk <iface> <domain_ns_ip> <start_qname> [<max_steps>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>

#define ETHERTYPE_IP 0x0800
#define DNS_TYPE_NSEC 47
#define LOCAL_SRC_PORT 45353
#define DEFAULT_MAX_STEPS 50

#pragma pack(push, 1)
struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
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

static int raw_sock = -1;
static struct sockaddr_in dst_addr;
static pcap_t *handle = NULL;

/* ---- helpers, same conventions as interceptor.c ------------------------ */

static uint16_t checksum16(const void *data, size_t len, uint32_t sum) {
    const uint16_t *p = (const uint16_t *)data;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* Encode a dotted name ("example.com" or "example.com.") into DNS wire
 * label format at buf+off. Returns offset just past the terminating zero
 * label, or -1 if it doesn't fit. */
static int encode_name(const char *name, uint8_t *buf, int off, int bufsz) {
    char tmp[256];
    strncpy(tmp, name, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    size_t l = strlen(tmp);
    if (l > 0 && tmp[l - 1] == '.') tmp[l - 1] = '\0'; /* strip trailing dot, we add labels explicitly */

    char *label = strtok(tmp, ".");
    while (label) {
        size_t ll = strlen(label);
        if (ll == 0 || ll > 63 || off + 1 + (int)ll >= bufsz) return -1;
        buf[off++] = (uint8_t)ll;
        memcpy(buf + off, label, ll);
        off += (int)ll;
        label = strtok(NULL, ".");
    }
    if (off + 1 >= bufsz) return -1;
    buf[off++] = 0; /* root label */
    return off;
}

/* Decode a (possibly compressed) name starting at buf+off into dotted
 * text. Shared logic with interceptor.c's parse_name. NSEC's "next domain
 * name" field is required to be uncompressed (RFC 4034 canonical form),
 * but this still safely handles a compressed owner name earlier in the
 * same answer record. */
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
        if (o + len + 1 < outsz) { memcpy(out + o, buf + off, len); o += len; out[o++] = '.'; }
        off += len;
    }
    if (o < outsz) out[o] = '\0'; else out[outsz - 1] = '\0';
    return jumped ? start : off;
}

static void normalize(char *s) {
    for (char *p = s; *p; p++) *p = (char)tolower((unsigned char)*p);
}

/* ---- sending ------------------------------------------------------------ */

static uint16_t send_nsec_query(const char *qname, uint32_t src_ip_net) {
    static uint16_t next_id = 0x1234;
    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));

    struct ip_hdr *ip = (struct ip_hdr *)pkt;
    int ip_off = sizeof(struct ip_hdr);
    struct udp_hdr *udp = (struct udp_hdr *)(pkt + ip_off);
    int udp_off = ip_off + sizeof(struct udp_hdr);
    int dns_off = udp_off + sizeof(struct udp_hdr) - sizeof(struct udp_hdr); /* = udp_off, kept explicit for clarity */
    (void)dns_off;
    int d_off = udp_off; /* dns header starts right after the udp header */
    struct dns_hdr *dns = (struct dns_hdr *)(pkt + d_off);

    uint16_t qid = next_id++;
    dns->id = htons(qid);
    dns->flags = htons(0x0000); /* standard query, RD=0: domain-ns is authoritative, no recursion needed */
    dns->qdcount = htons(1);
    dns->ancount = 0; dns->nscount = 0; dns->arcount = 0;

    int off = d_off + sizeof(struct dns_hdr);
    off = encode_name(qname, pkt, off, sizeof(pkt));
    if (off < 0) { fprintf(stderr, "name too long: %s\n", qname); exit(1); }
    uint16_t qtype = htons(DNS_TYPE_NSEC);
    memcpy(pkt + off, &qtype, 2); off += 2;
    uint16_t qclass = htons(1);
    memcpy(pkt + off, &qclass, 2); off += 2;

    int dns_len = off - d_off;
    int udp_len = sizeof(struct udp_hdr) + dns_len;
    udp->sport = htons(LOCAL_SRC_PORT);
    udp->dport = htons(53);
    udp->len = htons((uint16_t)udp_len);
    udp->checksum = 0; /* 0 is valid for UDP/IPv4: "no checksum computed" */

    int ip_total = ip_off + udp_len;
    ip->ver_ihl = 0x45;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)ip_total);
    ip->id = htons(qid);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = 17;
    ip->checksum = 0;
    ip->src_ip = src_ip_net;
    ip->dst_ip = dst_addr.sin_addr.s_addr;
    ip->checksum = checksum16(ip, sizeof(struct ip_hdr), 0);

    ssize_t sent = sendto(raw_sock, pkt, ip_total, 0,
                           (struct sockaddr *)&dst_addr, sizeof(dst_addr));
    if (sent < 0) { perror("sendto"); exit(1); }
    return qid;
}

/* ---- receiving (libpcap) ------------------------------------------------- */

/* Blocks (up to a short per-call pcap timeout, retried) until a UDP/53
 * reply from domain_ns to our fixed local port arrives with the expected
 * transaction id, then reports ancount and, if >=1, decodes the first
 * answer's "next domain name" into next_name. Returns 1 on a usable NSEC
 * answer, 0 on NODATA/NXDOMAIN (nothing more to walk from here), -1 on
 * timeout (no reply at all within the retry budget). */
static int wait_for_nsec_reply(uint16_t expect_id, char *next_name, int next_name_sz) {
    for (int attempt = 0; attempt < 30; attempt++) { /* ~3s total at 100ms pcap timeout */
        struct pcap_pkthdr *hdr;
        const u_char *bytes;
        int rc = pcap_next_ex(handle, &hdr, &bytes);
        if (rc == 0) continue; /* pcap_open_live timeout, keep waiting */
        if (rc < 0) { fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle)); return -1; }

        if (hdr->caplen < sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr) + sizeof(struct dns_hdr))
            continue;
        const struct eth_hdr *eth = (const struct eth_hdr *)bytes;
        if (ntohs(eth->ethertype) != ETHERTYPE_IP) continue;
        int ip_off = sizeof(struct eth_hdr);
        const struct ip_hdr *ip = (const struct ip_hdr *)(bytes + ip_off);
        if (ip->protocol != 17) continue;
        int ihl = (ip->ver_ihl & 0x0F) * 4;
        int udp_off = ip_off + ihl;
        const struct udp_hdr *udp = (const struct udp_hdr *)(bytes + udp_off);
        if (ntohs(udp->dport) != LOCAL_SRC_PORT) continue;

        int dns_off = udp_off + sizeof(struct udp_hdr);
        int caplen = (int)hdr->caplen;
        if (caplen < dns_off + (int)sizeof(struct dns_hdr)) continue;
        const struct dns_hdr *dns = (const struct dns_hdr *)(bytes + dns_off);
        if (ntohs(dns->id) != expect_id) continue;

        uint16_t ancount = ntohs(dns->ancount);
        uint16_t qdcount = ntohs(dns->qdcount);
        if (ancount == 0) return 0; /* NODATA/NXDOMAIN -- no NSEC RRset here */

        /* skip the question section to reach the first answer record */
        int off = dns_off + sizeof(struct dns_hdr);
        char scratch[256];
        for (int q = 0; q < qdcount; q++) {
            off = parse_name(bytes, caplen, off, scratch, sizeof(scratch));
            off += 4; /* qtype + qclass */
        }
        /* owner name of the answer record (should echo the query name) */
        off = parse_name(bytes, caplen, off, scratch, sizeof(scratch));
        if (off + 10 > caplen) return -1;
        uint16_t atype, rdlength;
        memcpy(&atype, bytes + off, 2); atype = ntohs(atype);
        memcpy(&rdlength, bytes + off + 8, 2); rdlength = ntohs(rdlength);
        int rdata_off = off + 10;
        (void)rdlength;
        if (atype != DNS_TYPE_NSEC) return 0; /* not actually an NSEC RRset (e.g. CNAME) -- stop */

        /* RDATA's first field: Next Domain Name, uncompressed */
        parse_name(bytes, caplen, rdata_off, next_name, next_name_sz);
        return 1;
    }
    return -1; /* timed out */
}

int main(int argc, char **argv) {
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "usage: %s <iface> <domain_ns_ip> <start_qname> [<max_steps>]\n", argv[0]);
        return 1;
    }
    const char *iface = argv[1];
    const char *domain_ns_ip = argv[2];
    char start_qname[256];
    strncpy(start_qname, argv[3], sizeof(start_qname) - 1);
    start_qname[sizeof(start_qname) - 1] = '\0';
    int max_steps = (argc == 5) ? atoi(argv[4]) : DEFAULT_MAX_STEPS;

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, domain_ns_ip, &dst_addr.sin_addr) != 1) {
        fprintf(stderr, "bad domain_ns_ip\n"); return 1;
    }

    /* Source IP for the raw packets we craft: read back from a UDP
     * connect() to domain_ns_ip, the normal way to ask the kernel "what
     * source address would you use for this destination" without parsing
     * `ip addr` output ourselves. */
    uint32_t src_ip_net;
    {
        int probe = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in tmp = dst_addr;
        tmp.sin_port = htons(53);
        if (connect(probe, (struct sockaddr *)&tmp, sizeof(tmp)) < 0) { perror("connect(probe)"); return 1; }
        struct sockaddr_in local; socklen_t ln = sizeof(local);
        if (getsockname(probe, (struct sockaddr *)&local, &ln) < 0) { perror("getsockname"); return 1; }
        src_ip_net = local.sin_addr.s_addr;
        close(probe);
    }

    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) { perror("socket(SOCK_RAW, IPPROTO_RAW)"); return 1; }
    int on = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt IP_HDRINCL"); return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(iface, 65536, 0 /*not promisc -- we only need our own unicast replies*/, 100, errbuf);
    if (!handle) { fprintf(stderr, "pcap_open_live: %s\n", errbuf); return 1; }
    char filter_exp[128];
    snprintf(filter_exp, sizeof(filter_exp), "udp and src host %s and dst port %d",
             domain_ns_ip, LOCAL_SRC_PORT);
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "bpf filter error: %s\n", pcap_geterr(handle)); return 1;
    }

    fprintf(stderr, "zonewalk: iface=%s domain-ns=%s start=%s max_steps=%d\n",
            iface, domain_ns_ip, start_qname, max_steps);

    char current[256];
    strncpy(current, start_qname, sizeof(current) - 1);
    current[sizeof(current) - 1] = '\0';
    normalize(current);
    if (current[strlen(current) - 1] != '.') strncat(current, ".", sizeof(current) - strlen(current) - 1);

    char first[256];
    strncpy(first, current, sizeof(first));

    int recovered = 0;
    printf("RECOVERED NAMES:\n");

    for (int step = 0; step < max_steps; step++) {
        uint16_t qid = send_nsec_query(current, src_ip_net);
        char next_name[256];
        int rc = wait_for_nsec_reply(qid, next_name, sizeof(next_name));
        if (rc < 0) {
            printf("  [query %d] %-32s -> TIMEOUT (no NSEC reply; walk cannot continue)\n", step + 1, current);
            break;
        }
        if (rc == 0) {
            printf("  [query %d] %-32s -> NODATA (no NSEC RRset at this name; walk stops here)\n", step + 1, current);
            break;
        }
        normalize(next_name);
        printf("  [query %d] %-32s -> next: %s\n", step + 1, current, next_name);
        recovered++;

        if (strcmp(next_name, first) == 0) {
            printf("  ring closed back at %s -- zone fully walked.\n", first);
            break;
        }
        strncpy(current, next_name, sizeof(current) - 1);
        current[sizeof(current) - 1] = '\0';
    }

    printf("\nTotal owner names visited (ring steps): %d\n", recovered);

    pcap_close(handle);
    close(raw_sock);
    return 0;
}
