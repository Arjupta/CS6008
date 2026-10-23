import struct, sys

def parse_dns_name(data, offset, full):
    labels = []
    jumped = False
    orig_offset = offset
    loop_guard = 0
    while True:
        loop_guard += 1
        if loop_guard > 100: break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            # pointer
            ptr = ((length & 0x3F) << 8) | data[offset+1]
            if not jumped:
                orig_offset = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        labels.append(full[offset:offset+length].decode('ascii', 'replace'))
        offset += length
    end_offset = orig_offset if jumped else offset
    return '.'.join(labels) + '.', end_offset

def parse_dns(payload):
    if len(payload) < 12:
        return None
    tid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', payload[:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF
    offset = 12
    questions = []
    for _ in range(qd):
        name, offset = parse_dns_name(payload, offset, payload)
        if offset+4 > len(payload): break
        qtype, qclass = struct.unpack('!HH', payload[offset:offset+4])
        offset += 4
        questions.append((name, qtype))

    def parse_rrs(count, offset):
        rrs = []
        for _ in range(count):
            if offset >= len(payload): break
            name, offset = parse_dns_name(payload, offset, payload)
            if offset+10 > len(payload): break
            rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', payload[offset:offset+10])
            offset += 10
            rdata = payload[offset:offset+rdlen]
            rdtext = ''
            if rtype == 1 and len(rdata) == 4:  # A
                rdtext = '.'.join(str(b) for b in rdata)
            elif rtype == 2:  # NS
                rdtext, _ = parse_dns_name(payload, offset, payload)
            elif rtype == 6:  # SOA
                rdtext = '(SOA)'
            offset += rdlen
            rrs.append((name, rtype, rdtext))
        return rrs, offset

    answers, offset = parse_rrs(an, offset)
    authority, offset = parse_rrs(ns, offset)
    additional, offset = parse_rrs(ar, offset)

    return {
        'id': tid, 'qr': qr, 'aa': aa, 'rd': rd, 'ra': ra, 'rcode': rcode,
        'questions': questions, 'answers': answers, 'authority': authority,
        'additional': additional
    }

TYPE_NAMES = {1:'A', 2:'NS', 6:'SOA', 28:'AAAA', 41:'OPT'}

def main(path):
    with open(path, 'rb') as f:
        data = f.read()

    magic = struct.unpack('<I', data[0:4])[0]
    if magic != 0xa1b2c3d4:
        print("Unexpected magic:", hex(magic))
        return
    linktype = struct.unpack('<I', data[20:24])[0]
    print("Linktype:", linktype, "(113 = Linux cooked / SLL)")
    offset = 24
    pkt_num = 0
    while offset < len(data):
        if offset + 16 > len(data): break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', data[offset:offset+16])
        offset += 16
        pkt = data[offset:offset+incl_len]
        offset += incl_len
        pkt_num += 1

        if linktype == 113:
            # SLL v1 header is 16 bytes, protocol type at bytes 14:16
            if len(pkt) < 16: continue
            eth_proto = struct.unpack('!H', pkt[14:16])[0]
            ip_start = 16
        elif linktype == 276:
            # SLL v2 header is 20 bytes, protocol type at bytes 0:2
            if len(pkt) < 20: continue
            eth_proto = struct.unpack('!H', pkt[0:2])[0]
            ip_start = 20
        elif linktype == 1:
            # Ethernet, 14 byte header
            eth_proto = struct.unpack('!H', pkt[12:14])[0]
            ip_start = 14
        else:
            print("Unhandled linktype", linktype)
            return

        if eth_proto != 0x0800:
            continue  # not IPv4

        ip_hdr = pkt[ip_start:]
        if len(ip_hdr) < 20: continue
        ver_ihl = ip_hdr[0]
        ihl = (ver_ihl & 0x0F) * 4
        proto = ip_hdr[9]
        src_ip = '.'.join(str(b) for b in ip_hdr[12:16])
        dst_ip = '.'.join(str(b) for b in ip_hdr[16:20])

        if proto != 17:  # UDP
            continue

        udp_hdr = ip_hdr[ihl:ihl+8]
        if len(udp_hdr) < 8: continue
        sport, dport, ulen, ucsum = struct.unpack('!HHHH', udp_hdr)
        payload = ip_hdr[ihl+8: ihl+ulen]

        dns = parse_dns(payload)
        print(f"\n=== Packet {pkt_num}  t={ts_sec}.{ts_usec:06d}  {src_ip}:{sport} -> {dst_ip}:{dport} ===")
        if dns is None:
            print("  (not parseable as DNS)")
            continue
        kind = "RESPONSE" if dns['qr'] else "QUERY"
        flags = []
        if dns['aa']: flags.append('aa')
        if dns['rd']: flags.append('rd')
        if dns['ra']: flags.append('ra')
        print(f"  {kind}  id={dns['id']}  flags={','.join(flags) if flags else '(none)'}  rcode={dns['rcode']}")
        for name, qtype in dns['questions']:
            print(f"  Q: {name} {TYPE_NAMES.get(qtype, qtype)}")
        for section_name, section in [('ANSWER', dns['answers']), ('AUTHORITY', dns['authority']), ('ADDITIONAL', dns['additional'])]:
            for name, rtype, rdtext in section:
                tname = TYPE_NAMES.get(rtype, rtype)
                if tname == 'OPT':
                    continue
                print(f"  {section_name}: {name} {tname} {rdtext}")

if __name__ == '__main__':
    main(sys.argv[1])

