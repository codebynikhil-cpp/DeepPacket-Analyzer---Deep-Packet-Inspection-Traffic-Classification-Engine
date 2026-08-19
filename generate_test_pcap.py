#!/usr/bin/env python3
"""
Generate an enriched test PCAP file for the DeepPacket Analyzer.
Includes: TLS/HTTPS (SNI), HTTP, DNS, UDP streams, QUIC, NTP, SYSLOG, streaming, VoIP (RTP), ICMP.
"""

import struct
import random

class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = 1700000000

    def write_global_header(self):
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)

    def write_packet(self, data, ts_delta=0):
        ts_sec  = self.timestamp + ts_delta
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)

    def close(self):
        self.file.close()


# ── Ethernet / IP / TCP / UDP Helpers ──────────────────────

def eth(src, dst, ethertype=0x0800):
    return bytes.fromhex(dst.replace(':', '')) + bytes.fromhex(src.replace(':', '')) + struct.pack('>H', ethertype)

def ip4(src, dst, proto, payload_len):
    total = 20 + payload_len
    hdr = struct.pack('>BBHHHBBH', 0x45, 0, total, random.randint(1, 65535), 0x4000, 64, proto, 0)
    hdr += bytes(int(x) for x in src.split('.'))
    hdr += bytes(int(x) for x in dst.split('.'))
    return hdr

def tcp(sport, dport, seq, ack, flags, payload_len=0):
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5<<4, flags, 65535, 0, 0)

def udp(sport, dport, payload_len):
    return struct.pack('>HHHH', sport, dport, 8 + payload_len, 0)

def icmp(type_, code=0, data=b'Hello DPI'):
    return struct.pack('>BBH', type_, code, 0) + data

# ── Payload Builders ───────────────────────────────────────

def tls_client_hello(sni):
    sni_b   = sni.encode()
    sni_ent = struct.pack('>BH', 0, len(sni_b)) + sni_b
    sni_lst = struct.pack('>H', len(sni_ent)) + sni_ent
    sni_ext = struct.pack('>HH', 0x0000, len(sni_lst)) + sni_lst
    sv_ext  = struct.pack('>HHBH', 0x002b, 3, 2, 0x0304)
    exts    = sni_ext + sv_ext
    ext_hdr = struct.pack('>H', len(exts)) + exts
    ch_body = struct.pack('>H', 0x0303) + bytes(random.randint(0,255) for _ in range(32)) \
              + struct.pack('B', 0) + struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302) \
              + struct.pack('BB', 1, 0) + ext_hdr
    hs      = struct.pack('B', 0x01) + struct.pack('>I', len(ch_body))[1:] + ch_body
    record  = struct.pack('B', 0x16) + struct.pack('>H', 0x0301) + struct.pack('>H', len(hs)) + hs
    return record

def http_req(host, path='/', method='GET'):
    return f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DPI-Test/2.0\r\nAccept: */*\r\n\r\n".encode()

def dns_query(domain):
    txid  = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)
    hdr   = txid + flags + struct.pack('>HHHH', 1, 0, 0, 0)
    q     = b''.join(struct.pack('B', len(l)) + l.encode() for l in domain.split('.')) + b'\x00'
    q    += struct.pack('>HH', 1, 1)
    return hdr + q

def dns_response(domain, ip):
    """Minimal DNS response with an A record answer."""
    txid  = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x8180)  # response, recursion available
    hdr   = txid + flags + struct.pack('>HHHH', 1, 1, 0, 0)
    q     = b''.join(struct.pack('B', len(l)) + l.encode() for l in domain.split('.')) + b'\x00'
    q    += struct.pack('>HH', 1, 1)
    # Answer: pointer to question, type A, class IN, TTL 300, rdlength 4, rdata
    ans   = struct.pack('>H', 0xC00C)  # pointer
    ans  += struct.pack('>HHIH', 1, 1, 300, 4)
    ans  += bytes(int(x) for x in ip.split('.'))
    return hdr + q + ans

def ntp_packet():
    # Minimal NTP client request
    li_vn_mode = (0 << 6) | (4 << 3) | 3  # LI=0, Version=4, Mode=3 (client)
    return struct.pack('B', li_vn_mode) + bytes(47)

def syslog_msg(msg):
    return f"<134>Apr 23 07:30:00 host1 kernel: {msg}\n".encode()

def rtp_packet(seq, timestamp, ssrc):
    """RTP header (RFC 3550) for VoIP simulation."""
    v_p_x_cc = (2 << 6)         # version=2, no padding/ext/csrc
    m_pt      = (0 << 7) | 0    # no marker, payload type 0 (PCMU)
    header    = struct.pack('>BBHII', v_p_x_cc, m_pt, seq, timestamp, ssrc)
    payload   = bytes(random.randint(0,255) for _ in range(160))  # 20ms G.711
    return header + payload

def quic_initial():
    """Minimal QUIC Initial packet header (RFC 9000-like)."""
    first_byte = 0xC3  # Long Header, Initial
    version    = struct.pack('>I', 1)  # QUIC v1
    dcid_len   = 8
    dcid       = bytes(random.randint(0,255) for _ in range(dcid_len))
    scid_len   = 8
    scid       = bytes(random.randint(0,255) for _ in range(scid_len))
    return struct.pack('B', first_byte) + version + struct.pack('BB', dcid_len, scid_len)[0:1] \
           + struct.pack('B', dcid_len) + dcid + struct.pack('B', scid_len) + scid + b'\x00' * 20


# ── Main ───────────────────────────────────────────────────

def main():
    w = PCAPWriter('test_dpi.pcap')

    USER_MAC = '00:11:22:33:44:55'
    GW_MAC   = 'aa:bb:cc:dd:ee:ff'
    USER_IP  = '192.168.1.100'

    seq = 1000
    pkt_count = 0

    # ── 1. TLS / HTTPS ─────────────────────────────────────
    tls_conns = [
        ('142.250.185.206', 'www.google.com'),
        ('142.250.185.110', 'www.youtube.com'),
        ('157.240.1.35',    'www.facebook.com'),
        ('157.240.1.174',   'www.instagram.com'),
        ('104.244.42.65',   'twitter.com'),
        ('52.94.236.248',   'www.amazon.com'),
        ('23.52.167.61',    'www.netflix.com'),
        ('140.82.114.4',    'github.com'),
        ('104.16.85.20',    'discord.com'),
        ('35.186.224.25',   'zoom.us'),
        ('35.186.227.140',  'web.telegram.org'),
        ('99.86.0.100',     'www.tiktok.com'),
        ('35.186.224.47',   'open.spotify.com'),
        ('192.0.78.24',     'www.cloudflare.com'),
        ('13.107.42.14',    'www.microsoft.com'),
        ('17.253.144.10',   'www.apple.com'),
        ('172.217.14.196',  'maps.google.com'),
        ('157.240.229.35',  'www.whatsapp.com'),
        ('13.225.103.50',   'www.twitch.tv'),
        ('13.107.42.14',    'teams.microsoft.com'),
        ('104.18.32.7',     'api.openai.com'),
        ('151.101.1.140',   'www.reddit.com'),
        ('18.205.100.1',    'store.steampowered.com'),
        ('13.107.42.16',    'linkedin.com'),
        ('151.101.65.140',  'medium.com'),
        ('54.230.1.10',     'notion.so'),
    ]

    for dst_ip, sni in tls_conns:
        sp = random.randint(49152, 65535)
        e = eth(USER_MAC, GW_MAC)
        # SYN
        t = tcp(sp, 443, seq, 0, 0x02); w.write_packet(e + ip4(USER_IP, dst_ip, 6, len(t)) + t); pkt_count+=1
        # SYN-ACK
        t = tcp(443, sp, seq+1000, seq+1, 0x12); w.write_packet(eth(GW_MAC, USER_MAC) + ip4(dst_ip, USER_IP, 6, len(t)) + t); pkt_count+=1
        # ACK
        t = tcp(sp, 443, seq+1, seq+1001, 0x10); w.write_packet(e + ip4(USER_IP, dst_ip, 6, len(t)) + t); pkt_count+=1
        # TLS Client Hello
        tls = tls_client_hello(sni)
        t = tcp(sp, 443, seq+1, seq+1001, 0x18); w.write_packet(e + ip4(USER_IP, dst_ip, 6, len(t)+len(tls)) + t + tls); pkt_count+=1
        seq += 10000

    # ── 2. HTTP (port 80) ───────────────────────────────────
    http_conns = [
        ('93.184.216.34',   'example.com',            '/',                'GET'),
        ('185.199.108.153', 'httpbin.org',             '/get',             'GET'),
        ('185.199.108.153', 'httpbin.org',             '/post',            'POST'),
        ('151.101.1.69',    'stackoverflow.com',      '/questions',       'GET'),
        ('104.20.5.46',     'developers.google.com',  '/apis',            'GET'),
        ('93.184.216.50',   'test-server.local',       '/api/v1/status',   'GET'),
        ('192.168.1.1',     'router.local',           '/login',           'POST'),
        ('10.0.0.5',        'internal-wiki.local',    '/index.php',       'GET'),
    ]

    for dst_ip, host, path, method in http_conns:
        sp = random.randint(49152, 65535)
        e = eth(USER_MAC, GW_MAC)
        t = tcp(sp, 80, seq, 0, 0x02); w.write_packet(e + ip4(USER_IP, dst_ip, 6, len(t)) + t); pkt_count+=1
        hd = http_req(host, path, method)
        t = tcp(sp, 80, seq+1, 1, 0x18); w.write_packet(e + ip4(USER_IP, dst_ip, 6, len(t)+len(hd)) + t + hd); pkt_count+=1
        seq += 10000

    # ── 3. DNS Queries + Responses (UDP port 53) ────────────
    DNS_DOMAINS = [
        ('www.google.com',        '142.250.185.206'),
        ('www.youtube.com',       '142.250.185.110'),
        ('www.facebook.com',      '157.240.1.35'),
        ('api.twitter.com',       '104.244.42.65'),
        ('www.netflix.com',       '23.52.167.61'),
        ('open.spotify.com',      '35.186.224.47'),
        ('discord.com',           '104.16.85.20'),
        ('zoom.us',               '35.186.224.25'),
        ('www.amazon.com',        '52.94.236.248'),
        ('www.reddit.com',        '151.101.1.140'),
        ('www.github.com',        '140.82.114.4'),
        ('www.tiktok.com',        '99.86.0.100'),
        ('cdnjs.cloudflare.com', '104.16.132.229'),
        ('fonts.googleapis.com',   '142.250.185.68'),
        ('api.openai.com',        '104.18.32.7'),
        ('cdn.discordapp.com',    '162.159.135.232'),
        ('raw.githubusercontent.com', '185.199.108.133'),
        ('s3.amazonaws.com',      '52.216.188.10'),
        ('edge.microsoft.com',    '13.107.42.16'),
        ('valortant.com',         '192.0.78.24'),
    ]

    for domain, answer_ip in DNS_DOMAINS:
        sp = random.randint(49152, 65535)
        e = eth(USER_MAC, GW_MAC)
        # Query
        dq = dns_query(domain)
        u  = udp(sp, 53, len(dq))
        w.write_packet(e + ip4(USER_IP, '8.8.8.8', 17, len(u)+len(dq)) + u + dq); pkt_count+=1
        # Response from DNS server
        dr = dns_response(domain, answer_ip)
        u  = udp(53, sp, len(dr))
        w.write_packet(eth(GW_MAC, USER_MAC) + ip4('8.8.8.8', USER_IP, 17, len(u)+len(dr)) + u + dr); pkt_count+=1

    # ── 4. NTP (UDP port 123) ───────────────────────────────
    NTP_SERVERS = ['216.239.35.0', '129.6.15.28', '132.163.97.1', '198.60.22.240']
    for ntp_ip in NTP_SERVERS:
        sp = random.randint(49152, 65535)
        e  = eth(USER_MAC, GW_MAC)
        np = ntp_packet()
        u  = udp(sp, 123, len(np))
        w.write_packet(e + ip4(USER_IP, ntp_ip, 17, len(u)+len(np)) + u + np); pkt_count+=1
        # NTP response (server  → client)
        u  = udp(123, sp, len(np))
        w.write_packet(eth(GW_MAC, USER_MAC) + ip4(ntp_ip, USER_IP, 17, len(u)+len(np)) + u + np); pkt_count+=1

    # ── 5. Syslog (UDP port 514) ────────────────────────────
    SYSLOG_MSGS = [
        'eth0: Link is up',
        'firewall: ACCEPT IN=eth0 SRC=192.168.1.100 DST=8.8.8.8 PROTO=UDP DPT=53',
        'firewall: DROP IN=eth0 SRC=192.168.1.50 DST=1.1.1.1 PROTO=TCP DPT=4444',
        'kernel: nf_conntrack: table full, dropping packet',
        'sshd: Accepted publickey for admin from 192.168.1.200',
        'auth: Failed password for root from 192.168.1.99 port 54312 ssh2',
    ]
    for msg in SYSLOG_MSGS:
        sp = random.randint(49152, 65535)
        e  = eth(USER_MAC, GW_MAC)
        sl = syslog_msg(msg)
        u  = udp(sp, 514, len(sl))
        w.write_packet(e + ip4(USER_IP, '10.0.0.1', 17, len(u)+len(sl)) + u + sl); pkt_count+=1

    # ── 6. VoIP / RTP (UDP) ─────────────────────────────────
    VOIP_DST = '10.10.10.5'
    ssrc = random.randint(0, 0xFFFFFFFF)
    for i in range(40):  # 40 RTP frames (~800ms of call)
        sp   = 16384
        dp   = 16386
        rtp  = rtp_packet(i, i*160, ssrc)
        u    = udp(sp, dp, len(rtp))
        e    = eth(USER_MAC, GW_MAC)
        w.write_packet(e + ip4(USER_IP, VOIP_DST, 17, len(u)+len(rtp)) + u + rtp); pkt_count+=1

    # ── 7. QUIC / UDP port 443 ───────────────────────────────
    QUIC_SERVERS = ['142.250.185.100', '104.16.0.1', '157.240.1.1', '142.250.185.110']
    for qip in QUIC_SERVERS:
        sp  = random.randint(49152, 65535)
        qp  = quic_initial()
        u   = udp(sp, 443, len(qp))
        e   = eth(USER_MAC, GW_MAC)
        w.write_packet(e + ip4(USER_IP, qip, 17, len(u)+len(qp)) + u + qp); pkt_count+=1

    # ── 8. ICMP Echo (ping) ──────────────────────────────────
    PING_TARGETS = ['8.8.8.8', '1.1.1.1', '142.250.185.206', '157.240.1.35', '9.9.9.9']
    for target in PING_TARGETS:
        for i in range(4):
            ic = icmp(8, 0, struct.pack('>HH', i, i) + b'DeepPacketDPI!')
            e  = eth(USER_MAC, GW_MAC)
            w.write_packet(e + ip4(USER_IP, target, 1, len(ic)) + ic); pkt_count+=1
            # Echo reply
            ic2 = icmp(0, 0, struct.pack('>HH', i, i) + b'DeepPacketDPI!')
            w.write_packet(eth(GW_MAC, USER_MAC) + ip4(target, USER_IP, 1, len(ic2)) + ic2); pkt_count+=1

    # ── 9. Suspicious Port Traffic (alerts) ─────────────────
    SUSPICIOUS = [
        ('192.168.1.50', 4444,  'TCP'), # Metasploit default
        ('192.168.1.51', 1337,  'TCP'), # Elite/leet port
        ('192.168.1.52', 31337, 'TCP'), # Back Orifice
        ('10.0.0.99',    4899,  'TCP'), # Radmin
        ('192.168.1.77', 6667,  'TCP'), # IRC Botnet C2
    ]
    for s_ip, s_port, proto in SUSPICIOUS:
        for _ in range(4):
            sp = random.randint(49152, 65535)
            e  = eth('00:de:ad:be:ef:01', GW_MAC)
            t  = tcp(sp, s_port, seq, 0, 0x02)
            w.write_packet(e + ip4(s_ip, USER_IP, 6, len(t)) + t); pkt_count+=1
            seq += 1000

    # ── 10. Simulated Port Scan (Attacker Reconnaissance) ────
    SCANNER_IP = '10.0.0.66'
    SCAN_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 5432, 8080]
    for scan_p in SCAN_PORTS:
        sp = random.randint(49152, 65535)
        e  = eth('00:aa:bb:cc:dd:ee', GW_MAC)
        t  = tcp(sp, scan_p, seq, 0, 0x02)  # SYN packet
        w.write_packet(e + ip4(SCANNER_IP, USER_IP, 6, len(t)) + t); pkt_count+=1

    # ── 11. High-volume UDP stream (streaming simulation) ───
    STREAM_DST = '1.2.3.4'
    for i in range(40):
        sp   = 10000 + (i % 5)
        data = bytes(random.randint(0,255) for _ in range(1316))  # MPEG-TS packet size
        u    = udp(sp, 5004, len(data))
        e    = eth(GW_MAC, USER_MAC)
        w.write_packet(e + ip4(STREAM_DST, USER_IP, 17, len(u)+len(data)) + u + data); pkt_count+=1

    w.close()

    print(f"[OK] Generated test_dpi.pcap")
    print(f"   Total packets : {pkt_count}")
    print(f"   TLS/HTTPS     : {len(tls_conns) * 4} packets ({len(tls_conns)} connections)")
    print(f"   HTTP          : {len(http_conns) * 2} packets ({len(http_conns)} requests)")
    print(f"   DNS           : {len(DNS_DOMAINS) * 2} packets ({len(DNS_DOMAINS)} queries + responses)")
    print(f"   NTP           : {len(NTP_SERVERS) * 2} packets")
    print(f"   Syslog        : {len(SYSLOG_MSGS)} packets")
    print(f"   VoIP/RTP      : 40 RTP frames")
    print(f"   QUIC (UDP443) : {len(QUIC_SERVERS)} packets")
    print(f"   ICMP/Ping     : {len(PING_TARGETS)*4*2} packets")
    print(f"   Suspicious    : {len(SUSPICIOUS)*4} packets")
    print(f"   Port Scan     : {len(SCAN_PORTS)} SYN scan packets from {SCANNER_IP}")
    print(f"   UDP Stream    : 40 packets")


if __name__ == '__main__':
    main()

