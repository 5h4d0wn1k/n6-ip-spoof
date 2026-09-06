import os, sys, struct, subprocess, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))
from ip_spoof import IPSpoofer, run_harness


class TestChecksumEngine(unittest.TestCase):
    s = IPSpoofer()

    def test_ip_header_checksum_classic_vector(self):
        hdr = bytes.fromhex(
            '450000730000400040110000c0a80001c0a800c7')
        self.assertEqual(self.s.checksum(hdr), 0xB861)

    def test_tcp_checksum_no_payload_vector(self):
        tcp = bytes.fromhex(
            '04d2' '0050' '00000000' '00000000'
            '5002' '16d0' '0000' '0000')
        ck = self.s.transport_checksum('192.0.2.1', '192.0.2.2', 6, tcp)
        self.assertEqual(ck, 0x0FED)

    def test_tcp_checksum_with_payload_vector(self):
        tcp = bytes.fromhex(
            'c000' '01bb' '00000001' '00000000'
            '5002' '2000' '0000' '0000')
        ck = self.s.transport_checksum('198.51.100.1', '198.51.100.2', 6,
                                       tcp, b'GET /')
        self.assertEqual(ck, 0xAF50)

    def test_udp_checksum_vector(self):
        udp = bytes.fromhex('0035' '3039' '000c' '0000')
        ck = self.s.transport_checksum('192.0.2.1', '192.0.2.2', 17,
                                       udp, b'test')
        self.assertEqual(ck, 0x638A)


class TestCraftedPacketConsistency(unittest.TestCase):
    s = IPSpoofer()

    def _verify_tcp_packet(self, src, dst, sport, dport, flags, payload):
        pkt = self.s.craft_raw_packet(src, dst, sport, dport,
                                      protocol='TCP', flags=flags,
                                      payload=payload)
        ip = struct.unpack('!BBHHHBBH4s4s', pkt[:20])
        stored_ip_ck = ip[7]
        zeroed = pkt[:10] + b'\x00\x00' + pkt[12:20]
        self.assertEqual(self.s.checksum(zeroed), stored_ip_ck)
        tcp_hdr = pkt[20:40]
        stored_tcp_ck = struct.unpack('!H', tcp_hdr[16:18])[0]
        zeroed_tcp = tcp_hdr[:16] + b'\x00\x00' + tcp_hdr[18:]
        self.assertEqual(
            self.s.transport_checksum(src, dst, 6, zeroed_tcp, payload),
            stored_tcp_ck)
        self.assertEqual(ip[2], len(pkt))

    def test_tcp_syn_packet_self_consistent(self):
        self._verify_tcp_packet('192.0.2.1', '192.0.2.2', 49152, 80,
                                ['SYN'], b'')

    def test_tcp_syn_ack_with_payload_self_consistent(self):
        self._verify_tcp_packet('198.51.100.1', '198.51.100.2',
                                1234, 443, ['SYN', 'ACK'], b'GET /')

    def test_udp_packet_self_consistent(self):
        pkt = self.s.craft_raw_packet('192.0.2.1', '192.0.2.2',
                                      53, 12345, protocol='UDP',
                                      payload=b'test')
        ip = struct.unpack('!BBHHHBBH4s4s', pkt[:20])
        stored_ip_ck = ip[7]
        zeroed = pkt[:10] + b'\x00\x00' + pkt[12:20]
        self.assertEqual(self.s.checksum(zeroed), stored_ip_ck)
        udp_hdr = pkt[20:28]
        stored_udp_ck = struct.unpack('!H', udp_hdr[6:8])[0]
        zeroed_udp = udp_hdr[:6] + b'\x00\x00'
        self.assertEqual(
            self.s.transport_checksum('192.0.2.1', '192.0.2.2', 17,
                                      zeroed_udp, b'test'),
            stored_udp_ck)
        self.assertEqual(ip[2], len(pkt))


class TestCraftedPacketFields(unittest.TestCase):
    s = IPSpoofer()

    def test_tcp_syn_header_fields(self):
        pkt = self.s.craft_raw_packet('192.0.2.1', '192.0.2.2',
                                      49152, 80, protocol='TCP',
                                      flags=['SYN'])
        sport, dport, seq, ack, doff_res, flags, win, ck, urg = \
            struct.unpack('!HHIIBBHHH', pkt[20:40])
        self.assertEqual(sport, 49152)
        self.assertEqual(dport, 80)
        self.assertEqual(doff_res >> 4, 5)
        self.assertEqual(flags, 0x02)
        self.assertEqual(urg, 0)

    def test_udp_header_fields(self):
        pkt = self.s.craft_raw_packet('192.0.2.1', '192.0.2.2',
                                      53, 12345, protocol='UDP',
                                      payload=b'test')
        sport, dport, length, ck = struct.unpack('!HHHH', pkt[20:28])
        self.assertEqual(sport, 53)
        self.assertEqual(dport, 12345)
        self.assertEqual(length, 12)


class TestRandomIP(unittest.TestCase):
    s = IPSpoofer()

    def test_random_ip_is_valid(self):
        ip = self.s.generate_random_ip()
        parts = ip.split('.')
        self.assertEqual(len(parts), 4)
        self.assertTrue(all(0 <= int(p) <= 255 for p in parts))

    def test_random_ip_not_reserved(self):
        ip = self.s.generate_random_ip()
        self.assertFalse(ip.startswith('0.'))
        self.assertFalse(ip.startswith('127.'))
        self.assertFalse(ip.startswith('10.'))
        self.assertFalse(ip.startswith('192.168.'))


class TestHarness(unittest.TestCase):
    def test_harness_exit_code_zero(self):
        r = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), '..', 'firmware',
                          'ip_spoof.py'), '--harness'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0)
        self.assertIn('[RESULT] PASS', r.stdout)

    def test_harness_output_contains_all_checks(self):
        r = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), '..', 'firmware',
                          'ip_spoof.py'), '--harness'],
            capture_output=True, text=True, timeout=10)
        self.assertIn('IP header checksum', r.stdout)
        self.assertIn('TCP checksum (no payload)', r.stdout)
        self.assertIn('TCP checksum (with payload)', r.stdout)
        self.assertIn('UDP checksum', r.stdout)
        self.assertIn('crafted IP header', r.stdout)
        self.assertIn('crafted TCP checksum', r.stdout)


class TestGatekeeping(unittest.TestCase):
    def test_no_send_without_live(self):
        r = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), '..', 'firmware',
                          'ip_spoof.py'),
             '--src', '192.0.2.1', '--dst', '192.0.2.2'],
            capture_output=True, text=True, timeout=5)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('--live', r.stdout.lower() + r.stderr.lower())

    def test_show_dry_run_prints_hex(self):
        r = subprocess.run(
            [sys.executable,
             os.path.join(os.path.dirname(__file__), '..', 'firmware',
                          'ip_spoof.py'),
             '--show', '--src', '192.0.2.1', '--dst', '192.0.2.2'],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(r.returncode, 0)
        self.assertIn('Hex:', r.stdout)
        self.assertIn('dry-run', r.stdout)


if __name__ == '__main__':
    unittest.main()
