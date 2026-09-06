# N6 — IP Spoof (offline checksum engine + gated live send)

Crafts IP packets with spoofed source addresses. The checksum engine computes
correct IPv4 header, TCP (pseudo-header) and UDP checksums; sending those
packets requires `--live` (root, raw sockets). `--show` prints the packet
bytes without sending. An offline `--harness` verifies all checksum paths
against four independent reference vectors.

## Overview

**Components:**
- `IPSpoofer.checksum` — standard RFC 1071 ones-complement.
- `IPSpoofer.transport_checksum` — pseudo-header + TCP/UDP header checksum.
- `IPSpoofer.craft_raw_packet` — builds a full IP frame (header + transport
  header with correct checksums) for TCP, UDP, or ICMP.
- `--harness` — offline self-check against known hex vectors; runs unprivileged.
- `--show` / `--dry-run` — build and print the packet hex, no socket created.
- `--live` — required for any actual send; pin to interface with `--iface`
  (`SO_BINDTODEVICE`).

## What Works

- IP header checksum (RFC 1071 reference vector: `0xB861`).
- TCP checksum with and without payload (`0x0FED`, `0xAF50`).
- UDP checksum (`0x638A`).
- Self-consistent crafted packets (re-derived checksums match in-packet fields).
- SYN flood and IPID prediction modes gated behind `--live`.

## Usage

```bash
# Offline harness (default — no privileges)
python3 ip_spoof.py --harness

# Build and display a TCP SYN packet (no send)
python3 ip_spoof.py --show --src 192.0.2.1 --dst 192.0.2.2 --protocol TCP

# Live send (root)
sudo python3 ip_spoof.py --live --src 192.0.2.1 --dst 192.0.2.2 \
    --protocol TCP --count 10 --iface eth0

# SYN flood test (root, bounded count)
sudo python3 ip_spoof.py --live --syn-flood --dst 192.0.2.2 --count 50

# Random IP (no privileges)
python3 ip_spoof.py --random-ip
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

> Authorized own-lab use only. Use documented placeholders (192.0.2.x, 198.51.100.x).

1. Run `--harness` and confirm all reference vectors pass.
2. Build a SYN packet with `--show`, paste the hex into Wireshark and confirm
   all fields (IP checksum, TCP checksum, payload) decode correctly.
3. On a lab target with TCP SYN cookies enabled, run
   `sudo python3 ip_spoof.py --live --src 192.0.2.1 --dst 192.0.2.2 --count 5`
   and confirm the target responds with SYN-ACK to the spoofed address.
4. Capture with `tcpdump -i <iface> -nn` during a bounded SYN flood
   (`--count 20`) and confirm spoofed source addresses appear.

## Metrics

Core offline checksum engine is deterministic and tested against four
hard-coded hex vectors:

- IP header checksum 0xB861: PASS
- TCP checksum (no payload) 0x0FED: PASS
- TCP checksum (with payload) 0xAF50: PASS
- UDP checksum 0x638A: PASS
- Crafted TCP/UDP packets self-consistent (re-derived checksums): PASS (5 tests)
- Header field correctness (sport, dport, doff, flags, length): PASS (2 tests)
- Random IP format: PASS (2 tests)
- `--harness` subprocess exit 0: PASS
- Gate (`--live` required for send): PASS
- `--show` prints hex: PASS
- Exit code: `0` on harness, `1` on gate refusal

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT