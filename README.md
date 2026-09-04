# N6 — IP Spoofing Tool

Craft packets with spoofed source IP addresses, SYN flood simulation, and IPID prediction.

## Overview

This project implements an IP spoofing research tool that:
- Crafts raw IP/TCP/UDP/ICMP packets with spoofed source addresses
- Simulates SYN flood attacks for testing SYN cookie defenses
- Predicts IPID sequences to assess host predictability
- Generates random source IPs for obfuscation testing
- Provides interactive and CLI modes

## Features

- **Packet crafting**: Build raw IP packets with arbitrary headers
- **SYN flood simulation**: Test SYN flood defenses in controlled environments
- **IPID prediction**: Analyze IP identification sequence predictability
- **Protocol support**: TCP, UDP, and ICMP packet generation
- **Random IP generation**: Create random source addresses by class

## Installation

No external dependencies — uses only the Python standard library.

```bash
# No pip install needed
```

## Usage

```bash
# Interactive mode
sudo python3 ip_spoof.py --interactive

# Send spoofed SYN packet
sudo python3 ip_spoof.py --src 10.0.0.1 --dst 192.168.1.1 --dport 80

# SYN flood simulation (requires root)
sudo python3 ip_spoof.py --syn-flood --dst 192.168.1.1 --count 100

# IPID prediction
sudo python3 ip_spoof.py --ipid-predict --target 192.168.1.1

# Generate random IP
python3 ip_spoof.py --random-ip
```

## Example Output

```
╔═══════════════════════════════════════╗
║     N6 — IP Spoofing Tool            ║
║  Craft packets with spoofed IPs      ║
╚═══════════════════════════════════════╝

--- Menu ---
1. Send spoofed packet
2. SYN flood simulation
3. IPID prediction
4. Generate random IP
5. Craft raw packet (inspect)
6. Stats
0. Exit

> 5
Source IP: 10.0.0.99
Dest IP: 192.168.1.1
Protocol (TCP/UDP/ICMP) [TCP]:
  Packet (54 bytes):
  Hex: 45000036...
```

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
