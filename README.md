> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# N6 — IP Spoofing Toolkit

IP packet-crafting toolkit for network security testing: builds raw IPv4 frames with forged source addresses, computes RFC 1071 IP/TCP/UDP checksums, and — only behind an explicit `--live` gate — sends them over raw sockets for authorized lab use.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/n6-ip-spoof.svg)](https://github.com/5h4d0wn1k/n6-ip-spoof)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/n6-ip-spoof.svg)](https://github.com/5h4d0wn1k/n6-ip-spoof)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/n6-ip-spoof.svg)](https://github.com/5h4d0wn1k/n6-ip-spoof)

## Why

Offline-first packet crafting is the safest way to learn IP spoofing mechanics — checksum math, header layout, TCP/UDP pseudo-headers, and raw sockets — without touching real systems. Every path that *can* be verified offline *is*: the checksum engine is benchmarked against four fixed reference hex vectors, and actual network egress is locked behind `--live` plus root privileges so mistakes are hard. Use it only against networks you own or hold express written authorization to test.

## Features

- **RFC 1071 ones-complement checksum engine** for IPv4, TCP pseudo-header and UDP, verified against fixed vectors (`0xB861`, `0x0FED`, `0xAF50`, `0x638A`)
- **Raw IPv4 frame builder** — IP header plus TCP / UDP / ICMP transport header in one pass
- **`--harness` offline self-test** — 15 unittest assertions, runs unprivileged, exit `0`
- **`--show` / `--dry-run`** — builds and prints packet bytes without creating a socket
- **`--live` gated send** — raw sockets, `--iface` (`SO_BINDTODEVICE`) binding required
- **Bounded `--syn-flood` and `--ipid-predict` modes** for lab traffic analysis
- **`--random-ip` generation** — safe to run with no privileges

## Quickstart

```bash
git clone https://github.com/5h4d0wn1k/n6-ip-spoof.git && cd n6-ip-spoof

# Offline checksum self-test (no privileges)
python3 firmware/ip_spoof.py --harness

# Build and print a TCP SYN packet without sending
python3 firmware/ip_spoof.py --show --src 192.0.2.1 --dst 192.0.2.2 --protocol TCP

# Live send (root, authorized lab network only)
sudo python3 firmware/ip_spoof.py --live --src 192.0.2.1 --dst 192.0.2.2 \
    --protocol TCP --count 10 --iface eth0

# Random IP generator (unprivileged)
python3 firmware/ip_spoof.py --random-ip
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Project structure

- `firmware/ip_spoof.py` — packet-crafting engine and CLI
- `tests/` — 15 unit tests including checksum reference vectors
- `ETHICS.md` / `SCOPE.md` / `SECURITY.md` — authorized-use and reporting rules

## Documentation

- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — how to report a vulnerability
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute safely
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community standards

## Contributing

Contributions that strengthen the checksum engine, fixtures, or defensive lab guidance are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); all contributions must stay educational and abuse-resistant.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, without warranty, for education and authorized testing only.