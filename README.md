# PulseScan C++

Async port and host scanner built with C++20 coroutines and Boost.Asio. Uses CLI11 for argument parsing and vcpkg for dependencies.

## Legal and ethical use

This tool is for authorized testing only. Do not scan systems or networks without explicit permission. Unauthorized use or exploitation is prohibited.

## Build

1) Bootstrap vcpkg (if needed) and set `VCPKG_ROOT`:
```bash
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
export VCPKG_ROOT="$PWD/vcpkg"
```

2) Configure and build with CMake (vcpkg manifests are enabled by default):
```bash
cmake -B build -S .
cmake --build build
```

## Run

Basic scan (replace with hosts you are authorized to test):
```bash
./build/pulsescan-cpp localhost -p 80,443,8000-8005 -t 1.5 --max-inflight 500
```

Multi-host scan:
```bash
./build/pulsescan-cpp localhost 127.0.0.1 ::1 -p 22,80
```

Ping mode (repeat and report changes):
```bash
./build/pulsescan-cpp localhost -p 80 --ping --interval 2
```

ICMP ping (requires root or CAP_NET_RAW):
```bash
sudo ./build/pulsescan-cpp 127.0.0.1 --icmp-ping -c 3
```

Modes:
- `-m connect` (default): TCP connect scan.
- `-m banner`: TCP connect plus a short banner read (`--banner-timeout`, `--banner-bytes`).
- `-m udp`: UDP probe that sends a protocol-specific payload when known (DNS, NTP, QUIC VN, SIP, IAX2), otherwise a minimal payload. No reply is reported as `open|filtered`.

Features:
- Multi-host scanning.
- `--ping` change detection.
- ICMP ping mode with CIDR/range expansion.
- IPv4/IPv6 filtering (`-4`/`-6`).
- Optional reverse DNS (`--reverse-dns`).
- Optional sandboxing (`--sandbox`) using Landlock (Linux) or Capsicum (FreeBSD).
- Press Enter (or SIGINFO on FreeBSD) to print progress while running.

## Notes / Next steps
- UDP scans are best-effort; no response is reported as `open|filtered`.
- ICMP ping requires root or `CAP_NET_RAW`.
- Consider JSON output and per-host/port rate caps for larger sweeps.
