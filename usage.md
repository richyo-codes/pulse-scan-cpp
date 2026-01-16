# Port Scanner Usage

## Legal and ethical use

Use this tool only on hosts and networks you own or have explicit permission to test. Unauthorized scanning or exploitation is prohibited.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Basic Scan

Scan a host with default ports and connect mode:

```bash
./build/pulsescan-cpp localhost
```

Scan specific ports:

```bash
./build/pulsescan-cpp localhost -p 22,80,443,8000-8010
```

Use banner mode:

```bash
./build/pulsescan-cpp localhost -m banner --banner-timeout 1.0 --banner-bytes 256
```

Use UDP mode:

```bash
./build/pulsescan-cpp localhost -m udp -t 1.5
```

Scan multiple hosts:

```bash
./build/pulsescan-cpp localhost 127.0.0.1 ::1 -p 22,80
```

## Ping Mode

Repeat scans on an interval and only report changes:

```bash
./build/pulsescan-cpp localhost --ping --interval 2
```

The first pass prints all results. Subsequent passes only print `CHANGE ...` lines.

## ICMP Ping

ICMP echo ping (requires root or CAP_NET_RAW):

```bash
sudo ./build/pulsescan-cpp 192.168.1.1 --icmp-ping
```

Ping a range or CIDR:

```bash
sudo ./build/pulsescan-cpp 192.168.1.50-70 --icmp-ping -c 3
sudo ./build/pulsescan-cpp 192.168.1.0/24 --icmp-ping -c 1
```

## Options

- `host`: target host(s) (IP or DNS)
- `-p, --ports`: comma list and ranges (example: `22,80,8000-8010`)
- `-t, --timeout`: per-connection timeout in seconds
- `--max-inflight`: max concurrent attempts
- `-m, --mode`: `connect`, `banner`, or `udp`
- `--banner-timeout`: banner wait timeout in seconds
- `--banner-bytes`: max banner bytes
- `--ping`: enable ping mode
- `--interval`: ping interval in seconds
- `--open`: only print open ports
- `--debug-dns`: log DNS resolution results
- `-v, --verbose`: verbose tracing
- `-4`: IPv4 only
- `-6`: IPv6 only
- `--icmp-ping`: ICMP echo ping mode
- `-c, --icmp-count`: ICMP echo count per host
- `--sandbox`: enable OS sandboxing (Landlock/Capsicum)
