# Port Scanner Usage

## Legal and ethical use

Use this tool only on hosts and networks you own or have explicit permission to test. Unauthorized scanning or exploitation is prohibited.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Basic Scan

Scan a host with default ports and connect mode (dev/service ports):

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

JSON output (one JSON object per line):

```bash
./build/pulsescan-cpp localhost --output json
```

Default output (text) uses a report-style summary for one-shot scans.

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
- `--top-ports`: scan top N common ports from the built-in list (example: `--top-ports 20`)
- `-t, --timeout`: per-connection timeout in seconds
- `--max-inflight`: max concurrent attempts
- `-m, --mode`: `connect`, `banner`, or `udp`
- `--output`: output format (`text` or `json`)
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
- `--reverse-dns`: resolve PTR records for target IPs
- `--sandbox`: enable OS sandboxing (Landlock/Capsicum, default on)
- `--no-sandbox`: disable OS sandboxing

## Bash Completion

Install completion (after `cmake --install`):

```bash
sudo cp scripts/completions/pulsescan-cpp.bash /usr/share/bash-completion/completions/pulsescan-cpp
```

Enable in your shell:

```bash
source /usr/share/bash-completion/completions/pulsescan-cpp
```

## Default Ports

When `--ports` is not specified, the scanner uses a built-in set of development and service ports:

```
22,80,443,3000,3001,3002,4000,4200,5000,5001,5173,5432,5672,6379,8000,8080,8081,8082,8443,9000,9090,9092,9200,9300,11211,15672,2181,27017,3306,6006,9222,9229
```
