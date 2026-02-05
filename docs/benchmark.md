# Benchmarking PulseScan vs Nmap

This document outlines a simple, repeatable way to compare PulseScan's range
scanning performance against nmap. The goal is a fair wall-clock comparison
with minimal DNS or network noise.

## General guidance

- Use a stable test range you own (lab VLAN, VM subnet, loopback).
- Disable DNS lookups (PulseScan: no `--reverse-dns`, nmap: `-n`).
- Keep scan scope identical (same hosts, same ports, same protocol).
- Use multiple runs and a warm-up to reduce variance.
- Do not scan public networks or hosts without permission.

## Tooling

`hyperfine` is a good fit for measuring total runtime.

Install (example for Debian/Ubuntu):

```bash
sudo apt-get install -y hyperfine
```

## Suggested baselines

Pick a range and port set:

- Range: `192.168.1.0/24` (example)
- Ports: 10 common ports
- Timeouts: 1.0s
- No DNS, no banner, no UDP (TCP connect only)

## Example: TCP connect scan

PulseScan:

```bash
./build/pulsescan-cpp 192.168.1.0/24 \
  --top-ports 10 \
  -t 1.0 \
  --max-inflight 200 \
  --output json > /dev/null
```

nmap:

```bash
nmap -n -Pn \
  --max-retries 1 \
  --host-timeout 1s \
  -p 20,21,22,23,25,53,80,81,88,110 \
  192.168.1.0/24 > /dev/null
```

Hyperfine:

```bash
hyperfine --warmup 1 --runs 5 \
  './build/pulsescan-cpp 192.168.1.0/24 --top-ports 10 -t 1.0 --max-inflight 200 --output json > /dev/null' \
  'nmap -n -Pn --max-retries 1 --host-timeout 1s -p 20,21,22,23,25,53,80,81,88,110 192.168.1.0/24 > /dev/null'
```

## Notes on fairness

- `--max-inflight` is PulseScan's concurrency knob; nmap has its own timing engine.
  You can also try `-T3` or `-T4` in nmap to explore different profiles.
- `--host-timeout` in nmap is a hard cap per host; adjust to match PulseScan timeouts.
- If you use `--ping` or `--icmp-ping`, benchmark them separately.

## Interpreting results

Hyperfine reports mean/median runtime and standard deviation. Compare relative
performance on the same hardware and network conditions. If results are noisy,
increase run count or narrow the test range.
