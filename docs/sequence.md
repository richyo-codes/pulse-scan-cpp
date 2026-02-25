# Sequence Diagrams

These diagrams capture key runtime flows in `pulsescan-cpp` using Mermaid.
Source files for CI rendering are under `docs/diagrams/*.mmd`.

## CLI to Port Scan Flow

```mermaid
sequenceDiagram
    participant User
    participant Main as main.cpp
    participant App as run_app (core/app.cpp)
    participant CLI as parse_cli (core/cli.cpp)
    participant Sandbox as apply_sandbox (platform/sandbox)
    participant Resolve as resolve_or_expand (core/resolve.cpp)
    participant Runner as run_scans (core/scan_runner.cpp)
    participant Scan as scan_tcp/scan_udp (src/net)
    participant Output as emit_scan_report/emit_port_result

    User->>Main: pulsescan-cpp [hosts] [options]
    Main->>App: run_app(argc, argv)
    App->>CLI: parse_cli(...)
    CLI-->>App: ScanOptions + host list
    App->>Sandbox: apply_sandbox(opts, hosts)
    Sandbox-->>App: status/message
    loop each host
        App->>Resolve: resolve_or_expand(host, resolver, opts)
        Resolve-->>App: address list
        App->>Runner: run_scans(host, addresses, opts, callback)
        loop each address x port
            Runner->>Scan: scan_one(...)
            alt TCP connect/banner
                Scan-->>Runner: ScanResult
            else UDP
                Scan-->>Runner: ScanResult
            end
            Runner-->>Output: callback(ScanRecord)
        end
    end
    Output-->>User: text report or JSON lines
```

## Ping Loop Change Detection (`--ping`)

```mermaid
sequenceDiagram
    participant App as run_app
    participant Loop as ping_loop (core/ping_loop.cpp)
    participant Resolve as resolve_or_expand
    participant Runner as run_scans
    participant State as last_state map
    participant Out as emit_port_result / emit_unavailable

    App->>Loop: ping_loop(hosts, opts, status)
    loop every opts.ping_interval
        Loop->>Resolve: resolve targets for current cycle
        Resolve-->>Loop: addresses
        Loop->>Runner: run_scans(..., callback)
        Runner-->>Loop: ScanRecord stream
        Loop->>State: compare current state vs previous
        alt first pass or changed
            Loop->>Out: emit_port_result(change=true/first)
        else unchanged
            Note over Loop: No text output; JSON depends on filters
        end
        Loop->>State: prune missing keys
        alt key disappeared
            Loop->>Out: emit_unavailable(...)
        end
    end
```

## ICMP Ping Flow (`--icmp-ping`)

```mermaid
sequenceDiagram
    participant App as run_app
    participant IcmpScan as icmp_scan_hosts / icmp_ping_loop
    participant Once as icmp_ping_once (net/icmp_ping.cpp)
    participant Sock as icmp::socket
    participant Timer as steady_timer
    participant Parse as parse_v4_echo_reply / parse_v6_echo_reply
    participant Out as output

    App->>IcmpScan: start ICMP mode
    loop each host/address (and cycle in ping loop)
        IcmpScan->>Once: icmp_ping_once(addr, opts)
        Once->>Sock: open(v4/v6)
        alt permission denied
            Once-->>IcmpScan: error (root or CAP_NET_RAW hint)
        else open ok
            Once->>Sock: async_send_to(echo request id/seq)
            Once->>Timer: arm timeout
            loop until timeout or valid reply
                Sock-->>Once: async_receive_from(...)
                Once->>Parse: validate type/code/id/seq
                alt valid echo reply
                    Once-->>IcmpScan: up
                else unrelated packet
                    Note over Once: ignore and continue waiting
                end
            end
            alt timeout
                Once-->>IcmpScan: down (timeout)
            end
        end
        IcmpScan->>Out: emit_icmp_result(...)
    end
```

## Status Signals / Enter Key Progress

```mermaid
sequenceDiagram
    participant User
    participant Signals as signal_set (SIGINT/SIGTERM/SIGINFO)
    participant Stdin as async_read_until('\\n')
    participant Status as ScanStatus
    participant Format as format_status (core/status.cpp)
    participant Err as stderr

    par Signal path
        User->>Signals: SIGINFO (FreeBSD) or SIGINT/SIGTERM
        Signals->>Format: format_status(Status)
        Format-->>Err: "progress: targets ... hosts ... cycles ..."
        alt SIGINT/SIGTERM
            Signals-->>Signals: stop io_context
        end
    and Enter key path
        User->>Stdin: press Enter
        Stdin->>Format: format_status(Status)
        Format-->>Err: progress snapshot
    end
```
