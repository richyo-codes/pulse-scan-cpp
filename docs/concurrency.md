# Concurrency Model

## Current Model

The scanner uses Boost.Asio coroutines to run many in-flight connection attempts while limiting
parallelism with a simple queue and an `inflight` counter.

### Port Scans

- `run_scans` queues `(address, port)` pairs and spawns coroutines until `max_inflight` is reached.
- Each coroutine performs one scan (`TCP connect`, `TCP banner`, or `UDP`) and calls the result
  callback.
- When a coroutine finishes, it decrements `inflight` and launches more work.
- A `steady_timer` acts as a latch to wait until all work completes.

### Ping Mode

- `ping_loop` performs a full scan cycle, tracks state changes, then sleeps for the configured
  interval before repeating.
- Only changes are reported after the first pass.

### ICMP Ping Mode

- `icmp_scan_hosts` resolves/expands targets, then runs ICMP pings sequentially per address.
- `icmp_ping_loop` repeats the ICMP scan cycle on an interval and reports changes.

## Known Characteristics

- **Fairness**: Ports for a host are processed in queue order; no priority between hosts.
- **Backpressure**: `max_inflight` caps concurrent scans but does not adapt to network conditions.
- **Single io_context**: All work is scheduled onto one executor.

## Improvement Ideas

1) **Per-host rate limits**
   - Limit concurrent scans per host to avoid hot-spotting a single target.

2) **Adaptive concurrency**
   - Scale `max_inflight` based on recent timeouts/errors to avoid overwhelming slow networks.

3) **Address rotation**
   - Round-robin across resolved addresses instead of scanning all ports per address in one batch.

4) **Work stealing queues**
   - Use multiple queues (per host or per protocol) to reduce head-of-line blocking.

5) **Batch DNS resolution**
   - Cache resolved addresses across ping cycles to reduce resolver load when `--ping` is used.

6) **Timeout tuning**
   - Separate connect timeout from read timeout for banner mode to reduce false negatives.

7) **Parallel ping loops**
   - Run ICMP and TCP/UDP scan cycles concurrently for mixed modes.

8) **Multi-threaded io_context**
   - Run multiple threads with shared `io_context` for CPU-bound parsing or logging overhead.

9) **Structured metrics**
   - Track per-host latency and error rates; feed into adaptive scheduling.

10) **Cancellation / stop signals**
    - Add signal handling to stop in-flight scans gracefully.
