# Debugging

## Enable Core Dumps

```bash
ulimit -c unlimited
```

Check where core files go:

```bash
cat /proc/sys/kernel/core_pattern
```

If the pattern is `core` or `core.%p`, the core file is written in the current
working directory.

If the pattern pipes to systemd-coredump, use:

```bash
coredumpctl list | tail
coredumpctl info <PID>
coredumpctl dump <PID> --output core.dump
```

## Attach gdb to a Running Process

Attach to the newest `pulsescan-cpp` process:

```bash
gdb -p $(pgrep -n pulsescan-cpp)
```

Attach to a specific PID:

```bash
gdb -p <PID>
```

## Run Under gdb

If the process exits too fast, run it under gdb directly:

```bash
gdb --args ./build/pulsescan-cpp localhost -p 443
```
