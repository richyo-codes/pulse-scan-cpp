# Build

## Configure and Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Enable Stacktrace (Optional)

The stacktrace support is optional and off by default.

Enable the vcpkg feature:

```bash
vcpkg install --feature-flags=manifest pulsescan-cpp[stacktrace]
```

Enable the CMake toggle:

```bash
cmake -S . -B build -DENABLE_STACKTRACE=ON
```
