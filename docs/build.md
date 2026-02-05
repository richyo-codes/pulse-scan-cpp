# Build

## Configure and Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

## Dependency Source (system vs vcpkg)

By default, the build uses vcpkg if `VCPKG_ROOT` is set. To prefer system
packages, disable vcpkg:

```bash
cmake -S . -B build -DPULSECAN_USE_VCPKG=OFF
```

To force vcpkg (static libs) when it is available:

```bash
cmake -S . -B build -DPULSECAN_USE_VCPKG=ON
```

## Packaging (DEB/RPM)

Packages are generated via CPack. After a successful build, run:

```bash
cpack --config build/CPackConfig.cmake -G DEB
cpack --config build/CPackConfig.cmake -G RPM
```

Or use the package target:

```bash
cmake --build build --target package
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
