# Packaging

This document describes how to build DEB/RPM packages for PulseScan and how to
choose between system dependencies and vcpkg (static).

## Quick start

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DPULSECAN_USE_VCPKG=OFF
cmake --build build --config Release
cpack --config build/CPackConfig.cmake -G DEB
cpack --config build/CPackConfig.cmake -G RPM
```

Use `-DPULSECAN_USE_VCPKG=ON` if you want to link against vcpkg-provided
dependencies (static where possible).

## System dependency packages

PulseScan uses Boost.Asio and CLI11. Catch2 is only required for tests.

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake ninja-build pkg-config \
  libboost-system-dev \
  libcli11-dev \
  catch2
```

Notes:
- `libboost-system-dev` covers Boost.System (used by Asio).
- If you do not build tests, `catch2` is optional.

### Fedora

```bash
sudo dnf install -y \
  gcc-c++ cmake ninja-build pkgconf-pkg-config \
  boost-devel \
  cli11-devel \
  catch2-devel
```

Notes:
- `boost-devel` provides Boost.System and headers.
- If you do not build tests, `catch2-devel` is optional.

### FreeBSD

```bash
sudo pkg update -f
sudo pkg install -y cmake ninja pkgconf cli11 boost-all catch2
```

Notes:
- This path uses system ports/packages for both CLI11 and Boost.
- Configure with `-DPULSECAN_USE_VCPKG=OFF`.

FreeBSD native static-ish third-party build (vcpkg):

```bash
sudo pkg update -f
sudo pkg install -y cmake ninja pkgconf git curl zip unzip
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh -disableMetrics
cmake -S . -B build \
  -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DPULSECAN_USE_VCPKG=ON \
  -DCMAKE_TOOLCHAIN_FILE="$PWD/vcpkg/scripts/buildsystems/vcpkg.cmake" \
  -DVCPKG_TARGET_TRIPLET=x64-freebsd \
  -DBUILD_TESTING=OFF
cmake --build build --config Release
```

Notes:
- This links third-party deps from vcpkg static libs where available.
- It is not fully static libc on FreeBSD; treat it as static-ish.

## Build and package with system deps

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DPULSECAN_USE_VCPKG=OFF \
  -DBUILD_TESTING=OFF
cmake --build build --config Release
cmake --build build --target package
```

Artifacts:
- `build/*.deb` (DEB)
- `build/*.rpm` (RPM)

## Build and package with vcpkg

```bash
export VCPKG_ROOT=/path/to/vcpkg
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DPULSECAN_USE_VCPKG=ON \
  -DBUILD_TESTING=OFF
cmake --build build --config Release
cmake --build build --target package
```

## Tips

- When using system packages, ensure your distro provides `cli11` and `catch2`.
  If not, use vcpkg or disable testing.
- CPack requires `dpkg-deb` for DEB and `rpmbuild` for RPM on the build host.

## CI RPM variants

CI now produces two RPM variants:

- `pulsescan-cpp-rpm-system`: Fedora-native packaging using system dependencies.
- `pulsescan-cpp-rpm-static-vcpkg`: vcpkg-linked build (mostly static third-party libs).
