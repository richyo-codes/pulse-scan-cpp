#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
PREFIX="${PREFIX:-${HOME}/.local}"

if [[ -z "${VCPKG_ROOT:-}" ]]; then
  if [[ -d "${ROOT_DIR}/vcpkg" ]]; then
    VCPKG_ROOT="${ROOT_DIR}/vcpkg"
  else
    echo "VCPKG_ROOT is not set and ${ROOT_DIR}/vcpkg does not exist."
    echo "Set VCPKG_ROOT or clone vcpkg into ${ROOT_DIR}/vcpkg."
    exit 1
  fi
fi

cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
  -DPULSECAN_USE_VCPKG=ON \
  -DBUILD_TESTING=OFF \
  -DCMAKE_TOOLCHAIN_FILE="${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"

cmake --build "${BUILD_DIR}" --config "${BUILD_TYPE}"
cmake --install "${BUILD_DIR}" --prefix "${PREFIX}"

echo "Installed to ${PREFIX}/bin/pulsescan-cpp"
