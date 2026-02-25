#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IN_DIR="${ROOT_DIR}/docs/diagrams"
OUT_DIR="${ROOT_DIR}/docs/diagrams/rendered"

mkdir -p "${OUT_DIR}"

for input in "${IN_DIR}"/*.mmd; do
  [ -e "${input}" ] || continue
  base="$(basename "${input}" .mmd)"
  output="${OUT_DIR}/${base}.svg"
  echo "Rendering ${input} -> ${output}"
  npx -y @mermaid-js/mermaid-cli@11.4.0 -i "${input}" -o "${output}" -b transparent
done

echo "Done. Rendered diagrams are in ${OUT_DIR}"

