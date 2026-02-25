#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IN_DIR="${ROOT_DIR}/docs/diagrams"
OUT_DIR="${ROOT_DIR}/docs/diagrams/rendered"
RENDER_TIMEOUT="${RENDER_TIMEOUT:-90s}"

mkdir -p "${OUT_DIR}"

MMDC="${ROOT_DIR}/node_modules/.bin/mmdc"
if [[ ! -x "${MMDC}" ]]; then
  if command -v mmdc >/dev/null 2>&1; then
    MMDC="$(command -v mmdc)"
  else
    echo "Mermaid CLI not found. Run: npm install" >&2
    exit 1
  fi
fi

PUPPETEER_CONFIG=""
USE_NO_SANDBOX=0
CHROME_PATH="${MERMAID_CHROME_PATH:-}"

if [[ -z "${CHROME_PATH}" ]]; then
  for browser in chromium-browser chromium google-chrome-stable google-chrome; do
    if command -v "${browser}" >/dev/null 2>&1; then
      CHROME_PATH="$(command -v "${browser}")"
      break
    fi
  done
fi

if [[ "${MERMAID_NO_SANDBOX:-}" == "1" ]]; then
  USE_NO_SANDBOX=1
fi
if [[ "$(uname -s)" == "Linux" && "${MERMAID_SANDBOX:-0}" != "1" ]]; then
  USE_NO_SANDBOX=1
fi

if [[ "${MERMAID_RENDERER:-node}" == "node" ]]; then
  PUPPETEER_CONFIG="$(mktemp)"
  {
    echo "{"
    echo "  \"headless\": \"new\","
    echo "  \"timeout\": 45000,"
    if [[ -n "${CHROME_PATH}" ]]; then
      echo "  \"executablePath\": \"${CHROME_PATH}\","
    fi
    echo "  \"args\": ["
    if [[ "${USE_NO_SANDBOX}" == "1" ]]; then
      echo "    \"--no-sandbox\","
      echo "    \"--disable-setuid-sandbox\","
      echo "    \"--disable-dev-shm-usage\","
      echo "    \"--disable-gpu\","
      echo "    \"--no-zygote\","
      echo "    \"--single-process\""
    fi
    echo "  ]"
    echo "}"
  } > "${PUPPETEER_CONFIG}"
  trap 'rm -f "${PUPPETEER_CONFIG}"' EXIT
  if [[ -n "${CHROME_PATH}" ]]; then
    echo "Using Chromium executable: ${CHROME_PATH}"
  else
    echo "No explicit Chromium executable found; Puppeteer default lookup will be used."
  fi
fi

for input in "${IN_DIR}"/*.mmd; do
  [ -e "${input}" ] || continue
  base="$(basename "${input}" .mmd)"
  output="${OUT_DIR}/${base}.svg"
  echo "Rendering ${input} -> ${output}"

  if [[ "${MERMAID_RENDERER:-node}" == "container" ]]; then
    container_cmd=(docker run --rm -u "$(id -u):$(id -g)" \
      -v "${ROOT_DIR}:/data:Z" \
      ghcr.io/mermaid-js/mermaid-cli/mermaid-cli:11.4.0 \
      -i "/data/docs/diagrams/${base}.mmd" \
      -o "/data/docs/diagrams/rendered/${base}.svg" \
      -b transparent)
    if command -v timeout >/dev/null 2>&1; then
      timeout --foreground "${RENDER_TIMEOUT}" "${container_cmd[@]}"
    else
      "${container_cmd[@]}"
    fi
    continue
  fi

  cmd=("${MMDC}" -i "${input}" -o "${output}" -b transparent)
  if [[ -n "${PUPPETEER_CONFIG}" ]]; then
    cmd+=(--puppeteerConfigFile "${PUPPETEER_CONFIG}")
  fi

  if command -v timeout >/dev/null 2>&1; then
    timeout --foreground "${RENDER_TIMEOUT}" "${cmd[@]}"
  else
    "${cmd[@]}"
  fi
done

echo "Done. Rendered diagrams are in ${OUT_DIR}"
