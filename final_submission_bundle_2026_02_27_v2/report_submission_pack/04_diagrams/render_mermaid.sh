#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$ROOT_DIR/source"
OUT_DIR="$ROOT_DIR/rendered"
mkdir -p "$OUT_DIR"

render_with_npx() {
  for f in "$SRC_DIR"/*.mmd; do
    name="$(basename "$f" .mmd)"
    echo "Rendering $name with Mermaid CLI..."
    npx @mermaid-js/mermaid-cli -i "$f" -o "$OUT_DIR/$name.png"
  done
}

render_with_kroki() {
  for f in "$SRC_DIR"/*.mmd; do
    name="$(basename "$f" .mmd)"
    echo "Rendering $name with Kroki API..."
    curl -sS -X POST "https://kroki.io/mermaid/png" --data-binary @"$f" -o "$OUT_DIR/$name.png"
  done
}

if command -v npx >/dev/null 2>&1; then
  render_with_npx
else
  echo "npx not found, using Kroki API fallback."
  render_with_kroki
fi

echo "Rendered diagrams are available in: $OUT_DIR"
