#!/usr/bin/env bash
set -euo pipefail

if ! command -v npx >/dev/null 2>&1; then
  echo "npx is required to render Mermaid diagrams."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$ROOT_DIR/source"
OUT_DIR="$ROOT_DIR/rendered"
mkdir -p "$OUT_DIR"

for f in "$SRC_DIR"/*.mmd; do
  name="$(basename "$f" .mmd)"
  echo "Rendering $name..."
  npx @mermaid-js/mermaid-cli -i "$f" -o "$OUT_DIR/$name.png"
done

echo "Rendered diagrams available in: $OUT_DIR"
