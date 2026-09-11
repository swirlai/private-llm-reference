#!/usr/bin/env bash
# Regenerate the committed diagram SVGs from the mermaid source in the markdown.
#
# The markdown embeds rendered SVGs rather than live mermaid blocks, because
# GitHub's client-side renderer fails intermittently. The mermaid source stays in
# a <details> block beside each diagram and IS the source of truth, so run this
# after editing one, or the picture and the source drift apart.
#
#   ./scripts/render-diagrams.sh      (needs npx; downloads mermaid-cli on first run)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/docs/diagrams"
mkdir -p "$OUT"
command -v npx >/dev/null || { echo "npx not found; install Node" >&2; exit 1; }

extract() {  # extract <markdown> -> stdout: the first mermaid block
  python3 -c '
import re, sys, pathlib
m = re.search(r"```mermaid\n(.*?)```", pathlib.Path(sys.argv[1]).read_text(), re.S)
sys.exit("no mermaid block in " + sys.argv[1]) if not m else sys.stdout.write(m.group(1))
' "$1"
}

render() {  # render <src.mmd> <basename>
  for variant in "light:neutral" "dark:dark"; do
    name="${variant%%:*}"; theme="${variant##*:}"
    npx -y @mermaid-js/mermaid-cli -i "$1" -o "$OUT/$2-$name.svg" -t "$theme" -b transparent >/dev/null
    echo "  $2-$name.svg"
  done
}

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

echo "README.md -> architecture"
extract "$ROOT/README.md" > "$tmp/architecture.mmd"
render "$tmp/architecture.mmd" architecture

echo "docs/ARCHITECTURE.md -> request-path"
extract "$ROOT/docs/ARCHITECTURE.md" > "$tmp/request-path.mmd"
render "$tmp/request-path.mmd" request-path

echo "done. Commit docs/diagrams/ alongside the markdown change."
