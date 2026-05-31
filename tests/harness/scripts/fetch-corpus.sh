#!/usr/bin/env bash
# Fetch reference hives for roundtrip and corpus tests.
#
# The corpus is gitignored (tests/corpus/) and pulled separately because the
# hives carry their own license terms. This script is a placeholder until the
# corpus source and licensing are settled with the spec agent; it documents the
# intended layout and refuses to invent a download URL.
#
# Expected layout once populated:
#   tests/corpus/<source>/<hive-name>.hiv
#   tests/corpus/<source>/LICENSE
#   tests/corpus/<source>/PROVENANCE.md   (where the hive came from)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CORPUS_DIR="$REPO_ROOT/tests/corpus"

echo "Corpus directory: $CORPUS_DIR"
mkdir -p "$CORPUS_DIR"

cat <<'NOTE'
No corpus source is configured yet.

Reference hives must come with redistributable licenses. Before wiring a
download here, raise a spec issue (tag: spec) to agree on:
  - which hives (synthetic vs. real Windows SOFTWARE/SYSTEM hives)
  - their license and provenance
  - a hosting location the CI can reach offline-friendly (apt mirror or
    internal artifact store, per the Debian-first rule)

Until then, drop hives manually under tests/corpus/<source>/ with a LICENSE
and PROVENANCE.md, and the roundtrip tests will pick them up.
NOTE
exit 0
