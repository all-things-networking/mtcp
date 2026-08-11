#!/usr/bin/env bash
#
# Derive src/infra/ from the donor: read each manifest row out of the donor
# commit, run it through provenance/rename.sed, write it to <outdir>.
#
# This is the single definition of "what the seeded file would be if nobody had
# touched it". tools/check_infra_provenance.sh calls it to prove that the files
# in the tree are still the donor's plus a recorded, reviewed residual, and
# whoever seeds a new file calls it to produce the starting point.
#
# It never writes into src/infra/ itself. Installing is a deliberate copy.
#
#   usage: tools/seed_infra.sh <outdir> [donor-commit]
#
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${1:?usage: seed_infra.sh <outdir> [donor-commit]}
donor=${2:-$(sed -n 's/^donor_commit[[:space:]]*//p' "$here/src/infra/provenance/DONOR")}

manifest=$here/src/infra/provenance/manifest.tsv
rules=$here/src/infra/provenance/rename.sed

mkdir -p "$out"
while IFS=$'\t' read -r src dst _rest; do
	case $src in ''|'#'*) continue ;; esac
	mkdir -p "$out/$(dirname "$dst")"
	git -C "$here" show "$donor:$src" | sed -E -f "$rules" > "$out/$dst"
done < "$manifest"
