#!/usr/bin/env bash
#
# Re-record the residual hashes in provenance/manifest.tsv after a deliberate
# edit to a seeded file.
#
# Run BY HAND, never from the build. The checker is only worth anything if
# accepting a change to seeded code is a thing a person did on purpose; a
# recorder that ran automatically would turn the gate into a rubber stamp.
#
# After running it, `git diff` the manifest, check the changed rows are the ones
# you meant to change, and write the reason in the fourth column.
#
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest=$here/src/infra/provenance/manifest.tsv

derived=$(mktemp -d)
trap 'rm -rf "$derived"' EXIT
"$here/tools/seed_infra.sh" "$derived"

tmp=$(mktemp)
while IFS=$'\t' read -r src dst want reason; do
	case $src in ''|'#'*) printf '%s\n' "$src"; continue ;; esac
	diff=$(diff -u --label "donor+rename" --label "ours" \
		"$derived/$dst" "$here/src/infra/$dst" || true)
	if [ -z "$diff" ]; then
		got=-
	else
		got=$(printf '%s' "$diff" | sha256sum | cut -d' ' -f1)
	fi
	[ "$got" != "$want" ] && echo "re-recorded $dst" >&2
	printf '%s\t%s\t%s\t%s\n' "$src" "$dst" "$got" "$reason"
done < "$manifest" > "$tmp"
mv "$tmp" "$manifest"
