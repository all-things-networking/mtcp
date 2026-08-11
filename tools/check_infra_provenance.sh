#!/usr/bin/env bash
#
# D-07's diffability requirement, as a test.
#
# Every file in src/infra/ is either derived from the donor by rename.sed alone,
# or differs from that derivation by exactly the residual recorded in
# provenance/manifest.tsv. Anything else — an unrecorded edit, a file nobody
# listed, a rename rule quietly changed — fails here.
#
# The point is not to forbid editing seeded code. It is to make every edit
# visible, so "the difference we measure is in the transport" stays a checkable
# statement rather than a hope.
#
#   usage: tools/check_infra_provenance.sh [-v]     (-v prints each residual)
#
set -euo pipefail

verbose=0
[ "${1:-}" = "-v" ] && verbose=1

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest=$here/src/infra/provenance/manifest.tsv
empty_sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

derived=$(mktemp -d)
trap 'rm -rf "$derived"' EXIT
"$here/tools/seed_infra.sh" "$derived"

fail=0
listed=$derived/.listed
: > "$listed"

while IFS=$'\t' read -r src dst want reason; do
	case $src in ''|'#'*) continue ;; esac
	echo "$dst" >> "$listed"
	ours=$here/src/infra/$dst
	if [ ! -f "$ours" ]; then
		echo "MISSING  $dst (manifest lists it, tree does not have it)"
		fail=1
		continue
	fi
	# stable labels: the derivation lives in a temp directory, and its name
	# must not be part of what is hashed
	diff=$(diff -u --label "donor+rename" --label "ours" "$derived/$dst" "$ours" || true)
	got=$(printf '%s' "$diff" | sha256sum | cut -d' ' -f1)
	[ "$want" = "-" ] && want=$empty_sha
	if [ "$got" != "$want" ]; then
		echo "DRIFT    $dst"
		echo "         recorded residual $want"
		echo "         actual   residual $got   ($reason)"
		[ "$verbose" = 1 ] && printf '%s\n' "$diff"
		fail=1
	elif [ "$verbose" = 1 ] && [ -n "$diff" ]; then
		echo "=== $dst — recorded residual: $reason"
		printf '%s\n' "$diff"
	fi
done < "$manifest"

# A file in src/infra/ that no manifest row claims is new work living in the
# seeded layer. That is allowed, but it must be obvious, so it is listed.
while IFS= read -r f; do
	rel=${f#"$here/src/infra/"}
	case $rel in provenance/*) continue ;; esac
	grep -qxF "$rel" "$listed" || echo "not seeded (written for this target): $rel"
done < <(find "$here/src/infra" -type f \( -name '*.c' -o -name '*.h' \) | sort)

[ "$fail" = 0 ] && echo "infra provenance: OK"
exit "$fail"
