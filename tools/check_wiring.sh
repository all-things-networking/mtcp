#!/usr/bin/env bash
#
# Declared and never connected — the defect class this tree has now produced
# three times.
#
#   PROG_L4_CSUM_OFFSET   defined, never read. The NIC then wrote the transport
#                         checksum at offset 0, over the source port, and every
#                         frame went out malformed. Cost five turns.
#   `mtp/tcp.mtp §name`   cited in generated code, pointing at a file that did
#                         not exist.
#   listener_table        built in the target, never called.
#
# All three are the same shape: something declared, nothing wired to it, and no
# compiler complaint because a definition without a use is legal C. A grep
# catches every one of them, so this fails the build rather than warning.
#
# It cannot catch a constant read in the wrong place — nothing can, short of a
# test — but it catches one read nowhere, which is where all three landed.
#
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here"
fail=0

# --- 1. program constants defined and never read ----------------------------
# The program's headers are compiler output; a constant it emits that nothing
# consumes means a wiring step was missed, not that the program is generous.
while IFS= read -r name; do
	# Declared ahead of the mechanism that will consume it. Each entry names
	# the milestone, so the list is a schedule rather than a silencer — and
	# it stays short, because a constant that outlives its milestone here is
	# the same defect the gate exists to catch.
	grep -qE "^$name\b" tools/wiring_pending.txt 2>/dev/null && continue
	uses=$(grep -rhow "$name" src apps tests 2>/dev/null | wc -l)
	# one hit is the #define itself
	if [ "$uses" -le 1 ]; then
		echo "UNWIRED  $name is defined in src/program/ and read nowhere"
		fail=1
	fi
done < <(grep -rhoE '^#define[[:space:]]+(PROG|PARITY)_[A-Z0-9_]+' src/program/*.h |
	 awk '{print $2}' | sort -u)

# --- 2. target fields set nowhere -------------------------------------------
# Narrow on purpose: a blueprint field the emitter reads and pkt_gen never
# writes is exactly the checksum-offset bug, and it is worth its own check
# because that field had a plausible default (zero) that looked like a header.
for f in $(grep -oE '^\s+[a-z0-9_]+\s+([a-z0-9_]+);' src/target/internal.h |
	   awk '{print $2}' | tr -d ';' | sort -u); do
	# `&bp->field` passed to something that fills it counts as a write
	writes=$(grep -rhoE "(bp|out)->$f[[:space:]]*=|&(bp|out)->$f\b" src/target 2>/dev/null | wc -l)
	reads=$(grep -rhoE "(bp|b)->$f\b" src/target 2>/dev/null | wc -l)
	if [ "$reads" -gt 0 ] && [ "$writes" -eq 0 ]; then
		echo "UNWIRED  struct bp field '$f' is read in src/target/ and assigned nowhere"
		fail=1
	fi
done

# --- 3. `.mtp` section references that point at nothing ----------------------
# Generated code cites the program section it came from. A citation into a file
# or a section that does not exist is the same defect wearing a comment.
while IFS= read -r ref; do
	file=${ref%% §*}
	sec=${ref##*§}
	if [ ! -f "$file" ]; then
		echo "UNWIRED  generated code cites '$file', which does not exist"
		fail=1
	elif ! grep -q "^// §$sec\b\|^§$sec\b" "$file"; then
		echo "UNWIRED  '$file' has no section §$sec, cited by generated code"
		fail=1
	fi
done < <(grep -rhoE 'mtp/[a-z0-9_]+\.mtp §[a-z0-9_]+' src/ 2>/dev/null | sort -u)

[ "$fail" = 0 ] && echo "wiring: OK — nothing declared without being connected."
exit "$fail"
