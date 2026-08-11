#!/usr/bin/env bash
#
# Rule 4, as a test: no protocol identity in src/target/ or src/infra/.
#
#   "no tcp/homa/quic/rocev2/ndp as defined symbols, macros, or
#    conditional-compilation guards, in the target or the compiler."
#
# ============================================================================
#  WHAT THIS TEST CANNOT CATCH — read this before trusting a green run
# ============================================================================
#
# It catches NAMES. It does not catch protocol-shaped HOLES with neutral names,
# and that is the failure mode that actually happens.
#
# The evidence is not hypothetical. C wrote Homa's MTP program against this
# target's contract (docs/DECISIONS.md D-09, docs/phase-d/programs/homa.mtp).
# The prototype's Homa branch solved six of its problems by putting
# protocol-shaped things into the target. A name grep catches `CreateHomaCtx`
# and `MTP_HOMA_MAX_RPC`. It does not catch `bp->prio`, `bp->cur_stream` or
# `IPOutputWTos` — a priority field, a current-stream pointer and a TOS-setting
# IP call, all with names that no grep would ever flag, each of them one
# protocol's scheduler leaking through the boundary.
#
# So a green run here means "nothing is NAMED after a protocol". It does not
# mean the boundary holds. The test that means that is rule 4's own: build two
# protocols and `diff -r` the target sources. That test is vacuous while there
# is one protocol, and writing Homa's program against the contract — reading
# what it cannot express — is the substitute until there are two.
#
# ============================================================================
#
# Three checks, in increasing strength:
#
#   1. file names
#   2. preprocessor definitions and guards, in source
#   3. the symbol table of what was actually compiled (nm), which is the only
#      one of the three that cannot be fooled by a comment or a string
#
# Comments are exempt by design. Rule 3 requires naming where mechanism came
# from ("from mTCP tcp_out.c:545"), and a rule that forbade saying "TCP" in a
# comment would forbid the provenance the charter demands.
#
#   usage: tools/check_rule4.sh
#
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
dirs="src/infra src/target"
names='tcp|homa|quic|rocev2|ndp'
allow=$here/tools/rule4_allow.txt

fail=0
note() { echo "RULE 4  $*"; fail=1; }

# --- 1. file names ----------------------------------------------------------
while IFS= read -r f; do
	note "file name names a protocol: $f"
done < <(cd "$here" && find $dirs -type f | grep -iE "/[^/]*($names)[^/]*$" || true)

# --- 2. preprocessor: definitions and guards --------------------------------
# `#define X`, `#undef X`, `#ifdef X`, `#ifndef X`, `#if defined(X)`. A protocol
# name anywhere in one of those is this tree taking a position on which protocol
# it is. Referencing a third-party macro in an expression is not, and is checked
# against the allowlist in step 3 instead.
while IFS= read -r hit; do
	tok=$(printf '%s' "$hit" | grep -oiE "\b[A-Za-z_][A-Za-z_0-9]*($names)[A-Za-z_0-9]*" | head -1)
	grep -qxF "$tok" "$allow" 2>/dev/null && continue
	note "protocol-named macro or guard: $hit"
done < <(cd "$here" && grep -rniE "^[[:space:]]*#[[:space:]]*(define|undef|ifdef|ifndef)[[:space:]]+[A-Za-z_0-9]*($names)" $dirs || true)

while IFS= read -r hit; do
	note "protocol name in a conditional-compilation guard: $hit"
done < <(cd "$here" && grep -rniE "^[[:space:]]*#[[:space:]]*(if|elif)\b.*defined[[:space:]]*\([[:space:]]*[A-Za-z_0-9]*($names)" $dirs || true)

# --- 3. the symbol table ----------------------------------------------------
# What the compiler actually produced. A defined symbol naming a protocol fails
# unless it is on the allowlist — and it may only be on the allowlist if it is
# somebody else's, which for a *defined* symbol means a `static const` that a
# third-party header dropped into our object file. An undefined one is a plain
# reference to another API (DPDK's RTE_*_TCP_CKSUM, libc's IPPROTO_TCP), which
# rule 4 does not forbid and which cannot be removed without changing
# behaviour.
#
# Both lists are allowlisted rather than one, because the distinction the rule
# cares about is who wrote the name, and nm cannot tell. The allowlist is where
# a human says so, in writing.
objs=$(cd "$here" && find build/src/infra build/src/target -name '*.o' 2>/dev/null | sort)
if [ -z "$objs" ]; then
	echo "RULE 4  note: no objects built, so the symbol-table check did not run."
	echo "        Run \`make\` first — it is the strongest of the three."
else
	while IFS= read -r sym; do
		grep -qxF "$sym" "$allow" 2>/dev/null && continue
		note "defined symbol names a protocol: $sym"
	done < <(cd "$here" && nm --defined-only $objs 2>/dev/null |
		 awk '{print $NF}' | sort -u | grep -iE "($names)" || true)

	while IFS= read -r sym; do
		grep -qxF "$sym" "$allow" 2>/dev/null && continue
		note "undefined symbol names a protocol and is not on the allowlist: $sym"
	done < <(cd "$here" && nm --undefined-only $objs 2>/dev/null |
		 awk '{print $NF}' | sort -u | grep -iE "($names)" || true)
fi

if [ "$fail" = 0 ]; then
	echo "rule 4: OK — nothing in src/infra/ or src/target/ names a protocol."
	echo "        (names only; see the header of this script for what that does"
	echo "         not prove)"
fi
exit "$fail"
