#!/usr/bin/env bash
# check_statics.sh — inventory every mutable static in the target, the program
# and the applications, and fail when the set CHANGES.
#
# WHY A GATE AND NOT A LIST. DESIGN.md §21 asserted "four places assume
# single-threaded run-to-completion" and one grep found about twenty. §21 was
# the first document written after the rule "name the observation already in
# hand and go and look at it", and it asserted the list instead of sweeping for
# it. A list in prose rots the moment someone adds a static; a gate does not.
#
# A mutable static shared by two threads is not automatically a bug -- most of
# these are counters, and a racy counter is not a crash. It is a DECISION, and
# the point of the gate is that the decision gets made rather than defaulted.
# The counters that attribute findings are the ones that matter: an instrument
# producing a plausible wrong number is the failure family this project has
# paid for most.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

BASELINE=tools/statics.baseline

sweep() {
  grep -rnE '^[[:space:]]*static ' --include=*.c src/target src/program apps \
    | grep -v 'static const' \
    | grep -vE '\('                       `# skip function definitions` \
    | sed -E 's/[[:space:]]+/ /g; s/ = .*/;/' \
    | sort
}

cur=$(sweep)
if [ ! -f "$BASELINE" ]; then
  echo "$cur" > "$BASELINE"
  echo "check_statics: baseline created with $(wc -l <<<"$cur") entries"
  exit 0
fi

if diff -u "$BASELINE" <(echo "$cur") > /tmp/.statics.diff 2>&1; then
  echo "check_statics: $(wc -l <<<"$cur") mutable statics, unchanged"
  exit 0
fi

echo "check_statics: THE SET OF MUTABLE STATICS CHANGED." >&2
echo "Each one is a decision about thread ownership, not an oversight to wave" >&2
echo "through. Decide, then update $BASELINE in the same commit." >&2
sed -n '3,$p' /tmp/.statics.diff | grep -E '^[+-]' >&2
exit 1
