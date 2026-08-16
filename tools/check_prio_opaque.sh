#!/usr/bin/env bash
# check_prio_opaque.sh — the SECOND half of D-17's acceptance test.
#
# The first half is observable: control ahead of pure acknowledgements ahead of
# data, on the wire. A target that hard-codes "class 2 is control" PASSES that
# and fails rule 4, because it has put the protocol back inside the target. So
# the second half is a property of the SOURCE: the target attaches no meaning
# to a priority class.
#
# HANDOFF-M4.md §4.2 calls this "the one that gets skipped", because it is an
# absence rather than a behaviour and nothing fails when it is not checked.
# This makes it fail.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# Any symbol in the target that names a class's MEANING, or any comparison of a
# priority against a named protocol concept. Prose explaining the rule is
# allowed; a mapping is not.
hits=$(grep -rniE \
    'PRIO_(CONTROL|ACK|DATA|SYN|FIN|RST|PROBE)|(prio|class)[^;]{0,20}==[^;]{0,20}(control|ack|data|syn|fin)' \
    src/target/ 2>/dev/null \
  | grep -viE 'attaches no meaning|no meaning to|what each class|a target that knew|would have put' \
  || true)

if [ -n "$hits" ]; then
  echo "check_prio_opaque: THE TARGET NAMES WHAT A PRIORITY CLASS MEANS." >&2
  echo "The target drains higher before lower and knows nothing else; which" >&2
  echo "packet takes which class is the program's, stated at pkt_gen." >&2
  echo "$hits" >&2
  exit 1
fi

# And the program must actually be declaring a policy -- an all-zero policy
# would pass the above and produce no ordering at all.
if ! grep -qE 'PRIO_(CONTROL|ACK|DATA)' src/program/*.c 2>/dev/null; then
  echo "check_prio_opaque: no priority policy declared in src/program/." >&2
  echo "The classes exist and nothing uses them, so the ordering is untested" >&2
  echo "and the wire half of the acceptance test cannot pass." >&2
  exit 1
fi

echo "check_prio_opaque: target opaque to class meaning; program declares a policy"
