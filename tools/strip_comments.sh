#!/usr/bin/env bash
# Regenerate mtp/tcp.bare.mtp -- the program with the commentary removed.
#
# mtp/tcp.mtp is the authority: it carries which donor line a value comes from,
# which explanations were withdrawn, and which reproduced behaviour is a defect
# on purpose. That is rule 3 and it stays. This is a NAVIGATION AID -- the same
# program with the prose gone, for reading the shape of it in one pass.
#
# It is derived, never edited, and never compiled: two .mtp files that can both
# be built is two programs that can drift.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python3 - <<'PY'
src = open('mtp/tcp.mtp').read().split('\n')
out = []
for l in src:
    if l.lstrip().startswith('//'):
        continue
    out.append(l.split('//')[0].rstrip() if '//' in l else l.rstrip())
res = []
for l in out:
    if l.strip() == '' and res and res[-1].strip() == '':
        continue
    res.append(l)
open('mtp/tcp.bare.mtp','w').write(
    "// tcp.mtp with the commentary removed. GENERATED from mtp/tcp.mtp by\n"
    "// tools/strip_comments.sh -- do not edit, and do not compile this one:\n"
    "// mtp/tcp.mtp is the authority and carries the reasons.\n\n"
    + '\n'.join(res).strip('\n') + '\n')
PY
echo "wrote mtp/tcp.bare.mtp"
