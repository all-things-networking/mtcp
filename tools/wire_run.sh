#!/usr/bin/env bash
#
# Run one of our binaries on a node, send traffic INSIDE its window, and report
# what the receive path saw.
#
# This exists because three separate measurements in the zero-receive
# investigation were wrong for the same reason: traffic sent outside the run
# window looks exactly like traffic that never arrived. Sleeping a fixed time
# before probing is not good enough — EAL bring-up takes a variable few seconds
# — and polling the log is not good enough either if the log still holds the
# previous run's banner, which is how the second attempt fooled itself.
#
# So: truncate the log, launch, and BLOCK until this run's banner appears.
#
# It also records the port's carrier and address on both nodes with every
# result, because an mlx4 that has had XDP detached comes back NO-CARRIER and
# without its IPv4 for ~35 s, and two failures were already misdiagnosed before
# that was understood.
#
#   usage: WIRE_CLIENT='<cmd>' tools/wire_run.sh <server> <client> <binary> <ms> -- <args>
#
# WIRE_CLIENT is whatever should run on the client node INSIDE the window —
# a real client, a curl, a probe. It defaults to the connectivity probe below.
#
# It takes an arbitrary command because the first time something needed to run
# that the built-in probe did not cover, the answer was to launch the server by
# hand instead, and that reintroduced every artefact this script exists to
# remove: an unattributable run, from an ad-hoc launch, minutes after the same
# binary had worked through here. When doing it properly is more typing than
# doing it wrong, it gets done wrong — so the correct thing has to be the easy
# thing.
#
set -uo pipefail

SRV=${1:?server node}; CLI=${2:?client node}; BIN=${3:?binary}; MS=${4:?window ms}
shift 4; [ "${1:-}" = "--" ] && shift
ARGS="$*"

# Extra environment for the server, e.g. WIRE_ENV='MTP_DROP_NTH=5'. Passed
# through rather than requiring a hand-rolled launch — which is the mistake
# WIRE_CLIENT exists to prevent, and it would have recurred here.
WIRE_ENV=${WIRE_ENV:-}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=(ssh -o BatchMode=yes -o ConnectTimeout=8)

# A FRESH DIRECTORY PER RUN. A fixed path let a run that produced nothing be
# read as the previous run's answer — and that is the most dangerous apparatus
# failure of the five, because the other four produced WRONG readings and this
# one produces a PLAUSIBLE one from a run that never happened. Same fix as
# waiting on the banner from a truncated log, applied to the output side.
RUNID=$(date +%Y%m%d-%H%M%S)-$$
RD=/tmp/mtp-wire/$RUNID

# REFUSE A STALE BINARY. The handoff says to check the binary's mtime before
# questioning the logic; then a `make 2>&1 | grep -c error` chain swallowed a
# failed build and the old binary ran anyway, producing a reading of code that
# was never compiled. Remembering did not work, so it is checked here. Same
# principle as the fresh run directory: make it impossible, not unlikely.
stale=$(find "$here/src" "$here/apps" -name '*.[ch]' -newer "$here/bin/$BIN" 2>/dev/null | head -3)
if [ ! -x "$here/bin/$BIN" ]; then
	echo "REFUSING: bin/$BIN does not exist — build it on the build host first." >&2
	exit 1
fi
if [ -n "$stale" ]; then
	echo "REFUSING: sources are newer than bin/$BIN, so this would measure code" >&2
	echo "that was never compiled. Rebuild. Newer than the binary:" >&2
	echo "$stale" | sed 's/^/  /' >&2
	exit 1
fi

link_state() {
	"${S[@]}" "$1" 'printf "carrier=%s addr=%s" "$(cat /sys/class/net/ens2/carrier 2>/dev/null)" "$(ip -br addr show ens2 | awk "{print \$3}")"'
}

echo "server $SRV: $(link_state "$SRV")"
echo "client $CLI: $(link_state "$CLI")"

# stage, clear leftovers, TRUNCATE the log, launch, and wait for THIS run's banner
"${S[@]}" "$SRV" "sudo rm -rf /dev/hugepages/* /var/run/dpdk/* 2>/dev/null || true
	mkdir -p $RD && cd $RD
	cp -r $here/conf/aqua/config . 2>/dev/null
	cp $here/conf/aqua/upcheck.conf . 2>/dev/null
	cp $here/conf/aqua/upcheck.conf tcpserver.conf 2>/dev/null
	cp $here/bin/$BIN . || exit 1
	rm -f run.log
	sudo $WIRE_ENV MTP_DUMP_TX=${MTP_DUMP_TX:-4} nohup timeout \$(( MS/1000 + 20 )) ./$BIN $ARGS -t $MS > run.log 2>&1 &
	for w in \$(seq 1 300); do
		grep -q 'RUN WINDOW OPENS' run.log 2>/dev/null && exit 0
		sleep 0.1
	done
	echo 'TIMED OUT waiting for the run window'; exit 1" || {
	echo "FAILED: the window never opened"; exit 1; }

DEFAULT_CLIENT='ping -c 6 -i 0.2 -W 1 10.7.0.12 >/dev/null 2>&1
	timeout 2 bash -c "echo > /dev/tcp/10.7.0.12/9999" >/dev/null 2>&1
	arping -c 2 -I ens2 10.7.0.12 >/dev/null 2>&1
	true'
CLIENT=${WIRE_CLIENT:-$DEFAULT_CLIENT}

echo "window open; on $CLI: ${CLIENT%%$'\n'*}"
"${S[@]}" "$CLI" "$CLIENT"
echo "client done"

sleep $(( MS/1000 + 3 ))
# REFUSE a run whose artefacts are absent, rather than printing nothing and
# letting the caller reach for a previous result.
if ! "${S[@]}" "$SRV" "cd $RD 2>/dev/null && grep -q 'RUN WINDOW CLOSED' run.log"; then
	echo "FAILED: $SRV/$RD has no completed run. The server did not finish;"
	echo "        there is no result here, and any number you have is from"
	echo "        somewhere else."
	"${S[@]}" "$SRV" "tail -5 $RD/run.log 2>/dev/null || echo '  (no log at all)'"
	"${S[@]}" "$SRV" "sudo rm -rf /dev/hugepages/* /var/run/dpdk/* 2>/dev/null || true"
	exit 1
fi

echo "run: $SRV:$RD"
"${S[@]}" "$SRV" "cd $RD && grep -oE 'rx classes:.*|tx: .*|payload sizes:.*|timers fired: .*|promisc=[0-9]+ .*' run.log
	sudo rm -rf /dev/hugepages/* /var/run/dpdk/* 2>/dev/null || true"
