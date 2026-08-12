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
#   usage: tools/wire_run.sh <server-node> <client-node> <binary> <window-ms> -- <args...>
#
set -uo pipefail

SRV=${1:?server node}; CLI=${2:?client node}; BIN=${3:?binary}; MS=${4:?window ms}
shift 4; [ "${1:-}" = "--" ] && shift
ARGS="$*"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=(ssh -o BatchMode=yes -o ConnectTimeout=8)
RD=/tmp/mtp-wire

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
	sudo nohup timeout \$(( MS/1000 + 20 )) ./$BIN $ARGS -t $MS > run.log 2>&1 &
	for w in \$(seq 1 300); do
		grep -q 'RUN WINDOW OPENS' run.log 2>/dev/null && exit 0
		sleep 0.1
	done
	echo 'TIMED OUT waiting for the run window'; exit 1" || {
	echo "FAILED: the window never opened"; exit 1; }

echo "window open; probing from $CLI"
"${S[@]}" "$CLI" 'ping -c 6 -i 0.2 -W 1 10.7.0.12 >/dev/null 2>&1
	timeout 2 bash -c "echo > /dev/tcp/10.7.0.12/9999" >/dev/null 2>&1
	arping -c 2 -I ens2 10.7.0.12 >/dev/null 2>&1
	true'

sleep $(( MS/1000 + 3 ))
"${S[@]}" "$SRV" "cd $RD && grep -oE 'rx classes:.*|promisc=[0-9]+ .*' run.log
	sudo rm -rf /dev/hugepages/* /var/run/dpdk/* 2>/dev/null || true"
