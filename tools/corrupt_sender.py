#!/usr/bin/env python3
"""Send one SYN with a correct layer-4 checksum and one with a corrupt one.

D-22's check can never fire in normal operation, and the injector
(MTP_CORRUPT_NTH_RX) only proves that the DROP PATH works — it condemns a frame
the hardware passed. It cannot prove the hardware actually condemns a corrupt
frame, because it never produces one.

This does. It puts a real frame with a wrong checksum on the wire, so the whole
chain is exercised: the NIC computes, the PMD translates, rx_csum_verdict()
reports, and the target drops. The observable is a SYN that gets no SYN-ACK
where an otherwise identical SYN gets one.

Both SYNs are sent so the run is a comparison rather than a single negative:
"no reply" on its own is also what a misconfigured port looks like.

Root, on a node whose kernel still owns the interface (bifurcated mlx4 —
see docs/DPDK_HANDOFF.md).

    sudo ./tools/corrupt_sender.py <dst-ip> <dst-port> [src-ip]
"""
import socket
import struct
import sys
import time


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def syn(src_ip: str, dst_ip: str, sport: int, dport: int, corrupt: bool) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    tcp = struct.pack(
        "!HHIIBBHHH",
        sport, dport,
        0x1000,          # our sequence number, arbitrary
        0,               # ack
        5 << 4,          # data offset 5 words, no options
        0x02,            # SYN
        8192,            # window
        0,               # checksum, filled in below
        0,               # urgent
    )
    pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
    csum = checksum(pseudo + tcp)
    if corrupt:
        # A DIFFERENT value, not a zero: zero means "not computed" for UDP and
        # is a special case worth staying away from, and flipping one bit keeps
        # the frame otherwise byte-identical to the good one.
        csum ^= 0x0001
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]

    total = 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0, 0x4000, 64, socket.IPPROTO_TCP, 0, src, dst
    )
    # the kernel fills the IP checksum for us; only the L4 one is under test
    return ip + tcp


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    dst_ip, dport = sys.argv[1], int(sys.argv[2])
    src_ip = sys.argv[3] if len(sys.argv) > 3 else \
        socket.gethostbyname(socket.gethostname())

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    for corrupt, sport in ((False, 40001), (True, 40002)):
        pkt = syn(src_ip, dst_ip, sport, dport, corrupt)
        s.sendto(pkt, (dst_ip, 0))
        print("sent SYN from port %d with a %s checksum"
              % (sport, "CORRUPT" if corrupt else "correct"))
        time.sleep(0.4)
    return 0


if __name__ == "__main__":
    sys.exit(main())
