#ifndef IP_CSUM_H
#define IP_CSUM_H
/*
 * The IPv4 header checksum.
 *
 * from mTCP io_engine/include/ps.h:66-95 @7fbb223c — VERBATIM, including the
 * assembly and the comment inside it. The rest of ps.h is the PacketShader I/O
 * library, which this target does not carry, but the donor's IP receive and
 * transmit paths both call this and it is on the packet path, so it comes
 * across unchanged rather than being rewritten (docs/DECISIONS.md D-07).
 *
 * A partial lift, so it is not in provenance/manifest.tsv, which works at file
 * granularity. It is listed in PROVENANCE.md under "partial lifts".
 *
 * ps.h keeps a portable fallback for non-x86. Every machine this runs on is
 * x86-64 and the fallback is unreachable dead code, so it is not carried; if
 * that stops being true the donor still has it.
 */
#include <linux/types.h>	/* __sum16 */

static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	unsigned int sum;

	asm("  movl (%1), %0\n"
	    "  subl $4, %2\n"
	    "  jbe 2f\n"
	    "  addl 4(%1), %0\n"
	    "  adcl 8(%1), %0\n"
	    "  adcl 12(%1), %0\n"
	    "1: adcl 16(%1), %0\n"
	    "  lea 4(%1), %1\n"
	    "  decl %2\n"
	    "  jne      1b\n"
	    "  adcl $0, %0\n"
	    "  movl %0, %2\n"
	    "  shrl $16, %0\n"
	    "  addw %w2, %w0\n"
	    "  adcl $0, %0\n"
	    "  notl %0\n"
	    "2:"
	    /* Since the input registers which are loaded with iph and ih
	       are modified, we must also specify them as outputs, or gcc
	       will assume they contain their original values. */
	    : "=r" (sum), "=r" (iph), "=r" (ihl)
	    : "1" (iph), "2" (ihl)
	       : "memory");
	return (__sum16)sum;
}

#endif /* IP_CSUM_H */
