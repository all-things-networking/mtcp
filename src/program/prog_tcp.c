/*
 * The protocol's wire layout and its segmentation rule.
 *
 * Compiler output, hand-written in the form `mtpc` would emit. This is the
 * first file in the tree that is allowed to know what a TCP header is; rule 4
 * permits protocol identity here and nowhere else.
 *
 * From the `.mtp` source:
 *
 *     pkt_bp TCPBP { uint16 src_port, dst_port; uint32 seq_no, ack_seq;
 *                    uint8 data_off, flags; uint16 window;
 *                    checksum16_t checksum; uint16 urg_ptr;
 *                    tcp_options opts; data_t data; }
 *
 *     seg_rule seg_seq(x) [ TCPBP::seq_no, x, prev.hdr.seq_no + prev.payload_len ]
 */
#include <string.h>
#include <arpa/inet.h>

#include "contract.h"
#include "prog_params.h"
#include "prog_ctx.h"

/* Field offsets within the serialised header. The compiler knows these from
 * the pkt_bp declaration; nothing outside src/program/ does. */
#define TCPH_SEQ	4
#define TCPH_ACK	8
#define TCPH_DOFF	12
#define TCPH_FLAGS	13
#define TCPH_WINDOW	14
#define TCPH_CSUM	16

/*
 * The segmentation rule, at the target's segmentation point (CR-1).
 *
 * TCP's recurrence is PER BYTE — the next segment's sequence number is the
 * previous one's plus the previous payload length — which is why TCP is safe
 * under coalescing and under any other optimisation that changes how a
 * blueprint is split. A protocol whose recurrence is per PACKET is not: QUIC
 * advances its packet number once per packet, pkt_gen does not report how it
 * split, and the program's prediction is then wrong. Recorded here because
 * this is the file a future protocol's author will copy from.
 */
void
mtp_program_segment(const struct mtp_seg_view *v)
{
	uint32_t seq;

	if (!v->prev_hdr)
		return;			/* segment 0 keeps what the program built */

	memcpy(&seq, (const uint8_t *)v->prev_hdr + TCPH_SEQ, 4);
	seq = htonl(ntohl(seq) + v->prev_paylen);
	memcpy((uint8_t *)v->hdr + TCPH_SEQ, &seq, 4);
}

/*
 * Serialise the header once, when the blueprint is built — not per segment.
 * The prototype re-serialises the options for every segment; there is one
 * serialisation here and the per-segment work is the rule above.
 *
 * The option layout is frozen from the donor (tcp_out.c:83-124, 181-192) and
 * is an M1 exit item byte for byte, because moving serialisation into the
 * program is the one place the wire can change with no protocol logic changing.
 *
 *   SYN / SYN-ACK, exactly 20 bytes:
 *     MSS(2,4,hi,lo) NOP NOP Timestamp(8,10,TSval,TSecr) NOP WScale(3,3,7)
 *   every non-SYN, exactly 12 bytes:
 *     NOP NOP Timestamp
 */
uint16_t
tcp_build_header(uint8_t *out, const struct tcp_ctx *c, uint32_t seq,
		 uint8_t flags, uint32_t ts_val, uint32_t ts_ecr)
{
	int is_syn = (flags & 0x02) != 0;
	uint8_t *o;
	uint16_t hdr_len, w;
	uint32_t v32;

	memset(out, 0, 20);
	w = htons(c->loc_port);   memcpy(out + 0, &w, 2);
	w = htons(c->rem_port);   memcpy(out + 2, &w, 2);
	v32 = htonl(seq);         memcpy(out + TCPH_SEQ, &v32, 4);
	v32 = htonl(c->recv_next); memcpy(out + TCPH_ACK, &v32, 4);

	/* PSH is never set: tested at tcp_out.c:172,265 and passed by no
	 * caller. The program builds the header now, so this is a flag bit
	 * that could diverge with nothing else wrong. */
	out[TCPH_FLAGS] = (uint8_t)(flags & ~(PARITY_SET_PSH ? 0 : 0x08));

	w = htons(tcp_window_field(c, is_syn));
	memcpy(out + TCPH_WINDOW, &w, 2);

	o = out + 20;
	if (is_syn) {
		*o++ = 2; *o++ = 4;
		w = htons(PARITY_MSS_ADVERTISED); memcpy(o, &w, 2); o += 2;
		*o++ = 1; *o++ = 1;
		*o++ = 8; *o++ = 10;
		v32 = htonl(ts_val); memcpy(o, &v32, 4); o += 4;
		v32 = htonl(ts_ecr); memcpy(o, &v32, 4); o += 4;
		*o++ = 1;
		*o++ = 3; *o++ = 3; *o++ = PARITY_WSCALE;
	} else {
		*o++ = 1; *o++ = 1;
		*o++ = 8; *o++ = 10;
		v32 = htonl(ts_val); memcpy(o, &v32, 4); o += 4;
		v32 = htonl(ts_ecr); memcpy(o, &v32, 4); o += 4;
	}

	hdr_len = (uint16_t)(o - out);
	out[TCPH_DOFF] = (uint8_t)((hdr_len / 4) << 4);
	return hdr_len;
}
