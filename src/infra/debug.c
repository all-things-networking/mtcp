#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include "debug.h"
#include "ip_csum.h"
#include "logger.h"

/*----------------------------------------------------------------------------*/
void
flush_log_data(core_ctx_t core)
{
	int ret = 0;
	if (core->w_buffer) {
		EnqueueJobBuffer(core->logger, core->w_buffer);
		ret = write(core->sp_fd, "A", 1);
		if (ret != 1) {
			TRACE_INFO("Failed to flush logs in the buffer.\n");
			perror("write() for pipe");
		}
	}
}
/*----------------------------------------------------------------------------*/
void
thread_printf(core_ctx_t core, FILE* f_idx, const char* _Format, ...) 
{
	va_list argptr;
	va_start(argptr, _Format);

	#define PRINT_LIMIT 4096
	int len;
	log_buff *wbuf;

	assert(f_idx != NULL);

	pthread_mutex_lock(&core->logger->mutex);
	wbuf = core->w_buffer;
	if (wbuf && (wbuf->buff_len + PRINT_LIMIT > LOG_BUFF_SIZE)) {
		flush_log_data(core);
		wbuf = NULL;
	}

	if (!wbuf) {
		do { // out of free buffers!!
			wbuf = DequeueFreeBuffer(core->logger);
			assert(wbuf);
		} while (!wbuf);
		wbuf->buff_len = 0;
		wbuf->tid = core->ctx->cpu;
		wbuf->fid = f_idx;
		core->w_buffer = wbuf;
	}
	
	len = vsnprintf(wbuf->buff + wbuf->buff_len, PRINT_LIMIT, _Format, argptr);
	wbuf->buff_len += len;
	pthread_mutex_unlock(&core->logger->mutex);

	va_end(argptr);

}
/*----------------------------------------------------------------------------*/
void
DumpPacket(core_ctx_t core, char *buf, int len, char *step, int ifindex)
{
	struct ethhdr *ethh;
	struct iphdr *iph;
	uint8_t *t;

	if (ifindex >= 0)
		thread_printf(core, core->log_fp, "%s %d %u", step, ifindex, core->cur_ts);
	else
		thread_printf(core, core->log_fp, "%s ? %u", step, core->cur_ts);

	ethh = (struct ethhdr *)buf;
	if (ntohs(ethh->h_proto) != ETH_P_IP) {
		thread_printf(core, core->log_fp, "%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ",
				ethh->h_source[0],
				ethh->h_source[1],
				ethh->h_source[2],
				ethh->h_source[3],
				ethh->h_source[4],
				ethh->h_source[5],
				ethh->h_dest[0],
				ethh->h_dest[1],
				ethh->h_dest[2],
				ethh->h_dest[3],
				ethh->h_dest[4],
				ethh->h_dest[5]);

		thread_printf(core, core->log_fp, "protocol %04hx  ", ntohs(ethh->h_proto));
		goto done;
	}

	thread_printf(core, core->log_fp, " ");

	iph = (struct iphdr *)(ethh + 1);
	t = (uint8_t *)&iph->saddr;
	thread_printf(core, core->log_fp, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);

	thread_printf(core, core->log_fp, " -> ");

	t = (uint8_t *)&iph->daddr;
	thread_printf(core, core->log_fp, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);

	thread_printf(core, core->log_fp, " IP_ID=%d", ntohs(iph->id));
	thread_printf(core, core->log_fp, " TTL=%d ", iph->ttl);

	if (ip_fast_csum(iph, iph->ihl)) {
		__sum16 org_csum, correct_csum;
		
		org_csum = iph->check;
		iph->check = 0;
		correct_csum = ip_fast_csum(iph, iph->ihl);
		thread_printf(core, core->log_fp, "(bad checksum %04x should be %04x) ",
				ntohs(org_csum), ntohs(correct_csum));
		iph->check = org_csum;
	}

	/* mTCP decodes the L4 header here — ports, flags, sequence, window.
	 * That is the program's knowledge, not this layer's, so the dump stops
	 * at IP. Increment 2 gives the program a dump hook; until then the
	 * protocol number is all this says, and PKTDUMP is off in every build
	 * anyone has measured. */
	thread_printf(core, core->log_fp, "protocol %d ", iph->protocol);
done:
	thread_printf(core, core->log_fp, "len=%d\n", len);
}
/*----------------------------------------------------------------------------*/
void
DumpIPPacket(core_ctx_t core, const struct iphdr *iph, int len)
{
	uint8_t *t;

	t = (uint8_t *)&iph->saddr;
	thread_printf(core, core->log_fp, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);

	thread_printf(core, core->log_fp, " -> ");

	t = (uint8_t *)&iph->daddr;
	thread_printf(core, core->log_fp, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);

	thread_printf(core, core->log_fp, " IP_ID=%d", ntohs(iph->id));
	thread_printf(core, core->log_fp, " TTL=%d ", iph->ttl);

	if (ip_fast_csum(iph, iph->ihl)) {
		thread_printf(core, core->log_fp, "(bad checksum) ");
	}

	/* mTCP decodes the L4 header here — ports, flags, sequence, window.
	 * That is the program's knowledge, not this layer's, so the dump stops
	 * at IP. Increment 2 gives the program a dump hook; until then the
	 * protocol number is all this says, and PKTDUMP is off in every build
	 * anyone has measured. */
	thread_printf(core, core->log_fp, "protocol %d ", iph->protocol);
	thread_printf(core, core->log_fp, "len=%d\n", len);
}
/*----------------------------------------------------------------------------*/
void
DumpIPPacketToFile(FILE *fout, const struct iphdr *iph, int len)
{
	uint8_t *t;

	t = (uint8_t *)&iph->saddr;
	fprintf(fout, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);

	fprintf(fout, " -> ");

	t = (uint8_t *)&iph->daddr;
	fprintf(fout, "%u.%u.%u.%u", t[0], t[1], t[2], t[3]);

	fprintf(fout, " IP_ID=%d", ntohs(iph->id));
	fprintf(fout, " TTL=%d ", iph->ttl);

	if (ip_fast_csum(iph, iph->ihl)) {
		fprintf(fout, "(bad checksum) ");
	}

	/* mTCP decodes the L4 header here — ports, flags, sequence, window.
	 * That is the program's knowledge, not this layer's, so the dump stops
	 * at IP. Increment 2 gives the program a dump hook; until then the
	 * protocol number is all this says, and PKTDUMP is off in every build
	 * anyone has measured. */
	fprintf(fout, "protocol %d ", iph->protocol);
	fprintf(fout, "len=%d\n", len);
}
