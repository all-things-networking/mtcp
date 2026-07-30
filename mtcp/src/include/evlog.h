#ifndef EVLOG_H
#define EVLOG_H
/* Per-event tracing, emitted identically by both stacks so their event streams
 * can be diffed line-for-line to locate a behavioural divergence.
 *
 * Inert unless EVLOG_PATH is set in the environment, so instrumented binaries
 * are safe to benchmark; EVLOG_MAX caps the line count (default 200k) to keep
 * a debug run from filling the disk. Every hook site emits
 *
 *     <n> <us_since_init> <KIND> <key=value>...
 *
 * with the counter and clock shared across translation units, so ordering
 * between the receive path and the send path is meaningful.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

extern FILE          *g_evlog;
extern long           g_evlog_n;
extern long           g_evlog_max;
extern struct timeval g_evlog_t0;

void evlog_init(void);

static inline long
evlog_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec - g_evlog_t0.tv_sec) * 1000000L +
	       (tv.tv_usec - g_evlog_t0.tv_usec);
}

#define EVLOG(fmt, ...) do {                                    \
	if (g_evlog && g_evlog_n < g_evlog_max)                     \
		fprintf(g_evlog, "%ld %ld " fmt "\n",                   \
		        g_evlog_n++, evlog_us(), ##__VA_ARGS__);        \
} while (0)

#endif /* EVLOG_H */
