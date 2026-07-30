#ifndef EVLOG_H
#define EVLOG_H
/* Per-event tracing, emitted identically by both stacks so their event streams
 * can be diffed line-for-line to locate a behavioural divergence.
 *
 * Inert unless EVLOG_PATH is set in the environment, so instrumented binaries
 * are safe to benchmark. Every hook site emits
 *
 *     <n> <us_since_init> <KIND> <key=value>...
 *
 * with the counter and clock shared across translation units, so ordering
 * between the receive path and the send path is meaningful.
 *
 * Two modes:
 *   stream (default)    append every line, up to EVLOG_MAX lines.
 *   ring (EVLOG_RING=N) keep only the last N lines in memory, written out on
 *                       SIGUSR1. This is the mode for diagnosing a stall: the
 *                       interesting events are the last ones before traffic
 *                       stops, which a forward-filling log never reaches.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

extern int            g_evlog_on;
extern long           g_evlog_n;
extern struct timeval g_evlog_t0;

void evlog_init(void);
void evlog_emit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static inline long
evlog_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec - g_evlog_t0.tv_sec) * 1000000L +
	       (tv.tv_usec - g_evlog_t0.tv_usec);
}

#define EVLOG(fmt, ...) do {                    \
	if (g_evlog_on)                             \
		evlog_emit(fmt, ##__VA_ARGS__);         \
} while (0)

#endif /* EVLOG_H */
