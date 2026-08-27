/*
 * The instrumentation residue — hand-written, and deliberately small.
 *
 * docs/DESIGN-COMPILER.md §6: the compiler generates no instrumentation, the
 * hand-written program stays on `mtp-dpdk-rebuild` as the instrumented build,
 * and this is everything the SHIPPING build owes the target so that it links.
 *
 * `prog_sample_inflight` and `prog_dump_flow_state` are already declared weak in
 * src/target/internal.h, so absent is a legal answer for them and they are not
 * here. The seven reporters are called unconditionally from the end-of-run
 * summary in scheduler.c, so they have to exist.
 *
 * A build made from this file REPORTS NOTHING, and that is the correct answer
 * rather than a gap: a measurement build and a shipping build stop being the
 * same binary by accident, which is D-03's rule applied to our own program.
 */
void prog_report_refusals(void) { }
void prog_report_avail(void)    { }
void prog_report_rtt(void)      { }
void prog_report_recv(void)     { }
void prog_report_acklat(void)   { }
void prog_report_inflight(void) { }
void prog_report_stages(void)   { }
