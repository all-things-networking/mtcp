#ifndef CPU_H
#define CPU_H

inline int GetNumCPUs();

inline int whichCoreID(int thread_no);

/* from mTCP mtcp_api.h, where it sits because the socket API exposes it. It is
 * defined in cpu.c and belongs with the rest of the CPU handling. */
int core_affinitize(int cpu);

#endif /* CPU_H */
