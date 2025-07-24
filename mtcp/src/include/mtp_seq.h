#ifndef MTP_SEQ_H
#define MTP_SEQ_H

#include <stdint.h>
#include <stdbool.h>

inline bool MTP_SEQ_LT (uint32_t a, uint32_t b, uint32_t h);

inline bool MTP_SEQ_GT (uint32_t a, uint32_t b, uint32_t h);

inline int32_t MTP_SEQ_SUB (uint32_t a, uint32_t b, uint32_t h);

#endif
