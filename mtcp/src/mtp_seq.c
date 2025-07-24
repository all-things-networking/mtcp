#include "mtp_seq.h"

inline bool MTP_SEQ_LT (uint32_t a, uint32_t b, uint32_t h) {
    return (a >= h && b >= h && a < b) 
           || (a >= h && b < h) 
           || (a < h && b < h && a < b);    
}

inline bool MTP_SEQ_GT (uint32_t a, uint32_t b, uint32_t h) {
    return (a >= h && b >= h && a > b) 
           || (a < h && b >= h) 
           || (a < h && b < h && a > b);    
}

inline int32_t MTP_SEQ_SUB (uint32_t a, uint32_t b, uint32_t h) {
    if (a >= h && b >= h) return a - b;
    if (a >= h && b < h) return -((UINT32_MAX - a) + b);
    if (a < h && b >= h) return (UINT32_MAX - b) + a;
    // case: a < h && b < h
    else return a - b;
}