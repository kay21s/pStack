#ifndef FIFO_COMMON_H
#define FIFO_COMMON_H

#include <stdint.h>

#define X86_FEATURE_XMM 	(0*32+25)
#define X86_FEATURE_3DNOW       (1*32+31) /* 3DNow! */
#define BASE_PREFETCH          "prefetcht0 (%1)"

#define alternative_input(oldinstr, newinstr, feature, input...)        \
	        asm volatile (newinstr: : "i" (0), ## input)

inline void prefetch0(const void *);

inline void prefetch1(const void *);

inline void prefetch2(const void *);

inline void prefetchnta(const void *);

inline void prefetchw(const void *);

inline uint64_t read_tsc();

inline void wait_ticks(uint64_t );

#endif
