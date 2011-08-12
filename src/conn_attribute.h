#ifndef CONN_ATTRI_H
#define CONN_ATTRI_H

#include <stdint.h>

#define CACHE_LINE_SIZE 64
#define PTR_SIZE 8
#define SET_SIZE CACHE_LINE_SIZE

#if defined(INDEXFREE_TCP)
// 14-way set associative, only store signature in cache table
// TCB index is the same as the signature (hash_index, pos in line)
// |      14 signature      |  ptr  |

typedef uint32_t idx_type;
typedef uint32_t sig_type;
typedef struct {
	sig_type signature;
} elem_type;

typedef struct ll_type {
	elem_type elem;
	idx_type index;
	struct ll_type *next;
} elem_list_type;

#define MAX_STREAM 1500000 // Note that this should be larger than CACHE_ELEM_NUM in indexfree version
#define SET_ASSOCIATIVE 14 // (64-8)/4

#elif defined(MAJOR_INDEXFREE_TCP)
// 16-way set associative, only store signature in cache table
// TCB index is the same as the signature (hash_index, pos in line)
// ptr for conflict is not stored in the cacheline, and is stored separately
// |        16 signature        |  ... |  ptr  |

typedef uint32_t idx_type;
typedef uint32_t sig_type;
typedef struct {
	sig_type signature;
} elem_type;

typedef struct ll_type {
	elem_type elem;
	idx_type index;
	struct ll_type *next;
} elem_list_type;

#define MAX_STREAM 1500000
#define SET_ASSOCIATIVE 16 // 64/4

#elif defined(COMPACT_TABLE)
// 8-way set associative, store index separately in 3 bytes(24 bits)
// |   8 signature    |   8 tcb index  | ptr  |

typedef uint32_t idx_type;
typedef uint32_t sig_type;
typedef struct {
	sig_type signature;
} elem_type;

typedef struct ll_type {
	elem_type elem;
	idx_type index;
	struct ll_type *next;
} elem_list_type;

#define MAX_STREAM (1 << 20)
#define SET_ASSOCIATIVE 8 // (64-8)/(4+3)

#define INDEX_OFFSET 32 // 8 way-associative, 4 bytes for each signature
#define INDEX_SIZE 3 // 24 bits/3 bytes for a index, since one million flow only needs 20 bits

#else
// 7-way set associative, the original version, element is (signature, index)
// |    8  two-tuple (signature, index)  | ptr  |

typedef uint32_t idx_type;
typedef uint32_t sig_type;
typedef struct {
	sig_type signature;
	idx_type index;
} elem_type;

typedef struct ll_type {
	elem_type elem;
	struct ll_type *next;
} elem_list_type;

#define MAX_STREAM (1 << 20)
#define SET_ASSOCIATIVE 7 // (64-8)/8

#endif

#define FIN_SENT 120
#define FIN_CONFIRMED 121
#define COLLECT_cc 1
#define COLLECT_sc 2
#define COLLECT_ccu 4
#define COLLECT_scu 8


inline sig_type calc_signature(const uint32_t, const uint32_t, const uint16_t, const uint16_t);
inline int sig_match_e(const sig_type, const elem_type *);
inline int sig_match_l(const sig_type, const elem_list_type *);
inline idx_type index_e(const elem_type *);
inline idx_type index_l(const elem_list_type *);
inline idx_type get_cached_index(const void *, const int);
inline void store_cached_index(const void *, const int, const idx_type);

#endif
