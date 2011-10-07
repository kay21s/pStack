#ifndef CONN_ATTRI_H
#define CONN_ATTRI_H

#include <stdint.h>

#define CACHE_LINE_SIZE 64
#define PTR_SIZE 8
#define SET_SIZE CACHE_LINE_SIZE

#define MAX_STREAM 4000000

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

#define SET_ASSOCIATIVE 16 // 64/4

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
