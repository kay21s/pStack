#ifndef CONN_ATTRI_H
#define CONN_ATTRI_H

#include <stdint.h>

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
#define CACHE_LINE_SIZE 64
#define PTR_SIZE 8
#define ELEM_SIZE 8
#define SET_ASSOCIATIVE ((CACHE_LINE_SIZE-PTR_SIZE)/ELEM_SIZE)
#define SET_SIZE CACHE_LINE_SIZE

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

#endif
