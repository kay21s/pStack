#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "bitmap.threaded.h"

#define BITSPERWORD 64
#define SHIFT 6
#define MASK 0x3F
#define BITMAP_SIZE (1 + MAX_STREAM / BITSPERWORD)

extern int number_of_cpus_used;

#if 0
#define WORD_FULL 0xFFFFFFFFFFFFFFFF

inline void set(int i, TCP_THREAD_LOCAL_P tcp_thread_local_p) { (tcp_thread_local_p->bitmap)[i>>SHIFT] |= ((uint64_t)1 << (i & MASK));}
inline void clr(int i, TCP_THREAD_LOCAL_P tcp_thread_local_p) { (tcp_thread_local_p->bitmap)[i>>SHIFT] &= ~((uint64_t)1 << (i & MASK));}
inline int test(int i, TCP_THREAD_LOCAL_P tcp_thread_local_p) { return (tcp_thread_local_p->bitmap)[i>>SHIFT] & ((uint64_t)1 << (i & MASK));}

void init_bitmap(TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	tcp_thread_local_p->bitmap_size = BITMAP_SIZE/(number_of_cpus_used - 1);
	tcp_thread_local_p->bitmap = calloc(tcp_thread_local_p->bitmap_size, sizeof(uint64_t));
	if (!tcp_thread_local_p->bitmap) {
		printf("Error allocating bitmap!\n");
		exit(0);
	}
	memset((void *)tcp_thread_local_p->bitmap, 0, tcp_thread_local_p->bitmap_size * 8);
}

// If a bit is 1, it represents that this block is in use
// if is 0, the block is free.
idx_type find_free_index(TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	uint32_t i, j;

	// FIXME: Can be optimized with a 2nd level bitmap
	for (i = 0; i < tcp_thread_local_p->bitmap_size; i ++) {
		// this word has no bits free, continue
		if ((tcp_thread_local_p->bitmap)[i] == WORD_FULL)
			continue;

		// find a bit is zero
#if defined(BUILTIN_FUNC)
		j = __builtin_ffsll(~((tcp_thread_local_p->bitmap)[i])) - 1;
		if (j >= 0)
			return (idx_type)(i * BITSPERWORD + j);
#else
		for (j = 0; j < BITSPERWORD; j ++) {
			if (!((tcp_thread_local_p->bitmap)[i] & (1 << j)))
				return (idx_type)(i * BITSPERWORD + j);
		}
#endif
	}

	printf("Run out of bits????? Too many connections?????\n");
	exit(0);
	return -1;
}
#else
#define WORD_FULL 0x0

inline void clr(int i, TCP_THREAD_LOCAL_P tcp_thread_local_p) { (tcp_thread_local_p->bitmap)[i>>SHIFT] |= ((uint64_t)1 << (i & MASK));}
inline void set(int i, TCP_THREAD_LOCAL_P tcp_thread_local_p) { (tcp_thread_local_p->bitmap)[i>>SHIFT] &= ~((uint64_t)1 << (i & MASK));}

void init_bitmap(TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	tcp_thread_local_p->bitmap_size = BITMAP_SIZE/(number_of_cpus_used - 1);
	tcp_thread_local_p->bitmap = calloc(tcp_thread_local_p->bitmap_size, sizeof(uint64_t));
	if (!tcp_thread_local_p->bitmap) {
		printf("Error allocating bitmap!\n");
		exit(0);
	}
	memset((void *)tcp_thread_local_p->bitmap, 0xFF, tcp_thread_local_p->bitmap_size * 8);
	tcp_thread_local_p->walker = -1;
}

// If a bit is 1, it represents that this block is in use
// if is 0, the block is free.
idx_type find_free_index(TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	uint32_t j;

	tcp_thread_local_p->walker ++;
	if (tcp_thread_local_p->walker == tcp_thread_local_p->bitmap_size)
		tcp_thread_local_p->walker = 0;

	int walker = tcp_thread_local_p->walker;

	// this word has no bits free, continue
	if ((tcp_thread_local_p->bitmap)[walker] == WORD_FULL) {
		printf("Run out of bits????? Too many connections?????\n");
		exit(0);
	}
	
	// find a bit is zero
	j = __builtin_ffsll((tcp_thread_local_p->bitmap)[walker]) - 1;
	if (j >= 0)
		return (idx_type)(walker * BITSPERWORD + j);

	printf("ERROR in find_free_index\n");
	exit(0);
}
#endif

idx_type get_free_index(TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	idx_type index;
	
	// Find a free index
	index = find_free_index(tcp_thread_local_p);

	// Mark as used in bitmap
	set(index, tcp_thread_local_p);

	return index;
}

void ret_free_index(idx_type index, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	// Mark as unused in bitmap
	clr(index, tcp_thread_local_p);
}
