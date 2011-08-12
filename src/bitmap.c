#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "bitmap.h"

#define BITSPERWORD 64
#define SHIFT 6
#define MASK 0x3F
#define BITMAP_SIZE (1 + MAX_STREAM / BITSPERWORD)
#define WORD_FULL 0xFFFFFFFFFFFFFFFF

uint64_t bitmap[BITMAP_SIZE];

extern int tcp_num;

inline void set(int i) { uint64_t a = 1; bitmap[i>>SHIFT] |= (a << (i & MASK));}
inline void clr(int i) { uint64_t a = 1; bitmap[i>>SHIFT] &= ~(a << (i & MASK));}
inline int test(int i) { uint64_t a = 1; return bitmap[i>>SHIFT] & (a << (i & MASK));}

void init_bitmap(void)
{
	memset((void *)bitmap, 0, BITMAP_SIZE * 8);
}

// If a bit is 1, it represents that this block is in use
// if is 0, the block is free.
idx_type find_free_index()
{
	uint32_t i, j;

	// FIXME: Can be optimized with a 2nd level bitmap
	for (i = 0; i < BITMAP_SIZE; i ++) {
		// this word has no bits free, continue
		if (bitmap[i] == WORD_FULL)
			continue;

		// find a bit is zero
#if defined(BUILTIN_FUNC)
		j = __builtin_ffsll(~bitmap[i]) - 1;
		if (j >= 0)
			return (idx_type)(i * BITSPERWORD + j);
#else
		for (j = 0; j < BITSPERWORD; j ++) {
			if (!(bitmap[i] & (1 << j)))
				return (idx_type)(i * BITSPERWORD + j);
		}
#endif
	}

	printf("Run out of bits????? Too many connections?????\n");
	printf("Current TCP number : %d\n", tcp_num);
	exit(0);
	return -1;
}

idx_type get_free_index()
{
	idx_type index;
	
	// Find a free index
	index = find_free_index();

	// Mark as used in bitmap
	set(index);

	return index;
}

void ret_free_index(idx_type index)
{
	// Mark as unused in bitmap
	clr(index);
}
