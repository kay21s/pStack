#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "bitmap.h"

#define BITSPERWORD 64
#define SHIFT 6
#define MASK 0x3F
#define BITMAP_SIZE (1 + MAX_STREAM / BITSPERWORD)

uint64_t bitmap[BITMAP_SIZE];

extern int tcp_num;

#if 0
#define WORD_FULL 0xFFFFFFFFFFFFFFFF
inline void set(int i) { bitmap[i>>SHIFT] |= ((uint64_t)1 << (i & MASK));}
inline void clr(int i) { bitmap[i>>SHIFT] &= ~((uint64_t)1 << (i & MASK));}
inline int test(int i) { return bitmap[i>>SHIFT] & ((uint64_t)1 << (i & MASK));}

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
#else

#define WORD_FULL 0x0

inline void clr(int i) { bitmap[i>>SHIFT] |= ((uint64_t)1 << (i & MASK));}
inline void set(int i) { bitmap[i>>SHIFT] &= ~((uint64_t)1 << (i & MASK));}

void init_bitmap(void)
{
	memset((void *)bitmap, 0xFF, BITMAP_SIZE * 8);
}

// If a bit is 0, it represents that this block is in use
// if is 1, the block is free.
idx_type find_free_index()
{
	uint32_t j;

	static uint32_t walker = -1;
	walker ++;
	if (walker == BITMAP_SIZE)
		walker = 0;

	// this word has no bits free, continue
	// FIXME: It's not right to declare all bits are allocated
	// Just do it here since the probability is very low =)
	if (bitmap[walker] == WORD_FULL) {
		printf("Run out of bits????? Too many connections?????\n");
		exit(0);
	}

	// find a bit is zero
	j = __builtin_ffsll(bitmap[walker]) - 1;
	if (j >= 0)
		return (idx_type)(walker * BITSPERWORD + j);

	printf("ERROR in find_free_index\n");
	exit(0);
}
#endif

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
