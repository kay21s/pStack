#include "arch.h"


/* PLEASE EDIT this list with the real parameters on your own machine. For
 * example, on a machine with 8 CPUs whose ids are from 0 to 7 and each pair
 * of CPUs share a last level cache, the Linux kernel may assign ids {0, 1},
 * {2, 3}, {4, 5}, {6, 7} to CPUs sharing the same cache. Or, it is also possible
 * that the kernel assigns {0, 4}, {1, 5}, {2, 6}, {3, 7} to CPUs sharing the same
 * cache. The user should edit this function to make sure the mapping is correct.
 */
int cache_to_cpus[ULCC_NUM_SHARED_CACHES][ULCC_NUM_CPUS_PER_CACHE] =
{
	/* For example, on our INTEL Core i5 machine with Linux 3.6.35 kernel,
	 * the array looks like this (2 SMT threads on each of the two cores): */
	{0, 1, 2, 3}
};

/* You DON'T need to change this function */
int cache_idx(int cid)
{
	int		i, j;

	for(i = 0; i < ULCC_NUM_SHARED_CACHES; i++)
	{
		for(j = 0; j < ULCC_NUM_CPUS_PER_CACHE; j++)
		{
			if(cache_to_cpus[i][j] == cid)
			{
				return i;
			}
		}
	}

	return -1;
}
