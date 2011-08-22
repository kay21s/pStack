/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#define _GNU_SOURCE
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sched.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "ulcc.h"
#include "allocator.h"
#include "remapper.h"
#include "cache.h"
#include "memmgr.h"
#include "mmclient.h"
#include "translator.h"

/* In cache.c */
extern sem_t *sem_cache_status _ULCC_HIDDEN;
extern sem_t *sem_busy_pages _ULCC_HIDDEN;
/* In mmclient.c */
extern sem_t *sem_mm_free_pages _ULCC_HIDDEN;
/* In registry.c */
extern sem_t sem_reg _ULCC_HIDDEN;

/* ULCC library constructor
 */
void _ULCC_HIDDEN __attribute ((constructor))
__cc_libinit(void)
{
	sem_cache_status = sem_open(ULCC_NAME_SEM_CACHE_STATUS, O_CREAT,
		ULCC_PRIV_SEM_CACHE_STATUS, 1);
	if(sem_cache_status == SEM_FAILED)
	{
		_ULCC_ERROR("sem_open error for cache status");
	}

	sem_busy_pages = sem_open(ULCC_NAME_SEM_BUSY_PAGES, O_CREAT,
		ULCC_PRIV_SEM_BUSY_PAGES, 1);
	if(sem_busy_pages == SEM_FAILED)
	{
		_ULCC_ERROR("sem_open error for busy_pages statistics");
	}

	sem_mm_free_pages = sem_open(ULCC_NAME_SEM_MM_FREE_PAGES, 0);

	if(sem_init(&sem_reg, 0, 1) == -1)
	{
		_ULCC_ERROR("sem_init error for sem_reg");
	}
}

/* ULCC library destructor
 */
void _ULCC_HIDDEN __attribute ((destructor))
__cc_libfini(void)
{
	cc_allocator_fini();
	cc_mmclient_fini();

	sem_close(sem_mm_free_pages);
	sem_mm_free_pages = SEM_FAILED;
	sem_close(sem_busy_pages);
	sem_busy_pages = SEM_FAILED;
	sem_close(sem_cache_status);
	sem_cache_status = SEM_FAILED;
}


int cc_init(void)
{
	if(cc_allocator_init() < 0)
	{
		_ULCC_ERROR("failed to initialize cache allocator");
		return -1;
	}

	if(cc_mmclient_init() < 0)
	{
		_ULCC_ERROR("mmclient_init error");
	}

	return 0;
}

void cc_fini(void)
{
	cc_allocator_fini();
	cc_mmclient_fini();
}

/* Allocate a cache space for a data set. The virtual memory regions specified
 * in this data set will be accessed by a set of threads, and the requirement
 * on the cache space is denoted by a cache slot. The parameter flags is passed
 * to the remapping component.
 *
 * (1) If tst is NULL, it means these virtual memory regions are accessed by all
 * threads in the caller process. To ensure the caches considered by cache
 * allocator are actually those used by the related threads / process, the user
 * should normally have set the CPU affinity for the threads / process before
 * calling this function.
 * (2) If cs is NULL, it means the virtual memory regions should be set
 * uncacheable. In this case, tst and flags are ignored. A more direct way to
 * set a set of virtual memory regions uncacheable is to call cc_set_uc().
 *
 * Return value:
 * If cs is not NULL, the function returns the id of the allocation on success,
 * and returns CC_AID_INVALID on failure;
 * If cs is NULL, the function returns CC_AID_INVALID on failure, and returns a
 * value other than CC_AID_INVALID on success.
 */
cc_aid_t cc_alloc(const cc_dataset_t *dst, const cc_thrdset_t *tst,
				  const cc_cacheslot_t *cs, int flags)
{
	cc_aid_t		aid = CC_AID_INVALID;
	cc_cpuset_t		cst;

	CPU_ZERO(&cst);

	if(!tst || tst->t_count == 0)
	{
		if(cc_cpuset_proc(&cst, getpid()) < 0)
		{
			_ULCC_ERROR("failed to retrieve the cpu set of this process");
			return aid;
		}
	}
	else
	{
		if(cc_cpuset_from_thrdset(&cst, tst))
		{
			_ULCC_ERROR("failed to construct cpu set from thread set");
			return aid;
		}
	}

	aid = cc_alloc_cpus(dst, &cst, cs, flags);

	return aid;
}

/* Allocate a cache space for a data set accessed from a set of CPUs. The cache
 * space requirement is specified by a cache slot.
 *
 * (1) If cst is NULL, it means the data set is accessed from all CPUs.
 * (2) If cs is NULL, it means the data set should be set uncacheable. In this
 * case, cst and flags are ignored. A more direct way to make a set of data
 * regions uncacheable is to use cc_set_uc().
 * (3) If dst is NULL, the cache space will be reserved w/o doing any page
 * remapping; the user may call cc_alloc_add to add data sets later.
 *
 * Return value:
 * If cs is not NULL, the function returns the id of the allocation on success,
 * and returns CC_AID_INVALID on failure;
 * If cs is NULL, the function returns CC_AID_INVALID on failure, and returns a
 * value other than CC_AID_INVALID on success.
 */
cc_aid_t cc_alloc_cpus(const cc_dataset_t *dst, const cc_cpuset_t *cst,
						const cc_cacheslot_t *cs, int flags)
{
	int			*cpus = NULL, num_cpus = 0;
	int			i, j;
	cc_aid_t	aid;

	if(!cs)
	{
		/* Set uncacheable */
		for(i = 0; i < dst->d_count; i++)
		{
			if(cc_set_uc(dst->d_start[i], dst->d_end[i], 1) < 0)
			{
				aid = CC_AID_INVALID;
				break;
			}
		}
		/* If set uncacheable failed, try to rewind to cacheable */
		if(i < dst->d_count)
		{
			while(i > 0)
			{
				i--;
				cc_set_uc(dst->d_start[i], dst->d_end[i], 0);
			}
		}
		else
		{
			aid = CC_AID_INVALID + 1;
		}
	}
	else
	{
		if(cst)
		{
			num_cpus = cc_cpuset_count(cst);
			if(num_cpus > 0)
			{
				cpus = malloc(sizeof(int) * num_cpus);
				if(!cpus)
				{
					aid = CC_AID_INVALID;
					return aid;
				}
				for(i = 0, j = 0; i < num_cpus; j++)
				{
					if(CPU_ISSET(j, cst))
					{
						cpus[i++] = j;
					}
				}
			}
		}
		aid = cc_do_alloc(
			dst ? dst->d_start : NULL,
			dst ? dst->d_end : NULL,
			dst ? dst->d_count : 0,
			cpus, num_cpus,
			cs->s_size, cs->s_type,
			flags);
		ULCC_FREE(cpus);
	}

	return aid;
}

/* Add a new data set to an existing allocation
 */
cc_aid_t cc_alloc_add(const cc_aid_t aid, const cc_dataset_t *dst, int flags)
{
	if(cc_do_alloc_add(aid, dst->d_start, dst->d_end, dst->d_count, flags) < 0)
	{
		return CC_AID_INVALID;
	}
	else
	{
		return aid;
	}
}

int cc_dealloc(const cc_aid_t aid)
{
	return cc_do_dealloc(aid);
}

cc_aid_t cc_alloc2(const unsigned long start, const unsigned long end,
				   const cc_thrdset_t *tst, const cc_cacheslot_t *cs,
				   int flags)
{
	cc_dataset_t	*dst = NULL;
	cc_aid_t		aid;

	if(start != 0 && end != 0)
	{
		dst = cc_dataset_new(1);
		if(!dst)
		{
			return CC_AID_INVALID;
		}
		cc_dataset_add(dst, start, end);
	}

	aid = cc_alloc(dst, tst, cs, flags);

	if(dst)
	{
		cc_dataset_free(dst);
	}

	return aid;
}

cc_aid_t cc_alloc2_cpus(const unsigned long start, const unsigned long end,
						const cc_cpuset_t *cst, const cc_cacheslot_t *cs,
						int flags)
{
	cc_dataset_t	*dst = NULL;
	cc_aid_t		aid;

	if(start != 0 && end != 0)
	{
		dst = cc_dataset_new(1);
		if(!dst)
		{
			return CC_AID_INVALID;
		}
		cc_dataset_add(dst, start, end);
	}

	aid = cc_alloc_cpus(dst, cst, cs, flags);

	if(dst)
	{
		cc_dataset_free(dst);
	}

	return aid;
}

cc_aid_t cc_alloc_add2(const cc_aid_t aid, const unsigned long start,
					   const unsigned long end, int flags)
{
	if(cc_do_alloc_add(aid, &start, &end, 1, flags) < 0)
	{
		return CC_AID_INVALID;
	}
	else
	{
		return aid;
	}
}

/* Set a data region uncacheable (when uc == 1) or cacheable (when uc == 0).
 * Now only support setting `uncacheable'. The physical pages will become
 * cacheable again after the data set is freed by the user.
 */
#define _SET_UC_BATCH_SIZE		128
int cc_set_uc(const unsigned long start, const unsigned long end, const int uc)
{
#ifdef _ULCC_CONFIG_SETUC_MMAP	/* If this back door is still open */

	unsigned long	start_aligned, end_aligned;
	cc_uint64_t		pfnbuf[_SET_UC_BATCH_SIZE];
	int				i, j, c_pages, n_batch;
	int				fm;

	/* We don't consider setting a memory region cacheable now */
	if(uc == 0)
	{
		return -1;
	}

	start_aligned = ULCC_ALIGN_HIGHER(start);
	end_aligned = ULCC_ALIGN_LOWER(end);
	c_pages = (end_aligned - start_aligned) / ULCC_PAGE_BYTES;

	fm = open("/dev/mem", O_RDWR | O_SYNC);
	if(fm == -1)
	{
		_ULCC_ERROR("failed to open /dev/mem for setting uncacheable");
		return -1;
	}

	for(i = 0; i < c_pages; i += _SET_UC_BATCH_SIZE)
	{
		n_batch = ULCC_MIN(c_pages - i, _SET_UC_BATCH_SIZE);

		if(cc_addr_translate(pfnbuf, start_aligned + i * ULCC_PAGE_BYTES,
			n_batch) < 0)
		{
			_ULCC_ERROR("cc_set_uc: address translation error");
			close(fm);
			return -1;
		}

		for(j = 0; j < n_batch; j++)
		{
			/* set uncachable */
			if(mmap((void *)(start_aligned + (i + j) * ULCC_PAGE_BYTES),
				ULCC_PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
				fm, pfnbuf[j] << ULCC_PAGE_BITS) == MAP_FAILED)
			{
				_ULCC_ERROR("failed to use mmap to set uncacheable in PAT");
				close(fm);
				return -1;
			}
		}
	}

	close(fm);
	return 0;

#else

	return -1;

#endif
}
