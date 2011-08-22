/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#include <unistd.h>
#include <semaphore.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include "ulcc.h"
#include "remapper.h"
#include "mmclient.h"
#define _H_CACHE_INTERNAL_
#include "cache.h"
#undef _H_CACHE_INTERNAL_

/* The mapping of a cpu id to the id of llc it uses */
extern int cache_idx(int cid);		/* in arch.c */

/* Shared memory region for bookkeeping the status of each shared cache:
 * cache_status[ULCC_NUM_SHARED_CACHES]
 */
cc_cache_status_t *cache_status _ULCC_HIDDEN = MAP_FAILED;
sem_t *sem_cache_status _ULCC_HIDDEN = SEM_FAILED;

/* Shared memory region that bookkeeps the number of physical
 * pages currently mapped to each color
 */
unsigned long *busy_pages _ULCC_HIDDEN = MAP_FAILED;
sem_t *sem_busy_pages _ULCC_HIDDEN = SEM_FAILED;

/* In mmclient.h */
extern unsigned long *mm_free_pages _ULCC_HIDDEN;


/* Lock the shared cache_status structure
 */
int cache_status_lock(void)
{
	int		ret = 0;

	if(sem_cache_status == SEM_FAILED)
	{
		return -1;
	}
	
	while(sem_wait(sem_cache_status) == -1)
	{
		if(errno != EINTR)
		{
			ret = -1;
			break;
		}
	}

	return ret;
}

/* Unlock the shared cache_status structure
 */
int cache_status_unlock(void)
{
	if(sem_cache_status != SEM_FAILED)
	{
		return sem_post(sem_cache_status);
	}
	return -1;
}

/* Lock the shared stat_pages structure
 */
int busy_pages_lock(void)
{
	int		ret = 0;

	if(sem_busy_pages == SEM_FAILED)
	{
		return -1;
	}
	
	while(sem_wait(sem_busy_pages) == -1)
	{
		if(errno != EINTR)
		{
			ret = -1;
			break;
		}
	}

	return ret;
}

/* Unlock the shared stat_pages structure
 */
int busy_pages_unlock(void)
{
	if(sem_busy_pages != SEM_FAILED)
	{
		return sem_post(sem_busy_pages);
	}
	return -1;
}

/* Open the cache status shared memory region.
 * Lock before open cache status; otherwise, it is possible that one process
 * succeeded to open cache status shared mem w/ O_EXCL flag, but before it
 * completes initializing cache status, another process opens the shared mem
 * assuming the shared mem has being created and initialized. In this case,
 * the data read by the second process may be wrong and the data written by
 * the second process will be erased when the frist process initializes the
 * shared mem.
 */
int cache_status_open(void)
{
	int		shmfd, first_open = 0;
	int		ret = -1;

	if(cache_status_lock())
	{
		_ULCC_ERROR("lock cache_status failed");
		return ret;
	}

	if(cache_status != MAP_FAILED)
	{
		cache_status_unlock();
		_ULCC_ERROR("cache status already open");
		return ret;
	}

	shmfd = shm_open(ULCC_NAME_SHM_CACHE_STATUS, O_CREAT | O_RDWR | O_EXCL,
		ULCC_PRIV_SHM_CACHE_STATUS);
	if(shmfd != -1)
	{
		first_open = 1;
	}
	else
	{
		if(errno != EEXIST)
		{
			cache_status_unlock();
			_ULCC_ERROR("failed to open cache status w/ O_EXCL flag");
			return ret;
		}

		/* Open again w/o specifying O_EXCL flag */
		shmfd = shm_open(ULCC_NAME_SHM_CACHE_STATUS, O_CREAT | O_RDWR,
			ULCC_PRIV_SHM_CACHE_STATUS);
		if(shmfd == -1)
		{
			cache_status_unlock();
			_ULCC_ERROR("failed to open cache status w/o O_EXCL flag");
			return ret;
		}

		first_open = 0;
	}

	if(ftruncate(shmfd, sizeof(cc_cache_status_t) * ULCC_NUM_SHARED_CACHES) == -1)
	{
		close(shmfd);
		if(first_open)
		{
			/* If this is the first open, we have to unlink the shared mem to let
			 * other do the initialization work that must be done in the first open.
			 */
			shm_unlink(ULCC_NAME_SHM_CACHE_STATUS);
		}
		cache_status_unlock();
		_ULCC_ERROR("failed to truncate cache status");
		return ret;
	}

	cache_status = mmap((void *)0, sizeof(cc_cache_status_t) * ULCC_NUM_SHARED_CACHES,
		PROT_READ | PROT_WRITE, MAP_SHARED, shmfd, 0);
	if(cache_status == MAP_FAILED)
	{
		close(shmfd);
		if(first_open)
		{
			shm_unlink(ULCC_NAME_SHM_CACHE_STATUS);
		}
		cache_status_unlock();
		_ULCC_ERROR("failed to map cache status to local address");
		return ret;
	}

	/* Initialize cache status if this is the first open
	 * TODO: This can be neglected, because newly created shared memory is
	 * automatically initialized to all zeros and CC_UNSPECIFIED is defined
	 * to be zero.
	 */
	if(first_open)
	{
		int i, j;
		for(i = 0; i < ULCC_NUM_SHARED_CACHES; i++)
		{
			for(j = 0; j < ULCC_NUM_CACHE_COLORS; j++)
			{
				cache_status[i].type[j] = CC_UNSPECIFIED;
				cache_status[i].owner[j] = (pid_t)0;
				cache_status[i].count[j] = 0;
			}
		}
	}

	close(shmfd);
	cache_status_unlock();

	ret = 0;
	return ret;
}

void cache_status_close(void)
{
	cache_status_lock();

	munmap(cache_status, sizeof(cc_cache_status_t) * ULCC_NUM_SHARED_CACHES);
	cache_status = MAP_FAILED;

	cache_status_unlock();
}

int busy_pages_open(void)
{
	int		shmfd, first_open = 0;
	int		ret = -1;

	if(busy_pages_lock())
	{
		_ULCC_ERROR("lock busy_pages failed");
		return ret;
	}

	if(busy_pages != MAP_FAILED)
	{
		busy_pages_unlock();
		_ULCC_ERROR("page statistics already open");
		return ret;
	}

	shmfd = shm_open(ULCC_NAME_SHM_BUSY_PAGES, O_CREAT | O_RDWR | O_EXCL,
		ULCC_PRIV_SHM_BUSY_PAGES);
	if(shmfd != -1)
	{
		first_open = 1;
	}
	else
	{
		if(errno != EEXIST)
		{
			busy_pages_unlock();
			_ULCC_ERROR("failed to open busy pages w/ O_EXCL flag");
			return ret;
		}

		/* Open again w/o specifying O_EXCL flag */
		shmfd = shm_open(ULCC_NAME_SHM_BUSY_PAGES, O_CREAT | O_RDWR,
			ULCC_PRIV_SHM_BUSY_PAGES);
		if(shmfd == -1)
		{
			busy_pages_unlock();
			_ULCC_ERROR("failed to open busy pages w/o O_EXCL flag");
			return ret;
		}

		first_open = 0;
	}

	/* Truncate shared mem region to its right length */
	if(ftruncate(shmfd, sizeof(int) * ULCC_NUM_CACHE_COLORS) == -1)
	{
		close(shmfd);
		if(first_open)
		{
			shm_unlink(ULCC_NAME_SHM_BUSY_PAGES);
		}
		busy_pages_unlock();
		_ULCC_ERROR("failed to truncate busy pages");
		return ret;
	}

	/* Map shared mem to local virtual address space */
	busy_pages = mmap((void *)0, sizeof(int) * ULCC_NUM_CACHE_COLORS,
		PROT_READ | PROT_WRITE, MAP_SHARED, shmfd, 0);
	if(busy_pages == MAP_FAILED)
	{
		close(shmfd);
		if(first_open)
		{
			shm_unlink(ULCC_NAME_SHM_BUSY_PAGES);
		}
		busy_pages_unlock();
		_ULCC_ERROR("failed to map busy pages to local address");
		return ret;
	}

	/* Initialize page statistics if this is the first open
	 * TODO: This can be neglected, because a newly created shared mem contain
	 * all zeros
	 */
	if(first_open)
	{
		int i;
		for(i = 0; i < ULCC_NUM_CACHE_COLORS; i++)
		{
			busy_pages[i] = 0;
		}
	}

	close(shmfd);
	busy_pages_unlock();

	ret = 0;
	return ret;
}

void busy_pages_close(void)
{
	busy_pages_lock();

	munmap(busy_pages, sizeof(int) * ULCC_NUM_CACHE_COLORS);
	busy_pages = MAP_FAILED;

	busy_pages_unlock();
}

int cc_cache_init(void)
{
	int ret = 0;

	/* Open cache status structure */
	ret = cache_status_open();
	if(ret < 0)
	{
		return ret;
	}

	/* Open page statistics structure */
	ret = busy_pages_open();
	if(ret < 0)
	{
		cache_status_close();
	}

	return ret;
}

void cc_cache_fini(void)
{
	busy_pages_close();
	cache_status_close();
}

/* Get the cache indexes corresponding to an array of core ids.
 * It is guaranteed that on return array caidx contains unrepeated cache indexes,
 * and nca is set to the number of unique cache indexes in caidx.
 * Since each index in caidx will be unique, so the maximum size of caidx only
 * needs to be of ULCC_NUM_SHARED_CACHES integers.
 */
int cache_idx_array(const int *cpus, const int nc, int *caidx, int *nca)
{
	int		i, j, idx, c;

	c = 0;
	for(i = 0; i < nc; i++)
	{
		idx = cache_idx(cpus[i]);
		if(idx < 0)
		{
			return -1;
		}

		/* Whether this idx is already in caidx */
		for(j = 0; j < c; j++)
		{
			if(caidx[j] == idx)
			{
				break;
			}
		}
		if(j < c)	/* If this cache index is already in caidx */
		{
			continue;
		}

		caidx[c++] = idx;
	}
	
	*nca = c;
	return 0;
}

int busy_pages_add(const cc_cacheregn_t *regn, const int *c_pages)
{
	int		i, j;

	if(busy_pages_lock() < 0)
	{
		return -1;
	}

	for(i = 0, j = 0; i < ULCC_NUM_CACHE_COLORS; i++)
	{
		if(ULCC_TST_COLOR_BIT(regn, i))
		{
			busy_pages[i] += c_pages[j++];
		}
	}

	busy_pages_unlock();
	return 0;
}

int busy_pages_rm(const cc_cacheregn_t *regn, const int *c_pages)
{
	int		i, j;

	if(busy_pages_lock() < 0)
	{
		return -1;
	}

	for(i = 0, j = 0; i < ULCC_NUM_CACHE_COLORS; i++)
	{
		if(ULCC_TST_COLOR_BIT(regn, i))
		{
			busy_pages[i] -= c_pages[j++];
			/* In case of statistics error?? */
			if(busy_pages[i] < 0)
			{
				busy_pages[i] = 0;
			}
		}
	}

	busy_pages_unlock();
	return 0;
}

/* Reserve cache space on shared caches, caidx, and return the selected cache
 * region in `regn'. TODO: what if the maporder is RAND? Then the total number
 * of pages need to be larger than c_pages, and this is enough and will help
 * effectively use all colors.
 */
int cc_cache_rsv(const int size, const int type, const int *caidx, const int nca,
				 const int c_pages, cc_cacheregn_t *regn)
{
	int		c_colors, c_pages_per_color;
	int		usefp, ret = -1;

	/* How many colors are needed; rounded up to the nearest number of cache
	 * colors to cover size
	 */
	c_colors = (size % ULCC_CACHE_BYTES_PER_COLOR) ?
		(size / ULCC_CACHE_BYTES_PER_COLOR + 1) :
		(size / ULCC_CACHE_BYTES_PER_COLOR);
	if(c_colors <= 0)
	{
		_ULCC_ERROR("invalid cache slot size");
		return ret;
	}
	/* c_pages_per_color may be zero if c_pages is zero when the user only wants
	 * to reserve cache space w/o mapping data
	 */
	c_pages_per_color = (c_pages % c_colors) ? (c_pages / c_colors + 1) :
		(c_pages / c_colors);

	if(cache_status_lock() < 0)
	{
		_ULCC_ERROR("failed to lock cache status");
		return ret;
	}
	if(mm_free_pages_lock() < 0)
	{
		if(busy_pages_lock() < 0)
		{
			cache_status_unlock();
			_ULCC_ERROR("failed to lock either free_pages or busy_pages");
			return ret;
		}
		usefp = 0;	/* use busy_pages, not free_pages */
	}
	else
	{
		usefp = 1;	/* use busy_pages */
	}

	if(type == CC_SHARED)
	{
		ret = _cache_rsv_shared(caidx, nca, c_colors,
			c_pages_per_color, usefp, regn);
	}
	else if(type == CC_PRIVATE)
	{
		ret = _cache_rsv_private(caidx, nca, c_colors,
			c_pages_per_color, usefp, regn);
	}
	else
	{
		_ULCC_ERROR("unrecognized cache slot type");
	}

	if(usefp)
	{
		mm_free_pages_unlock();
	}
	else
	{
		busy_pages_unlock();
	}
	cache_status_unlock();

	return ret;
}

/* Since no two threads can be in cache_status critical region concurrently,
 * so the two data structures below can be reused across and by different
 * allocations. They are used by _cache_rsv_shared* and _cache_rsv_private*.
 */
/* Existing, already-allocated cache colors that are candidates to be reused for
 * current allocation
 */
int candidates_exist[ULCC_NUM_CACHE_COLORS] _ULCC_HIDDEN;
int i_sel_exist_start _ULCC_HIDDEN = 0;
int i_sel_exist_end _ULCC_HIDDEN = 0;
/* New, still-unallocated cache colors that are condidates to be used for
 * current allocation
 */
int candidates_new[ULCC_NUM_CACHE_COLORS] _ULCC_HIDDEN;
int i_sel_new_start _ULCC_HIDDEN = 0;
int i_sel_new_end _ULCC_HIDDEN = 0;

/* Question: how to allocate colors when user wants to reserve cache region w/o
 * instant mapping?
 * If the region is selected w/ too few available pages in each color, then
 * subsequent adding to this cache space may fail. A solution is to allow user
 * to pass flags that indicate what kind of cache region should be reserved.
 * User may also tell whether cache colors should be reserved even though the
 * number of avaialble pages in according colors is fewer than expected.
 */
int _cache_rsv_shared(const int *caidx, const int nca, const int c_colors,
						 const int c_pages_per_color, const int usefp,
						 cc_cacheregn_t *regn)
{
	int		n_selected = 0, ica, ico, i;
	int		ret = -1;

	if(usefp)
	{
		n_selected = _cache_rsv_shared_fp(caidx, nca, c_colors, c_pages_per_color);
	}
	else
	{
		n_selected = _cache_rsv_shared_bp(caidx, nca, c_colors, c_pages_per_color);
	}

	if(n_selected == c_colors)
	{
		/* Update cache status for newly selected colors */
		for(ica = 0; ica < nca; ica++)
		{
			for(ico = i_sel_exist_start; ico < i_sel_exist_end; ico++)
			{
				cache_status[caidx[ica]].count[candidates_exist[ico]]++;
			}

			for(ico = i_sel_new_start; ico < i_sel_new_end; ico++)
			{
				cache_status[caidx[ica]].type[candidates_new[ico]] = CC_SHARED;
				cache_status[caidx[ica]].count[candidates_new[ico]]++;
			}
		}

		/* Set selected cache region */
		for(i = i_sel_exist_start; i < i_sel_exist_end; i++)
		{
			ULCC_SET_COLOR_BIT(regn, candidates_exist[i]);
		}
		for(i = i_sel_new_start; i < i_sel_new_end; i++)
		{
			ULCC_SET_COLOR_BIT(regn, candidates_new[i]);
		}

		ret = 0;
	}

	return ret;
}

int _cache_rsv_shared_fp(const int *caidx, const int nca,
						 const int c_colors, const int c_pages_per_color)
{
	int		n_exist = 0, n_new = 0;
	int		n_shared, n_public;
	int		n_selected = 0;
	int		i, ico, ica;

	/* Get exsiting cache colors that are of `shared' type on each of the shared
	 * caches requested; these existing shared colors are candidate colors to be
	 * reused by this allocation. Meanwhile, also get cache colors that are not
	 * private (public) on any of the shared caches; these colors are candidate
	 * colors to be assigned `shared' for this allocation.
	 */
	for(ico = 0; ico < ULCC_NUM_CACHE_COLORS; ico++)
	{
		n_shared = 0;
		n_public = 0;

		for(ica = 0; ica < nca; ica++)
		{
			if(cache_status[caidx[ica]].type[ico] == CC_SHARED)
			{
				n_shared++;
			}
			if(cache_status[caidx[ica]].type[ico] != CC_PRIVATE)
			{
				n_public++;	/* Number of non-private colors */
			}
		}

		if(n_shared == nca)
		{
			candidates_exist[n_exist++] = ico;
		}
		else if(n_public == nca)
		{
			candidates_new[n_new++] = ico;
		}
	}

	i_sel_exist_start = 0;
	i_sel_exist_end = 0;
	i_sel_new_start = 0;
	i_sel_new_end = 0;

	/* Select from existing shared colors; selected colors will be in
	 * candidates_exist[i_sel_exist_start, i_sel_exist_end).
	 */
	if(n_exist > 0)
	{
		/* Sort color index in ascending order of the number of free pages */
		_sort_coidx(candidates_exist, n_exist, mm_free_pages);

		for(i = 0; i < n_exist; i++)
		{
			if(mm_free_pages[candidates_exist[i]] >= c_pages_per_color)
			{
				break;
			}
		}

		i_sel_exist_start = i;
		if(n_exist - i > c_colors - n_selected)
		{
			i_sel_exist_end = i_sel_exist_start + (c_colors - n_selected);
		}
		else
		{
			i_sel_exist_end = n_exist;
		}
		n_selected += i_sel_exist_end - i_sel_exist_start;
	}

	/* Select from new colors */
	if(n_selected < c_colors && n_new > 0)
	{
		_sort_coidx(candidates_new, n_new, mm_free_pages);

		for(i = 0; i < n_new; i++)
		{
			if(mm_free_pages[candidates_new[i]] >= c_pages_per_color)
			{
				break;
			}
		}

		i_sel_new_start = i;
		if(n_new - i > c_colors - n_selected)
		{
			i_sel_new_end = i_sel_new_start + (c_colors - n_selected);
		}
		else
		{
			i_sel_new_end = n_new;
		}
		n_selected += i_sel_new_end - i_sel_new_start;
	}

	return n_selected;
}

int _cache_rsv_shared_bp(const int *caidx, const int nca,
						 const int c_colors, const int c_pages_per_color)
{
	int		n_selected = 0;
	int		ico, ica;
	int		n_new = 0;

	/* Get cache colors that are not privateon any of the shared caches; these
	 * colors are candidate colors to be assigned to `shared' for this allocation.
	 * We use candidates_new to contain all candidate colors.
	 */
	for(ico = 0; ico < ULCC_NUM_CACHE_COLORS; ico++)
	{
		for(ica = 0; ica < nca; ica++)
		{
			if(cache_status[caidx[ica]].type[ico] == CC_PRIVATE)
			{
				break;
			}
		}

		if(ica == nca)
		{
			candidates_new[n_new++] = ico;
		}
	}

	i_sel_exist_start = 0;
	i_sel_exist_end = 0;
	i_sel_new_start = 0;
	i_sel_new_end = 0;

	if(n_new > 0)
	{
		_sort_coidx(candidates_new, n_new, busy_pages);

		/* Select the first c_colors colors w/ the least number of busy pages */
		if(n_new - i_sel_new_start > c_colors - n_selected)
		{
			i_sel_new_end = i_sel_new_start + (c_colors - n_selected);
		}
		else
		{
			i_sel_new_end = n_new;
		}
		n_selected += i_sel_new_end - i_sel_new_start;
	}

	return n_selected;


}

int _cache_rsv_private(const int *caidx, const int nca, const int c_colors,
						  const int c_pages_per_color, const int usefp,
						  cc_cacheregn_t *regn)
{
	int			i_sel_start = 0, i_sel_end = 0;
	int			i, ico, ica;
	int			n_new = 0;
	int			ret = -1;
	pid_t		pid;

	/* Get cache colors that are unspecified on each of the shared caches; these
	 * colors are candidate colors to be assigned to private colors for this
	 * allocation.
	 */
	for(ico = 0; ico < ULCC_NUM_CACHE_COLORS; ico++)
	{
		for(ica = 0; ica < nca; ica++)
		{
			if(cache_status[caidx[ica]].type[ico] != CC_UNSPECIFIED)
			{
				break;
			}
		}

		if(ica >= nca)
		{
			candidates_new[n_new++] = ico;
		}
	}
	if(n_new < c_colors)
	{
		return ret;
	}

	if(usefp)
	{
		_sort_coidx(candidates_new, n_new, mm_free_pages);

		for(i = 0; i < n_new; i++)
		{
			if(mm_free_pages[candidates_new[i]] >= c_pages_per_color)
			{
				break;
			}
		}
		if(n_new - i < c_colors)
		{
			return ret;
		}

		i_sel_start = i;
		i_sel_end = i_sel_start + c_colors;
	}
	else
	{
		_sort_coidx(candidates_new, n_new, busy_pages);
		i_sel_start = 0;
		i_sel_end = i_sel_start + c_colors;
	}

	/* Update cache status for newly selected colors */
	pid = getpid();
	for(ica = 0; ica < nca; ica++)
	{
		for(ico = i_sel_start; ico < i_sel_end; ico++)
		{
			cache_status[ica].type[candidates_new[ico]] = CC_PRIVATE;
			cache_status[ica].owner[candidates_new[ico]] = pid;
			cache_status[ica].count[candidates_new[ico]]++;
		}
	}

	/* Set selected cache region */
	for(ico = i_sel_start; ico < i_sel_end; ico++)
	{
		ULCC_SET_COLOR_BIT(regn, candidates_new[ico]);
	}

	ret = 0;
	return ret;
}

int _partition(int *sort, int p, int r, const unsigned long *ref)
{
	unsigned long	x = ref[sort[r]];      /* pivot */
	int				i = p - 1, j;
	int				temp;

	for(j = p; j < r; j++)
	{
		if(ref[sort[j]] <= x)
		{
			i++;
			temp = sort[i];
			sort[i] = sort[j];
			sort[j] = temp;
		}
	}

	i++;
	temp = sort[i];
	sort[i] = sort[r];
	sort[r] = temp;

	return i;
}

/* Sort elements sort[p:r] w/ key values referenced to ref */
void _quick_sort(int *sort, int p, int r, const unsigned long *ref)
{
	/* quick sort (inner) */
	if(p < r)
	{
		int q = _partition(sort, p, r, ref);
		_quick_sort(sort, p, q - 1, ref);
		_quick_sort(sort, q + 1, r, ref);
	}
}

/* Sort cache color index according to free_pages or busy_pages associated
 * w/ each color in ascending order.
 */
void _sort_coidx(int *sort, const int nsort, const unsigned long *ref)
{
	_quick_sort(sort, 0, nsort - 1, ref);
}

int cc_cache_rel(const int *caidx, const int nca, const cc_cacheregn_t *regn)
{
	int		ico, ica;

	if(cache_status_lock() < 0)
	{
		_ULCC_ERROR("failed to lock cache status");
		return -1;
	}

	for(ico = 0; ico < ULCC_NUM_CACHE_COLORS; ico++)
	{
		if(ULCC_TST_COLOR_BIT(regn, ico))
		{
			for(ica = 0; ica < nca; ica++)
			{
				if((--cache_status[ica].count[ico]) <= 0)
				{
					cache_status[ica].type[ico] = CC_UNSPECIFIED;
					cache_status[ica].owner[ico] = (pid_t)0;
					cache_status[ica].count[ico] = 0;
				}
			}
		}
	}

	cache_status_unlock();

	return 0;
}
