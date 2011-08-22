/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License, as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#include <stdlib.h>
#include "ulcc.h"
#include "remapper.h"
#include "registry.h"
#include "cache.h"
#include "allocator.h"

int cc_allocator_init(void)
{
	/* Link to global shared cache status memory */
	if(cc_cache_init() < 0)
	{
		_ULCC_ERROR("failed to initialize cache status and page statistics");
		return -1;
	}

	/* Initialize local per-process allocation registry */
	if(cc_reg_init() < 0)
	{
		_ULCC_ERROR("failed to initialize local per-process registry");
		cc_cache_fini();
		return -1;
	}

	return 0;
}

void cc_allocator_fini(void)
{
	cc_reg_fini();
	cc_cache_fini();
}

cc_aid_t cc_do_alloc(const unsigned long *start, const unsigned long *end,
					 const int ndr, const int *cpus, const int nc,
					 const int cs_size, const int cs_type,
					 int flags)
{
	int				caidx[ULCC_NUM_SHARED_CACHES], nca;
	cc_aid_t		aid = CC_AID_INVALID;
	int				*new_pages = NULL;
	cc_cacheregn_t	regn;
	int				i;

	if(cpus && nc > 0)
	{
		/* Convert cpu ids to cache indexes */
		if(cache_idx_array(cpus, nc, caidx, &nca) < 0)
		{
			return CC_AID_INVALID;
		}
		if(nca <= 0)
		{
			return aid;
		}
	}
	else
	{
		/* Set all shared caches to be covered by this allocation */
		for(i = 0; i < ULCC_NUM_SHARED_CACHES; i++)
		{
			caidx[i] = i;
		}
		nca = ULCC_NUM_SHARED_CACHES;
	}

	/* Reserve cache space for this allocation */
	cc_cacheregn_clr(&regn);
	if(cc_cache_rsv(cs_size, cs_type, caidx, nca,
		num_aligned_pages(start, end, ndr), &regn) < 0)
	{
		_ULCC_ERROR("cc_do_alloc: failed to reserve cache space");
		return aid;
	}

	/* Remap physical pages in reserved cache space to the data set */
	if(start && end && ndr > 0)
	{
		new_pages = (int *)malloc(sizeof(int) * cc_cacheregn_cnt(&regn));
		if(!new_pages)
		{
			_ULCC_ERROR("cc_do_alloc: malloc failed for new_pages array");
			cc_cache_rel(caidx, nca, &regn);
			return aid;
		}

		/* On return, new_pages store how many pages selected in each color */
		if(cc_remap(start, end, ndr, &regn, flags, new_pages) < 0)
		{
			_ULCC_ERROR("cc_do_alloc: cc_remap error");
			cc_cache_rel(caidx, nca, &regn);
			ULCC_FREE(new_pages);
			return aid;
		}

		/* Update busy_pages statistics */
		if(busy_pages_add(&regn, new_pages) < 0)
		{
			_ULCC_ERROR("data set has been remapped, but busy pages update failed");
			cc_cache_rel(caidx, nca, &regn);
			ULCC_FREE(new_pages);
			return aid;
		}
	}

	/* Insert a new entry into the per-process, allocation registry */
	if(start && end && ndr > 0)
	{
		aid = cc_reg_push(start, end, ndr, caidx, nca, &regn, new_pages);
	}
	else
	{
		aid = cc_reg_push((void *)0, (void *)0, 0, caidx, nca, &regn, (void *)0);
	}
	if(aid == CC_AID_INVALID)
	{
		_ULCC_ERROR("this is awkward: data set has been remapped, "
			"but failed to add it to local registry");
		busy_pages_rm(&regn, new_pages);
		cc_cache_rel(caidx, nca, &regn);
	}

	ULCC_FREE(new_pages);
	return aid;
}

int cc_do_alloc_add(const cc_aid_t aid, const unsigned long *start,
					const unsigned long *end, const int ndr, int flags)
{
	void			*new_start, *new_end;
	int				*new_pages = NULL;
	int				i, c_colors;
	cc_cacheregn_t	regn;
	cc_regent_t		*ent;

	if(cc_reg_lock() < 0)
	{
		return -1;
	}

	ent = cc_reg_get(aid);
	if(!ent)	/* not found */
	{
		cc_reg_unlock();
		return -1;
	}
	/* Get cache region allocated */
	regn = ent->regn;

	cc_reg_unlock();

	c_colors = cc_cacheregn_cnt(&regn);
	new_pages = malloc(sizeof(int) * c_colors);
	if(!new_pages)
	{
		_ULCC_ERROR("do_alloc_add: malloc failed for new_pages array");
		return -1;
	}

	if(cc_remap(start, end, ndr, &regn, flags, new_pages) < 0)
	{
		_ULCC_ERROR("do_alloc_add: cc_remap error");
		ULCC_FREE(new_pages);
		return -1;
	}

	if(busy_pages_add(&regn, new_pages) < 0)
	{
		_ULCC_ERROR("do_alloc_add: but busy pages update failed");
		ULCC_FREE(new_pages);
		return -1;
	}

	cc_reg_lock();

	/* Let's assume ent is still there, but this is not safe ~~~
	 * Merge two lock regions into one?
	 */
	new_start = realloc(ent->start, sizeof(unsigned long) * (ent->ndr + ndr));
	if(!new_start)
	{
		cc_reg_unlock();
		_ULCC_ERROR("realloc error for new start addr array");
		busy_pages_rm(&regn, new_pages);
		ULCC_FREE(new_pages);
		return -1;
	}
	ent->start = new_start;
	new_end = realloc(ent->end, sizeof(unsigned long) * (ent->ndr + ndr));
	if(!new_end)
	{
		cc_reg_unlock();
		_ULCC_ERROR("realloc error for new end addr array");
		busy_pages_rm(&regn, new_pages);
		ULCC_FREE(new_pages);
		return -1;
	}
	ent->end = new_end;

	for(i = 0; i < ndr; i++)
	{
		ent->start[ent->ndr + i] = start[i];
		ent->end[ent->ndr + i] = end[i];
	}
	ent->ndr += ndr;

	for(i = 0; i < c_colors; i++)
	{
		ent->c_pages[i] += new_pages[i];
	}

	cc_reg_unlock();

	ULCC_FREE(new_pages);
	return 0;
}

int cc_do_dealloc(const cc_aid_t aid)
{
	cc_regent_t *ent;

	if(cc_reg_lock() < 0)
	{
		return -1;
	}
	ent = cc_reg_rm(aid);
	cc_reg_unlock();

	if(!ent)
	{
		return -1;
	}

	busy_pages_rm(&(ent->regn), ent->c_pages);
	cc_cache_rel(ent->caidx, ent->nca, &(ent->regn));
	cc_regent_free(ent);

	return 0;
}

/* Get the number of aligned whole pages in a set of data regions
 */
int num_aligned_pages(const unsigned long *start, const unsigned long *end,
					  const int ndr)
{
	int				c_pages = 0, i;
	unsigned long	s, e;

	for(i = 0; i < ndr; i++)
	{
		s = ULCC_ALIGN_HIGHER(start[i]);
		e = ULCC_ALIGN_LOWER(end[i]);
		if(e > s)
		{
			c_pages += (e - s) / ULCC_PAGE_BYTES;
		}
	}

	return c_pages;
}
