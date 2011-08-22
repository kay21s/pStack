/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#include <semaphore.h>
#include <stdlib.h>
#include <errno.h>
#include "ulcc.h"
#include "remapper.h"
#include "registry.h"
#include "cache.h"

/* Next alloc id available */
cc_aid_t next_aid _ULCC_HIDDEN = 0;

/* Bookkeeping of currently registered allocation */
cc_registry_t reg_alloc _ULCC_HIDDEN =
{
	.n_entries = 0,
	.head = NULL,
};

/* Lock for registry operations */
sem_t _ULCC_HIDDEN sem_reg;


/* A simple return of next alloc id.
 * TODO: This needs to be modifed in case the aid rounds up and overlaps w/
 * still-alive aids.
 */
cc_aid_t _next_aid(void)
{
	cc_aid_t		aid;

	aid = next_aid;
	next_aid = (next_aid + 1) % _ULCC_MAX_AID;

	return aid;
}

int cc_reg_init(void)
{
	int ret = 0;

	if(cc_reg_lock() < 0)
	{
		return -1;
	}

	if(reg_alloc.n_entries != 0 || reg_alloc.head)
	{
		_ULCC_ERROR("per-process registry has already been initialized");
		ret = -1;
	}

	cc_reg_unlock();
	return ret;
}

void cc_reg_fini(void)
{
	cc_regent_t		*ent;

	if(cc_reg_lock() < 0)
	{
		return;
	}

	ent = reg_alloc.head;
	while(ent)
	{
		reg_alloc.head = ent->next;
		busy_pages_rm(&(ent->regn), ent->c_pages);
		cc_cache_rel(ent->caidx, ent->nca, &(ent->regn));
		cc_regent_free(ent);
		ent = reg_alloc.head;
	}
	reg_alloc.n_entries = 0;

	cc_reg_unlock();
}

cc_regent_t *cc_regent_new(const unsigned long *start, const unsigned long *end,
						   const int ndr, const int *caidx, const int nca,
						   const cc_cacheregn_t *regn, const int *new_pages)
{
	cc_regent_t		*p;
	int				i;

	p = malloc(sizeof(cc_regent_t));
	if(!p)
	{
		_ULCC_ERROR("malloc error for a new registry entry structure");
		return NULL;
	}

	if(start)
	{
		p->start = malloc(sizeof(unsigned long) * ndr);
		if(!p->start)
		{
			_ULCC_ERROR("malloc error for a new start addr array");
			ULCC_FREE(p);
			return NULL;
		}
	}
	else
	{
		p->start = NULL;
	}

	if(end)
	{
		p->end = malloc(sizeof(unsigned long) * ndr);
		if(!p->end)
		{
			_ULCC_ERROR("malloc error for a new end addr array");
			ULCC_FREE(p->start);
			ULCC_FREE(p);
			return NULL;
		}
	}
	else
	{
		p->end = NULL;
	}

	p->caidx = malloc(sizeof(int) * nca);
	if(!p->caidx)
	{
		_ULCC_ERROR("malloc error for a new cache index array");
		ULCC_FREE(p->end);
		ULCC_FREE(p->start);
		ULCC_FREE(p);
		return NULL;
	}

	p->c_colors = 0;
	for(i = 0; i < ULCC_NUM_CACHE_COLORS; i++)
	{
		if(ULCC_TST_COLOR_BIT(regn, i))
		{
			p->c_colors++;
		}
	}
	p->c_pages = malloc(sizeof(int) * p->c_colors);
	if(!p->c_pages)
	{
		_ULCC_ERROR("malloc error for a new pages array");
		ULCC_FREE(p->caidx);
		ULCC_FREE(p->end);
		ULCC_FREE(p->start);
		ULCC_FREE(p);
		return NULL;
	}
	if(new_pages)
	{
		for(i = 0; i < p->c_colors; i++)
		{
			p->c_pages[i] = new_pages[i];
		}
	}
	else
	{
		for(i = 0; i < p->c_colors; i++)
		{
			p->c_pages[i] = 0;
		}
	}

	for(i = 0; i < ndr; i++)
	{
		p->start[i] = start[i];
		p->end[i] = end[i];
	}
	p->ndr = ndr;

	for(i = 0; i < nca; i++)
	{
		p->caidx[i] = caidx[i];
	}
	p->nca = nca;
	p->regn = *regn;

	p->next = NULL;
	p->prev = NULL;

	return p;
}

void cc_regent_free(cc_regent_t *ent)
{
	ULCC_FREE(ent->c_pages);
	ULCC_FREE(ent->caidx);
	ULCC_FREE(ent->end);
	ULCC_FREE(ent->start);
	ULCC_FREE(ent);
}

cc_aid_t cc_reg_push(const unsigned long *start, const unsigned long *end,
					 const int ndr, const int *caidx, const int nca,
					 const cc_cacheregn_t *regn, const int *new_pages)
{
	cc_aid_t		aid = CC_AID_INVALID;
	cc_regent_t		*new_ent;

	new_ent = cc_regent_new(start, end, ndr, caidx, nca, regn, new_pages);
	if(!new_ent)
	{
		return aid;
	}

	if(cc_reg_lock() < 0)
	{
		cc_regent_free(new_ent);
		return aid;
	}

	/* Get a allocation id for this new entry */
	aid = _next_aid();
	new_ent->aid = aid;

	/* Add this new entry to the head of the registry */
	if(reg_alloc.head)
	{
		reg_alloc.head->prev = new_ent;
		new_ent->next = reg_alloc.head;
	}
	reg_alloc.head = new_ent;
	reg_alloc.n_entries++;

	cc_reg_unlock();

	return aid;
}

cc_regent_t *cc_reg_rm(cc_aid_t aid)
{
	cc_regent_t		*ent;

	ent = reg_alloc.head;
	while(ent)
	{
		if(ent->aid == aid)
		{
			break;
		}
		ent = ent->next;
	}

	if(ent)
	{
		if(ent->prev)
		{
			ent->prev->next = ent->next;
		}
		if(ent->next)
		{
			ent->next->prev = ent->prev;
		}
		if(ent == reg_alloc.head)
		{
			reg_alloc.head = ent->next;
		}
		reg_alloc.n_entries--;
	}

	return ent;
}

/* Search for registry entry by allocation id.
 * It is assumed that the registry has been locked before calling this function.
 */
cc_regent_t *cc_reg_get(const cc_aid_t aid)
{
	cc_regent_t		*ent;

	ent = reg_alloc.head;
	while(ent)
	{
		if(ent->aid == aid)
		{
			break;
		}
		ent = ent->next;
	}

	return ent;
}

int cc_reg_lock(void)
{
	int ret = 0;

	while(sem_wait(&sem_reg) == -1)
	{
		if(errno != EINTR)
		{
			ret = -1;
			break;
		}
	}

	return ret;
}

int cc_reg_unlock(void)
{
	return sem_post(&sem_reg);
}
