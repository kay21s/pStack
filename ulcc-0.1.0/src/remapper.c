/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include "ulcc.h"
#include "memmgr.h"
#include "mmclient.h"
#include "allocator.h"
#include "translator.h"
#include "kmodules/pagepipe.h"
#define _H_REMAPPER_INTERNAL_
#include "remapper.h"
#undef _H_REMAPPER_INTERNAL_
#include "cache.h"

/* Remap a set of data regions to physical pages in desired colors
 * TODO: Optimizations
 * 1. pages already in desired regn don't need to be remapped again;
 * ... ...
 */
int cc_remap(const unsigned long *start, const unsigned long *end, const int n,
			 const cc_cacheregn_t *regn, const int flags, int *new_pages)
{
	int						c_pages, c_colors, c_pages_per_color;
	int						maporder, i, j;
	int						pick_ret, ret = -1;
	struct _page_picker_s	*picker;
	struct _vm_list_s		*vml;

	maporder = flags & CC_MASK_MAPORDER;

	/* Get the number of aligned pages to be remapped */
	c_pages = num_aligned_pages(start, end, n);
	if(c_pages <= 0)
	{
		_ULCC_ERROR("no aligned whole pages to be remapped in the data regions");
		return ret;
	}

	/* Get the number of page colors and maximum number of pages per color */
	c_colors = cc_cacheregn_cnt(regn);
	if(c_colors <= 0)
	{
		return ret;
	}
	c_pages_per_color = (c_pages % c_colors) ? (c_pages / c_colors + 1) :
		(c_pages / c_colors);

	/* Create a vm list to store the vm regions malloced for page picking */
	vml = _vm_list_new();
	if(!vml)
	{
		return ret;
	}

	picker = _page_picker_new(c_pages, c_pages_per_color, regn, maporder);
	if(!picker)
	{
		_vm_list_free(vml);
		return ret;
	}

	/* Pick pages in requested page colors */
#ifdef _ULCC_CONFIG_KMODULE_PAGEPIPE	/* Use pagepipe to pass pages */
	pick_ret = _pick_pages_pagepipe(picker, vml, c_pages, c_colors,
		c_pages_per_color, maporder);
#else	/* Pass pages w/o pagepipe */
	pick_ret = _pick_pages_nopipe(picker, vml, c_pages, c_colors,
		c_pages_per_color, maporder);
#endif

	if(pick_ret == 0)
	{
		/* Set the number of pages picked in each color */
		if(new_pages)
		{
			for(i = 0, j = 0; i < ULCC_NUM_CACHE_COLORS; i++)
			{
				if(ULCC_TST_COLOR_BIT(regn, i))
				{
					new_pages[j++] = picker[i].picked;
				}
			}
		}

		/* Remap data regions to picked physical pages */
		ret = _remap_pages(picker, start, end, n, flags);
	}

	_page_picker_free(picker);
	_vm_list_free(vml);

	return ret;
}

struct _vm_list_node_s *_vm_list_node_new()
{
	struct _vm_list_node_s		*p;

	p = malloc(sizeof(struct _vm_list_node_s));
	if(!p)
	{
		return (void *)0;
	}

	p->mem = malloc(sizeof(void *) * VM_LIST_NODE_SIZE);
	if(!p->mem)
	{
		free(p);
		return NULL;
	}

	p->count = 0;
	p->max = VM_LIST_NODE_SIZE;
	p->next = NULL;

	return p;
}

void _vm_list_node_free(struct _vm_list_node_s *node)
{
	int		i;

	for(i = 0; i < node->count; i++)
	{
		free(node->mem[i]);
	}

	free(node->mem);
	free(node);
}

struct _vm_list_s *_vm_list_new()
{
	struct _vm_list_s	*p;

	p = malloc(sizeof(struct _vm_list_s));
	if(!p)
	{
		return NULL;
	}

	p->head = _vm_list_node_new();
	if(!p->head)
	{
		free(p);
		return NULL;
	}

	return p;
}

int _vm_list_add(struct _vm_list_s *list, void *m)
{
	int		ret = 0;

	if(list->head->count < list->head->max)
	{
		list->head->mem[list->head->count++] = m;
	}
	else
	{
		struct _vm_list_node_s *p = _vm_list_node_new();
		if(!p)
		{
			ret = -1;
		}
		else
		{
			p->next = list->head;
			p->mem[p->count++] = m;
			list->head = p;
		}
	}

	return ret;
}

void _vm_list_free(struct _vm_list_s *list)
{
	struct _vm_list_node_s	*p, *q;

	p = list->head;
	while(p)
	{
		q = p->next;
		_vm_list_node_free(p);
		p = q;
	}

	free(list);
}

/* Create and initialize a new page picker structure
 */
struct _page_picker_s *_page_picker_new(const int c_pages,
										const int c_pages_per_color,
										const cc_cacheregn_t *regn,
										const int maporder)
{
	struct _page_picker_s	*p;
	int						i;

	/* Create a new page picker array */
	p = malloc(ULCC_NUM_CACHE_COLORS * sizeof(struct _page_picker_s));
	if(!p)
	{
		return p;
	}

	/* Initialize page picker structures */
	for(i = 0; i < ULCC_NUM_CACHE_COLORS; i++)
	{
		p[i].picked = 0;

		if(ULCC_TST_COLOR_BIT(regn, i))
		{
			/* For CC_MAPORDER_ARB, max indicates whether this color is
			 * requested; otherwise, max is the maximum	number of pages needed
			 * in this color.
			 */
			p[i].needed = c_pages_per_color;

			/* For CC_MAPORDER_ARB, only p[0].pages is needed, so set pages to
			 * NULL here temporarily;
			 */
			if(maporder == CC_MAPORDER_ARB)
			{
				p[i].pages = NULL;
			}
			/* otherwise, p[i].pages is the container for all pages to be
			 * picked up in this color.
			 */
			else
			{
				p[i].pages = malloc(sizeof(void *) * p[i].needed);
				if(!p[i].pages)
				{
					break;
				}
			}
		}
		else
		{
			p[i].needed = 0;
			p[i].pages = NULL;
		}
	}

	/* If initialization for non-arb map orders failed */
	if(i < ULCC_NUM_CACHE_COLORS)
	{
		/* Delete all previously allocated pages regions */
		while(i >= 0)
		{
			if(p[i].pages)
			{
				free(p[i].pages);
			}
			i--;
		}

		free(p);
		p = NULL;
	}
	else
	{
		/* Set up page pickup container for CC_MAPORDER_ARB */
		if(maporder == CC_MAPORDER_ARB)
		{
			p[0].pages = malloc(sizeof(void *) * c_pages);
			if(!p[0].pages)
			{
				free(p);
				p = NULL;
			}
		}
	}

	return p;
}

/* Destroy a page picker structure */
void _page_picker_free(struct _page_picker_s *picker)
{
	int		i;

	for(i = 0; i < ULCC_NUM_CACHE_COLORS; i++)
	{
		if(picker[i].pages)
		{
			free(picker[i].pages);
		}
	}

	free(picker);
}

#ifdef _ULCC_CONFIG_KMODULE_PAGEPIPE	/* TODO */
/* TODO: ulcc client, memory manager and pagepipe must consider the case when
there're not enough pages in a color in memory manager. the client must be able
to know how mnay pages are actually put in the pagepipe. */
int _pick_pages_pagepipe(struct _page_picker_s *picker, struct _vm_list_s *vml,
						 const int c_pages, const int c_colors,
						 const int c_pages_per_color, const int maporder)
{
	int				*index, i, i_color, i_loop, n_max_loop;
	int				c_pages_picked = 0, c_pages_per_loop;
	void			*mem, *mem_aligned;
	unsigned long	pipeid, key;
	cc_uint64_t		*pfnbuf;
	int				fid, ret = 0;

	pfnbuf = malloc(sizeof(cc_uint64_t) * ULCC_MAX_PAGES_PER_LOOP);
	if(!pfnbuf)
	{
		return -1;
	}

	fid = open(ULCC_PATH_PAGEPIPE, O_RDWR);
	if(fid != -1)
	{
		key = _new_pagepipe_key();
		pipeid = ioctl(fid, IOCTL_SETUP_PIPE, key);
		if(pipeid < 0)
		{
			close(fid);
			fid = -1;
		}
	}

	if(use_memmgr(c_colors, c_pages_per_color) && fid != -1)
	{
		/* Build index array for requested page colors */
		index = malloc(sizeof(int) * (c_colors + 1));
		if(!index)
		{
			close(fid);
			free(pfnbuf);
			return -1;
		}
		for(i = 0, i_color = 0; i < ULCC_NUM_CACHE_COLORS; i++)
		{
			if(picker[i].max)
			{
				index[i_color++] = i;
			}
		}
		_ULCC_ASSERT(i_color == c_colors);
		index[i_color] = -1;	/* This flag indicates the start of picking w/o
								 * the help of memmgr */
	}
	else
	{
		index = (int *)malloc(sizeof(int));
		if(!index)
		{
			return -1;
		}

		index[0] = -1;
	}

	i_color = 0;
	i_loop = 0;
	n_max_loop = max_pick_loops(c_pages, c_colors);	/* How many loops at most */

	/* Page allocation and picking loop, possibly w/ the help of memmgr in the
	 * first few loops
	 */
	while(c_pages_picked < c_pages && i_loop < n_max_loop)
	{
		/* Compute the number of pages to malloc in the next loop */
		if(index[i_color] != -1)
		{
			c_pages_per_loop = picker[index[i_color]].max -
				picker[index[i_color]].picked;
			i_color++;

			/* Send a request to memory manager for c_pages_per_loop pages in color
			 * index[i_color]. If the first parameter is -1, it will do nothing.
			 * TODO: what if there're not enough pages in the color, and the
			 * memory manager put less than expected number of pages in the pipe?
			 * what will happen if the client triggers page faults beyond what
			 * can be provided?
			 */
			cc_mm_sndreq(index[i_color], c_pages_per_loop, pipeid, key);

			mem_aligned = mmap(NULL, ULCC_PAGE_BYTES * c_pages_per_loop,
				PROT_READ | PROT_WRITE, MAP_SHARED, fid, 0);
			if(mem == MAP_FAILED)
			{
				ret = -1;
				break;
			}
			for(i = 0; i < c_pages_per_loop; i++)
			{
				/* Enforce physical page allocation */
				*(char *)(mem_aligned + i * ULCC_PAGE_SIZE) = 'x';
				/* mem_lock() ?? */
			}
		}
		else
		{
			c_pages_per_loop = next_pages_per_loop(-1, c_pages - c_pages_picked);
		}

		/* Immediately malloc a vm region and enforce physical page allocation,
		trying to capture the pages just released by the memmgr */
		if(!mem)
		{
			/* We don't have to free vm regions already malloced;
			vmh destroyer will take care of it in caller's routine. */
			ret = -1;
			break;
		}
		mem_aligned = ULCC_ALIGN_HIGHER(mem);

		/* Add this vm region to vm list */
		if(_cc_vm_list_add(vml, mem) < 0)
		{
			free(mem);	/* It was not added to the list, so free it here */
			ret = -1;
			break;
		}

		/* Translate virtual page addresses in this new virtual memory region
		to their physical page numbers */
		if(cc_addr_translate(pfnbuf, mem_aligned, c_pages_per_loop) < 0)
		{
			ret = -1;
			break;
		}

		/* Check and pick out pages in desired colors */
		if(maporder == CC_MAPORDER_ARB)
		{
			for(i = 0; i < c_pages_per_loop; i++)
			{
				/* If this physical page is present and its color is among what we need */
				if(cc_pfn_present(pfnbuf[i]) && picker[cc_pfn_color(pfnbuf[i])].max)
				{
					picker[0].pages[c_pages_picked++] = mem_aligned + i * ULCC_PAGE_SIZE;
					picker[cc_pfn_color(pfnbuf[i])].n_picked++;
					if(c_pages_picked >= c_pages)
					{
						break;
					}
				}
			}
		}
		else
		{
			for(i = 0; i < c_pages_per_loop; i++)
			{
				/* If this physical page is present, its color is among what we need,
				and we still need more pages in this color */
				if(cc_pfn_present(pfnbuf[i]) &&
					picker[cc_pfn_color(pfnbuf[i])].n_picked < picker[cc_pfn_color(pfnbuf[i])].max)
				{
					picker[cc_pfn_color(pfnbuf[i])].pages[picker[cc_pfn_color(pfnbuf[i])].n_picked++] =
						mem_aligned + i * ULCC_PAGE_SIZE;
					if((++c_pages_picked) >= c_pages)
					{
						break;
					}
				}
			}
		}

		i_loop++;
	} /* while */

	/* If loop exited due to too many loops */
	if(i_loop >= n_max_loop)
	{
		ret = -1;
	}

	if(fid != -1)
	{
		close(fid);
	}
	free(index);
	free(pfnbuf);
	return ret;
}

#else

int _pick_pages_nopipe(struct _page_picker_s *picker, struct _vm_list_s *vml,
					   const int c_pages, const int c_colors,
					   const int c_pages_per_color, const int maporder)
{
	int				*index, i, i_color, i_loop, n_max_loop;
	int				c_pages_picked = 0, c_pages_per_loop;
	void			*mem, *mem_aligned;
	cc_uint64_t		*pfnbuf;
	int				pfcolor, ret = 0;

	pfnbuf = malloc(sizeof(cc_uint64_t) * MAX_PAGES_PER_LOOP);
	if(!pfnbuf)
	{
		return -1;
	}

	/* Depending on the number of page colors and the number of pages in each
	 * color requested, see whether the help of memory manager is needed. If
	 * yes, we pick out pages with memmgr's help first; if not, we pick out
	 * pages directly on our own. Memory manager is not available when memory
	 * manager daemon process is not started.
	 */
	if(use_memmgr(c_colors, c_pages_per_color))
	{
		/* Build index array for requested page colors */
		index = malloc(sizeof(int) * (c_colors + 1));
		if(!index)
		{
			return -1;
		}
		for(i = 0, i_color = 0; i < ULCC_NUM_CACHE_COLORS; i++)
		{
			if(picker[i].needed)
			{
				index[i_color++] = i;
			}
		}
		_ULCC_ASSERT(i_color == c_colors);
		index[i_color] = -1;	/* Mark the start of picking w/o memmgr */
	}
	else
	{
		index = (int *)malloc(sizeof(int));
		if(!index)
		{
			return -1;
		}

		index[0] = -1;
	}

	i_color = 0;
	i_loop = 0;
	n_max_loop = max_pick_loops(c_pages, c_colors);
	/* Page allocation and picking loop, possibly w/ the help of memmgr in the
	 * first few loops
	 */
	while(c_pages_picked < c_pages && i_loop < n_max_loop)
	{
		c_pages_per_loop = next_pages_per_loop(index[i_color],
			index[i_color] != -1 ?
			picker[index[i_color]].needed - picker[index[i_color]].picked :
			c_pages - c_pages_picked);
		if(!c_pages_per_loop)
		{
			i_color++;
			continue;
		}

		/* Send a request to memory manager for c_pages_per_loop pages in color
		 * index[i_color].
		 */
		if(index[i_color] != -1)
		{
			cc_mm_sndreq(index[i_color], c_pages_per_loop);
		}

		/* Immediately malloc a vm region and enforce physical page allocation,
		trying to capture the pages just released by the memmgr */
		mem = malloc(ULCC_PAGE_BYTES * (c_pages_per_loop + 1));
		if(!mem)
		{
			/* We don't have to free vm regions already malloced;
			vmh destroyer will take care of it in caller's routine. */
			ret = -1;
			break;
		}
		mem_aligned = (void *)ULCC_ALIGN_HIGHER((unsigned long)mem);
		for(i = 0; i < c_pages_per_loop; i++)
		{
			/* Enforce physical page allocation by writing a byte into the page */
			*(char *)(mem_aligned + i * ULCC_PAGE_BYTES) = 'x';
			/* mem_lock() ?? */
		}

		/* Add this vm region to vm list */
		if(_vm_list_add(vml, mem) < 0)
		{
			free(mem);	/* It was not added to the list; so free it here */
			ret = -1;
			break;
		}

		/* Translate virtual page addresses in this new virtual memory region
		to their physical page numbers */
		if(cc_addr_translate(pfnbuf, (unsigned long)mem_aligned,
			c_pages_per_loop) < 0)
		{
			ret = -1;
			break;
		}

		/* Check and pick out pages in desired colors */
		if(maporder == CC_MAPORDER_ARB)
		{
			for(i = 0; i < c_pages_per_loop; i++)
			{
				pfcolor = cc_pfn_color(pfnbuf[i]);
				/* If present and its color is among what we need */
				if(cc_pfn_present(pfnbuf[i]) && picker[pfcolor].needed > 0)
				{
					picker[0].pages[c_pages_picked++] =
						mem_aligned + i * ULCC_PAGE_BYTES;
					picker[pfcolor].picked++;
					if(c_pages_picked >= c_pages)
					{
						break;
					}
				}
			}
		}
		else
		{
			for(i = 0; i < c_pages_per_loop; i++)
			{
				pfcolor = cc_pfn_color(pfnbuf[i]);
				/* If present, its color is among what we need and we still
				need more pages in this color */
				if(cc_pfn_present(pfnbuf[i]) &&
					picker[pfcolor].picked < picker[pfcolor].needed)
				{
					picker[pfcolor].pages[picker[pfcolor].picked++] =
						mem_aligned + i * ULCC_PAGE_BYTES;
					if((++c_pages_picked) >= c_pages)
					{
						break;
					}
				}
			}
		}

		i_loop++;
	} /* while */

	/* If loop exited due to too many loops */
	if(i_loop >= n_max_loop)
	{
		ret = -1;
	}

	free(index);
	free(pfnbuf);
	return ret;
}
#endif

/* Remap user data regions to picked physical pages.
 */
int _remap_pages(struct _page_picker_s *picker,
					const unsigned long *start, const unsigned long *end,
					const int n, int flags)
{
	int		maporder, movedata;
	int		ret = 0;

	maporder = flags & CC_MASK_MAPORDER;
	if((flags & CC_MASK_MOVE) == CC_ALLOC_MOVE)
	{
		movedata = 1;
	}
	else
	{
		movedata = 0;
	}

	/* Sequential mapping */
	if(maporder == CC_MAPORDER_SEQ)
	{
		ret = _remap_pages_seq(picker, start, end, n, movedata);
	}
	/* Random mapping */
	else if(maporder == CC_MAPORDER_RAND)
	{
		ret = _remap_pages_rand(picker, start, end, n, movedata);
	}
	/* Arbitrary mapping */
	else if(maporder == CC_MAPORDER_ARB)
	{
		ret = _remap_pages_arb(picker, start, end, n, movedata);
	}
	/* Unknown mapping */
	else
	{
		ret = -1;
	}

	return ret;
}

int _remap_pages_seq(struct _page_picker_s *picker,
						const unsigned long *start, const unsigned long *end,
						const int n, const int movedata)
{
	void		*remap_to, *remap_to_end, *remap_from;
	int			index[ULCC_NUM_CACHE_COLORS];
	int			c_colors = 0, cont = 1;
	int			idr, ii, i;
	int			ret = 0;

	/* Compute the number of colors in this request and build index array */
	for(i = 0, ii = 0; i < ULCC_NUM_CACHE_COLORS; i++)
	{
		if(picker[i].needed > 0)
		{
			c_colors++;
			index[ii++] = i;
		}
	}
	_ULCC_ASSERT(c_colors > 0);

	/* For each data region */
	for(idr = 0, ii = 0; idr < n; idr++)
	{
		remap_to = (void *)ULCC_ALIGN_HIGHER(start[idr]);
		remap_to_end = (void *)ULCC_ALIGN_LOWER(end[idr]);

		/* Remap a picked page to each page in this data region */
		while(remap_to < remap_to_end)
		{
			/* Get the next picked page to remap from.
			 * Infinite looping is guaranteed not to happen as long as the total
			 * amount of picked pages is not fewer than required, which is true
			 * after _cc_pick_pages successfully returned.
			 */
			while(picker[index[ii]].picked == 0)
			{
				ii = (ii + 1) % c_colors;
			}
			/* Select page to remap from from TAIL to HEAD of the pages list
			 * TODO: A possible problem to remap from tail to head is that the
			 * number of continuous physical pages in the virtual memory area
			 * being remapped to will decrease. Consider to remap from head to
			 * tail.
			 */
			remap_from = picker[index[ii]].pages[--picker[index[ii]].picked];

			/* Copy data before remapping */
			if(movedata)
			{
				memcpy(remap_from, remap_to, ULCC_PAGE_BYTES);
			}

			/* Remap the picked physical page to user data region */
			if(mremap(remap_from, ULCC_PAGE_BYTES, ULCC_PAGE_BYTES,
				MREMAP_MAYMOVE | MREMAP_FIXED, remap_to) == MAP_FAILED)
			{
				cont = 0;
				ret = -1;
				break;
			}

			/* Repair the page hole caused by the above remapping */
			if(mmap(remap_from, ULCC_PAGE_BYTES, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0, 0) != remap_from)
			{
				cont = 0;
				ret = -1;
				break;
			}

			remap_to += ULCC_PAGE_BYTES;
			ii = (ii + 1) % c_colors;
		} /* while */

		if(!cont)
		{
			break;
		}
	} /* for each data region */

	return ret;
}

int _remap_pages_rand(struct _page_picker_s *picker,
					  const unsigned long *start, const unsigned long *end,
					  const int n, const int movedata)
{
	void			*remap_to, *remap_to_end, *remap_from;
	int				index[ULCC_NUM_CACHE_COLORS];
	int				c_colors = 0, cont = 1;
	int				idr, ii, i;
	unsigned int	rand_seed;
	int				n_rand;
	int				ret = 0;

	/* Compute the number of colors in this request and build index array */
	for(i = 0, ii = 0; i < ULCC_NUM_CACHE_COLORS; i++)
	{
		if(picker[i].needed > 0)
		{
			c_colors++;
			index[ii++] = i;
		}
	}
	_ULCC_ASSERT(c_colors > 0);

	rand_seed = time(NULL);

	/* For each data region */
	for(idr = 0, ii = 0; idr < n; idr++)
	{
		remap_to = (void *)ULCC_ALIGN_HIGHER(start[idr]);
		remap_to_end = (void *)ULCC_ALIGN_LOWER(end[idr]);

		/* Remap a picked page to each page in this data region */
		while(remap_to < remap_to_end)
		{
			/* Get the next picked page to remap from.
			 * Move the color index forward by a random number.
			 */
			n_rand = rand_r(&rand_seed) % c_colors;
			while(n_rand >= 0)
			{
				ii = (ii + 1) % c_colors;
				if(picker[index[ii]].picked > 0)
				{
					n_rand--;
				}
			}

			/* Select page to remap from from TAIL to HEAD of the pages list */
			remap_from = picker[index[ii]].pages[--picker[index[ii]].picked];

			/* Copy data before remapping */
			if(movedata)
			{
				memcpy(remap_from, remap_to, ULCC_PAGE_BYTES);
			}

			/* Remap the picked physical page to user data region */
			if(mremap(remap_from, ULCC_PAGE_BYTES, ULCC_PAGE_BYTES,
				MREMAP_MAYMOVE | MREMAP_FIXED, remap_to) == MAP_FAILED)
			{
				cont = 0;
				ret = -1;
				break;
			}

			/* Repair the page hole caused by the above remapping */
			if(mmap(remap_from, ULCC_PAGE_BYTES, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0, 0) != remap_from)
			{
				cont = 0;
				ret = -1;
				break;
			}

			remap_to += ULCC_PAGE_BYTES;
		} /* while */

		if(!cont)
		{
			break;
		}
	} /* for each data region */

	return ret;
}

int _remap_pages_arb(struct _page_picker_s *picker,
						const unsigned long *start, const unsigned long *end,
						const int n, const int movedata)
{
	void *remap_to, *remap_to_end, *remap_from;
	int idr, cont = 1, i_picked = 0;
	int ret = 0;

	for(idr = 0; idr < n; idr++)
	{
		remap_to = (void *)ULCC_ALIGN_HIGHER(start[idr]);
		remap_to_end = (void *)ULCC_ALIGN_LOWER(end[idr]);

		while(remap_to < remap_to_end)
		{
			/* Select page to remap from from HEAD to TAIL of the pages list */
			remap_from = picker[0].pages[i_picked++];

			/* Copy data before remapping */
			if(movedata)
			{
				memcpy(remap_from, remap_to, ULCC_PAGE_BYTES);
			}

			/* Remap the picked physical page to user data region */
			if(mremap(remap_from, ULCC_PAGE_BYTES, ULCC_PAGE_BYTES,
				MREMAP_MAYMOVE | MREMAP_FIXED, remap_to) == MAP_FAILED)
			{
				cont = 0;
				ret = -1;
				break;
			}

			/* Repair the page hole caused by the above remapping */
			if(mmap(remap_from, ULCC_PAGE_BYTES, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0, 0) != remap_from)
			{
				cont = 0;
				ret = -1;
				break;
			}

			remap_to += ULCC_PAGE_BYTES;
		} /* While more pages in this data region to be remapped */

		if(!cont)
		{
			break;
		}
	} /* For each data region */

	return ret;
}

/* Set or clear a set of color bits, [low, high], in a cache region struct
 */
void cc_cacheregn_set(cc_cacheregn_t *regn, const int low, const int high,
					  const int set)
{
	int		i;

	if(set)
	{
		for(i = low; i <= high; i++)
		{
			ULCC_SET_COLOR_BIT(regn, i);
		}
	}
	else
	{
		for(i = low; i <= high; i++)
		{
			ULCC_CLR_COLOR_BIT(regn, i);
		}
	}
}

/* Get the cache region covered by a data region.
 * Usually regn should have been cleared before calling this function, but user may
 * choose to call this function multiple times on different data regions with the
 * same regn to get the aggregate cache region covered by these data regions.
 */
#define _CACHEREGN_GET_BATCH_SIZE	128
int cc_cacheregn_get(cc_cacheregn_t *regn, const unsigned long start,
					 const unsigned long end)
{
	cc_uint64_t		pfnbuf[_CACHEREGN_GET_BATCH_SIZE];
	unsigned long	start_aligned;
	int				i, j, l, n;
	int				ret = 0;

	start_aligned = ULCC_ALIGN_HIGHER(start);
	n = (ULCC_ALIGN_LOWER(end) - start_aligned) / ULCC_PAGE_BYTES;

	for(i = 0; i < n; i += _CACHEREGN_GET_BATCH_SIZE)
	{
		l = ULCC_MIN(_CACHEREGN_GET_BATCH_SIZE, n - i);

		if(cc_addr_translate(pfnbuf, start_aligned + i * ULCC_PAGE_BYTES, l) < 0)
		{
			ret = -1;
			break;
		}

		for(j = 0; j < l; j++)
		{
			if(cc_pfn_present(pfnbuf[j]))
			{
				ULCC_SET_COLOR_BIT(regn, cc_pfn_color(pfnbuf[j]));
			}
		}
	}

	return ret;
}

/* Clear a cache region struct
 */
void cc_cacheregn_clr(cc_cacheregn_t *regn)
{
	cc_cacheregn_set(regn, 0, ULCC_NUM_CACHE_COLORS - 1, 0);
}

/* Get the number of colors in a cache region
 */
int cc_cacheregn_cnt(const cc_cacheregn_t *regn)
{
	int		i, c_colors = 0;

	for(i = 0; i < ULCC_NUM_CACHE_COLORS; i++)
	{
		if(ULCC_TST_COLOR_BIT(regn, i))
		{
			c_colors++;
		}
	}

	return c_colors;
}

/* To be used in next version */
unsigned long _new_pagepipe_key(void)
{
	unsigned int	rand_seed = time(NULL);	/* TODO: use ns-level time value */
	unsigned int	key_low;
#ifdef _ULCC_CONFIG_OS64
	unsigned int	key_high;
#endif

	key_low = rand_r(&rand_seed);

#ifdef _ULCC_CONFIG_OS32
	return (unsigned long)key_low;

#else
	key_high = rand_r(&rand_seed);

	return (((unsigned long)key_high) << 16) & (unsigned long)key_low;
#endif
}
