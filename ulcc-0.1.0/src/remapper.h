/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_REMAPPER_H_
#define _ULCC_REMAPPER_H_

#include "ulcc.h"

/* Cache region
 * A bitmap representation of cache colors in this region. It is safe to assume
 * the number of cache colors is a multiple of 8, which is true as long as the
 * page color bits in a physical address are longer than 3.
 */
typedef struct cc_cacheregn_s
{
	unsigned char color_map[ULCC_NUM_CACHE_COLORS / 8];
} cc_cacheregn_t;

/* set a bit in a color bitmap */
#define ULCC_SET_COLOR_BIT(regn, ibit)	\
	((regn)->color_map[(ibit)/8] |= \
	((unsigned char)((unsigned char) 1) << ((ibit) % 8)))
/* clear a bit in a color bitmap */
#define ULCC_CLR_COLOR_BIT(regn, ibit)	\
	((regn)->color_map[(ibit)/8] &= \
	~((unsigned char)(((unsigned char) 1) << ((ibit) % 8))))
/* test whether a bit in a color bitmap is 1 or 0 */
#define ULCC_TST_COLOR_BIT(regn, ibit)	\
	(((regn)->color_map[(ibit)/8] & \
	((unsigned char)(((unsigned char) 1) << ((ibit) % 8)))) >> ((ibit) % 8))

#ifdef _H_REMAPPER_INTERNAL_
/* Temporary page picking structure. See cc_remap() for use.
 */
struct _page_picker_s
{
	int		picked;		/* Number of pages already picked */
	int		needed;		/* Max number of pages needed in this color */
	void	**pages;	/* Container of picked pages */
};

/* A temporary list of virtual memory spaces, used to store the intermediate
 * malloc-ed memory regions during page picking.
 * Only two operations are applicable on the list: one is adding a new malloc-ed
 * space into the list; the other is freeing ALL virtual spaces in this list.
 */
#define VM_LIST_NODE_SIZE	32
struct _vm_list_node_s
{
	int		count;		/* Current number of vm regions in this node */
	int		max;		/* Max number of virtual spaces in this node */
	void	**mem;		/* The list of vm regions */
	struct _vm_list_node_s *next;
};
struct _vm_list_s
{
	struct _vm_list_node_s	*head;
};

/* Generate a unique key for use in papepipe */
unsigned long _new_pagepipe_key(void);

/* Operations on the vm heap */
struct _vm_list_node_s _ULCC_HIDDEN *_vm_list_node_new();
void _ULCC_HIDDEN _vm_list_node_free(struct _vm_list_node_s *node);
struct _vm_list_s _ULCC_HIDDEN *_vm_list_new();
int _ULCC_HIDDEN _vm_list_add(struct _vm_list_s *list, void *m);
void _ULCC_HIDDEN _vm_list_free(struct _vm_list_s *list);

/* Operations on the page picker structure */
struct _page_picker_s _ULCC_HIDDEN *_page_picker_new(const int c_pages,
	const int c_pages_per_color, const cc_cacheregn_t *regn,
	const int maporder);
void _ULCC_HIDDEN _page_picker_free(struct _page_picker_s *picked);
#ifdef _ULCC_CONFIG_KMODULE_PAGEPIPE
int _ULCC_HIDDEN _pick_pages_pagepipe(struct _page_picker_s *picker,
	struct _vm_list_s *vml, const int c_pages, const int c_colors,
	const int c_pages_per_color, const int maporder);
#else
int _ULCC_HIDDEN _pick_pages_nopipe(struct _page_picker_s *picker,
	struct _vm_list_s *vml, const int c_pages, const int c_colors,
	const int c_pages_per_color, const int maporder);
#endif

/* Remap user data regions to the physical pages picked */
int _ULCC_HIDDEN _remap_pages(struct _page_picker_s *picker,
	const unsigned long *start, const unsigned long *end, const int n,
	int flags);
int _ULCC_HIDDEN _remap_pages_seq(struct _page_picker_s *picker,
	const unsigned long *start, const unsigned long *end, const int n,
	const int movedata);
int _ULCC_HIDDEN _remap_pages_rand(struct _page_picker_s *picker,
	const unsigned long *start, const unsigned long *end, const int n,
	const int movedata);
int _ULCC_HIDDEN _remap_pages_arb(struct _page_picker_s *picker,
	const unsigned long *start, const unsigned long *end, const int n,
	const int movedata);
#endif	/* _H_REMAPPER_INTERNAL_ */

/* Remapper interface functions
 */
void _ULCC_EXPORT cc_cacheregn_set(cc_cacheregn_t *regn, const int low,
	const int high, const int set);
int _ULCC_EXPORT cc_cacheregn_get(cc_cacheregn_t *regn,
	const unsigned long start, const unsigned long end);
void _ULCC_EXPORT cc_cacheregn_clr(cc_cacheregn_t *regn);
int _ULCC_EXPORT cc_cacheregn_cnt(const cc_cacheregn_t *regn);

/* The low-level cache space allocation interface */
int _ULCC_EXPORT cc_remap(const unsigned long *start, const unsigned long *end,
	const int n, const cc_cacheregn_t *regn, const int flags, int *new_pages);

#endif
