/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_TRANSLATOR_H_
#define _ULCC_TRANSLATOR_H_

#include "ulcc.h"

/* Pagemap interface masks */
#define PAGEMAP_MASK_PFN		(((cc_uint64_t)1 << 55) - 1)
#define PAGEMAP_PAGE_PRESENT	((cc_uint64_t)1 << 63)

/* Whether this physical page is present in memory */
#define cc_pfn_present(pfn)		((pfn) > 0)

/* The color of this physical page */
#define cc_pfn_color(pfn)		((pfn) % ULCC_NUM_CACHE_COLORS)

/* Translation from virtual page addresses to their physical page numbers */
int _ULCC_HIDDEN cc_addr_translate(cc_uint64_t *pfnbuf,
	const unsigned long vmp_start, const unsigned int n);

#endif
