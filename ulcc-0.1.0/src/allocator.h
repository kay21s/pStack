/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_ALLOCATOR_H_
#define _ULCC_ALLOCATOR_H_

/* Allocator interface functions
 */
int _ULCC_HIDDEN cc_allocator_init(void);
void _ULCC_HIDDEN cc_allocator_fini(void);

cc_aid_t _ULCC_HIDDEN cc_do_alloc(const unsigned long *start,
	const unsigned long *end, const int ndr, const int *cores, const int nc,
	const int cs_size, const int cs_type, int flags);

int _ULCC_HIDDEN cc_do_alloc_add(const cc_aid_t aid, const unsigned long *start,
	const unsigned long *end, const int ndr, int flags);

int _ULCC_HIDDEN cc_do_dealloc(const cc_aid_t aid);

/* Return the total number of aligned pages in a set of data regions */
int _ULCC_HIDDEN num_aligned_pages(const unsigned long *start,
	const unsigned long *end, const int n);

#endif
