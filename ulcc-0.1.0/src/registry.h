/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_REGISTRY_H_
#define _ULCC_REGISTRY_H_


/* Allocation registry entry
 */
#define _ULCC_MAX_AID		((cc_aid_t)0x10000000L)
typedef struct cc_regent_s
{
	cc_aid_t				aid;		/* Allocation id */

	/* Data regions */
	unsigned long			*start;		/* Start addresses of data regions */
	unsigned long			*end;		/* End addresses of data regions */
	int						ndr;		/* Number of data regions */

	/* Caches and cache region */
	cc_cacheregn_t			regn;		/* Cache region covered */
	int						*caidx;		/* Indexes to shared caches involved */
	int						nca;		/* Number of shared caches involved */

	/* Contribution of pages to each color */
	int						*c_pages;	/* Contain c_colors integers */
	int						c_colors;	/* Number of cache colors */

	struct cc_regent_s		*next, *prev;
} cc_regent_t;

/* Per-process allocation registry
 */
typedef struct cc_registry_s
{
	int				n_entries;
	cc_regent_t		*head;
} cc_registry_t;


/* Registry entry functions
 */
cc_regent_t _ULCC_HIDDEN *cc_regent_new(const unsigned long *start,
	const unsigned long *end, const int ndr, const int *caidx, const int nca,
	const cc_cacheregn_t *regn, const int *new_pages);
void _ULCC_HIDDEN cc_regent_free(cc_regent_t *ent);

/* Registry manipulation interfaces
 */
int _ULCC_HIDDEN cc_reg_init(void);
void _ULCC_HIDDEN cc_reg_fini(void);
int _ULCC_HIDDEN cc_reg_lock(void);
int _ULCC_HIDDEN cc_reg_unlock(void);

cc_aid_t _ULCC_HIDDEN cc_reg_push(const unsigned long *start,
	const unsigned long *end, const int ndr, const int *caidx, const int nca,
	const cc_cacheregn_t *regn, const int *new_pages);
cc_regent_t _ULCC_HIDDEN *cc_reg_rm(cc_aid_t aid);
cc_regent_t _ULCC_HIDDEN *cc_reg_get(const cc_aid_t aid);

#endif
