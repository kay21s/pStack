/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_CACHE_H_
#define _ULCC_CACHE_H_

#include "remapper.h"

/* Names of global shared resources */
#define ULCC_NAME_SHM_CACHE_STATUS		"/ulcc-shm-cache-status"
#define ULCC_NAME_SEM_CACHE_STATUS		"/ulcc-sem-cache-status"
#define ULCC_NAME_SHM_BUSY_PAGES		"/ulcc-shm-busy-pages"
#define ULCC_NAME_SEM_BUSY_PAGES		"/ulcc-sem-busy-pages"

/* Privilege bits for sem_open or shm_open */
#define ULCC_PRIV_SEM_CACHE_STATUS		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP \
		| S_IROTH | S_IWOTH)
#define ULCC_PRIV_SHM_CACHE_STATUS		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP \
		| S_IROTH | S_IWOTH)
#define ULCC_PRIV_SEM_BUSY_PAGES		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP \
		| S_IROTH | S_IWOTH)
#define ULCC_PRIV_SHM_BUSY_PAGES		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP \
		| S_IROTH | S_IWOTH)

/* Status of a shared cache */
typedef struct cc_cache_status_s
{
	int		type[ULCC_NUM_CACHE_COLORS];	/* Type of each color: CC_PRIVATE,
											   CC_SHARED or CC_UNSPECIFIED */
	int		count[ULCC_NUM_CACHE_COLORS];	/* Count of current mappings to each
											   color */
	pid_t	owner[ULCC_NUM_CACHE_COLORS];	/* Owner of each private color */
} cc_cache_status_t;

/* For internal use only
 */
#ifdef _H_CACHE_INTERNAL_
int _ULCC_HIDDEN cache_status_open(void);
void _ULCC_HIDDEN cache_status_close(void);
int _ULCC_HIDDEN cache_status_lock(void);
int _ULCC_HIDDEN cache_status_unlock(void);

int _ULCC_HIDDEN busy_pages_open(void);
void _ULCC_HIDDEN busy_pages_close(void);
int _ULCC_HIDDEN busy_pages_lock(void);
int _ULCC_HIDDEN busy_pages_unlock(void);

int _ULCC_HIDDEN _cache_rsv_shared(const int *caidx, const int nca,
	const int c_colors, const int c_pages_per_color, const int usefp,
	cc_cacheregn_t *regn);
int _ULCC_HIDDEN _cache_rsv_shared_fp(const int *caidx, const int nca,
	const int c_colors, const int c_pages_per_color);
int _ULCC_HIDDEN _cache_rsv_shared_bp(const int *caidx, const int nca,
	const int c_colors, const int c_pages_per_color);
int _ULCC_HIDDEN _cache_rsv_private(const int *caidx, const int nca,
	const int c_colors, const int c_pages_per_color, const int usefp,
	cc_cacheregn_t *regn);

int _ULCC_HIDDEN _partition(int *sort, int p, int r, const unsigned long *ref);
void _ULCC_HIDDEN _quick_sort(int *sort, int p, int r, const unsigned long *ref);
void _ULCC_HIDDEN _sort_coidx(int *sort, const int nsort, const unsigned long *ref);
#endif

int _ULCC_HIDDEN cc_cache_init(void);
void _ULCC_HIDDEN cc_cache_fini(void);

int _ULCC_HIDDEN cache_idx_array(const int *cpus, const int nc, int *caidx,
	int *nca);

int _ULCC_HIDDEN cc_cache_rsv(const int size, const int type, const int *caidx,
	const int nca, const int c_pages, cc_cacheregn_t *regn);
int _ULCC_HIDDEN cc_cache_rel(const int *caidx, const int nca,
	const cc_cacheregn_t *regn);

int _ULCC_HIDDEN busy_pages_add(const cc_cacheregn_t *regn, const int *c_pages);
int _ULCC_HIDDEN busy_pages_rm(const cc_cacheregn_t *regn, const int *c_pages);

#endif
