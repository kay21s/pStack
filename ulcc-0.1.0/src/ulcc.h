/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_H_
#define _ULCC_H_

#include <pthread.h>
#include <sched.h>
#include "arch.h"

#ifdef _ULCC_LIB
#define _ULCC_EXPORT	__attribute__ ((visibility ("default")))
#define _ULCC_HIDDEN	__attribute__ ((visibility ("hidden")))
#else
#define _ULCC_EXPORT
#define _ULCC_HIDDEN
#endif

#ifdef _ULCC_DBG
#include <stdio.h>
#define _ULCC_STRINGIFY(x)	#x
#define _ULCC_ASSERT(x)		if(!(x)) fprintf(stderr,\
			"_ULCC_ASSERT Error: the evaluation of (%s) returned false\n",\
			_ULCC_STRINGIFY(x))
#define _ULCC_ERROR(m)		perror("ULCC_DBG_ERROR: " m)
#else
#define _ULCC_ASSERT(x)
#define _ULCC_ERROR(m)
#endif

#define ULCC_FREE(p)	if(p) free(p)

#define ULCC_MIN(x,y)	((x) < (y) ? (x) : (y))
#define ULCC_MAX(x,y)	((x) > (y) ? (x) : (y))

/* Page alignment macros
 */
#define ULCC_ALIGN_HIGHER(addr) \
		(((addr) & ULCC_PAGE_OFFSET_MASK) ?\
		(((addr) & ULCC_PAGE_IDX_MASK) + ULCC_PAGE_BYTES) :\
		(addr)\
	)
#define ULCC_ALIGN_LOWER(addr)	\
		(((addr) & ULCC_PAGE_OFFSET_MASK) ?\
		((addr) & ULCC_PAGE_IDX_MASK) :\
		(addr)\
	)

/* Constants for allocation flags
 */
#define CC_MASK_MOVE			0x0001	/* MOVE bits mask: bit 0 */
#define CC_ALLOC_MOVE			0x0000	/* Move data to new pages; default */
#define CC_ALLOC_NOMOVE			0x0001	/* No need to move data to new pages */

#define CC_MASK_MAPORDER		0x0006	/* MAP_ORDER bits mask */
#define CC_MAPORDER_SEQ			0x0000	/* Sequential mapping; default */
#define CC_MAPORDER_RAND		0x0002	/* Random mapping */
#define CC_MAPORDER_ARB			0x0004	/* Arbitrary mapping */

/* Portable data types
 */
#ifdef _ULCC_CONFIG_OS32	/* 32-bit operating system */
typedef long long				cc_int64_t;
typedef unsigned long long		cc_uint64_t;
#else
#ifdef _ULCC_CONFIG_OS64	/* 64-bit operating system */
typedef long					cc_int64_t;
typedef unsigned long			cc_uint64_t;
#endif
#endif

/* Status of a cache color, or type of a cache space */
enum
{
	CC_UNSPECIFIED =	0,
	CC_PRIVATE =		1,
	CC_SHARED =			2
};

/* Allocation id */
typedef cc_int64_t cc_aid_t;
#define CC_AID_INVALID		((cc_aid_t)-1)

/* Thread id */
typedef pthread_t cc_tid_t;

/* Cpu id */
typedef int cc_cid_t;

/* Data set */
typedef struct cc_dataset_s
{
	/* The ith virtual memory region in this data set is [start[i], end[i]) */
	unsigned long	*d_start;
	unsigned long	*d_end;
	int				d_max;		/* Maximum number of memory regions */
	int				d_count;	/* Current number of memory regions */
} cc_dataset_t;

/* Cache slot */
typedef struct cc_cacheslot_s
{
	int s_size;			/* Size of cache space in bytes */
	int s_type;			/* Type of cache space: CC_PRIVATE or CC_SHARED */
} cc_cacheslot_t;

/* Thread set */
typedef struct cc_thrdset_s
{
	cc_tid_t	*t_threads;	/* Thread id array */
	int			t_max;		/* Maximum number of tids in the thread group */
	int			t_count;	/* Current number of tids in this thread group */
} cc_thrdset_t;

/* CPU set
 */
typedef cpu_set_t cc_cpuset_t;


/* Library interfaces
 */
int _ULCC_EXPORT cc_init(void);
void _ULCC_EXPORT cc_fini(void);

cc_aid_t _ULCC_EXPORT cc_alloc(const cc_dataset_t *dst, const cc_thrdset_t *tst,
	const cc_cacheslot_t *cs, int flags);
cc_aid_t _ULCC_EXPORT cc_alloc_cpus(const cc_dataset_t *dst,
	const cc_cpuset_t *cst, const cc_cacheslot_t *cs, int flags);

cc_aid_t _ULCC_EXPORT cc_alloc_add(const cc_aid_t aid, const cc_dataset_t *dst,
	int flags);

int _ULCC_EXPORT cc_dealloc(const cc_aid_t aid);

int _ULCC_EXPORT cc_set_uc(const unsigned long start, const unsigned long end,
	const int uc);

/* Utility and wrapper interfaces
 */
#include "util.h"

/* Wrappers for single data region cache allocation */
cc_aid_t _ULCC_EXPORT cc_alloc2(const unsigned long start,
	const unsigned long end, const cc_thrdset_t *tst, const cc_cacheslot_t *cs,
	int flags);
cc_aid_t _ULCC_EXPORT cc_alloc2_cpus(const unsigned long start,
	const unsigned long end, const cc_cpuset_t *cst, const cc_cacheslot_t *cs,
	int flags);
cc_aid_t _ULCC_EXPORT cc_alloc_add2(const cc_aid_t aid,
	const unsigned long start, const unsigned long end,
	int flags);

#endif
