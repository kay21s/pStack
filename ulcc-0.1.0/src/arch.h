/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_ARCH_H_
#define _ULCC_ARCH_H_

/****************************************************************************
 * EDIT information below to fit the parameters of your machine */

/* 32-bit or 64-bit operating system? */
#define _ULCC_CONFIG_OS32
/*#define _ULCC_CONFIG_OS64*/

/* The number of bits for page offset in an address */
#define ULCC_PAGE_BITS				12

/* Cache size in KiB */
#define ULCC_CACHE_KB				(3 * 1024)
/* Cache associativity */
#define ULCC_CACHE_ASSOC			12

/* Number of physical threads sharing the same cache */
#define ULCC_NUM_CPUS_PER_CACHE		4
/* Number of shared caches */
#define ULCC_NUM_SHARED_CACHES		1

/* END OF EDIT (Please also go to arch.c to set the cache_to_cpus array )
 ***************************************************************************/

#define ULCC_PAGE_BYTES			((unsigned long)1 << ULCC_PAGE_BITS)
#define ULCC_PAGE_KB			(ULCC_PAGE_BYTES / 1024)
#define ULCC_PAGE_OFFSET_MASK	(((unsigned long)1 << ULCC_PAGE_BITS) - 1)
#define ULCC_PAGE_IDX_MASK		(~ULCC_PAGE_OFFSET_MASK)
#define ULCC_PAGE_NBR(addr)		(((unsigned long)(addr)) >> ULCC_PAGE_BITS)

/* Number of cache colors */
#define ULCC_NUM_CACHE_COLORS	(ULCC_CACHE_KB / ULCC_CACHE_ASSOC / ULCC_PAGE_KB)
/* Size of each cache color */
#define ULCC_CACHE_BYTES_PER_COLOR	(ULCC_CACHE_ASSOC * ULCC_PAGE_BYTES)

/* Number of cpus */
#define ULCC_NUM_CPUS		(ULCC_NUM_CPUS_PER_CACHE * ULCC_NUM_SHARED_CACHES)

#endif
