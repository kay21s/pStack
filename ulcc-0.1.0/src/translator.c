/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifdef _ULCC_CONFIG_PAGEMAP
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#else
#ifdef _ULCC_CONFIG_KMODULE_ADDRTRAN
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#endif
#endif

#include "arch.h"
#include "translator.h"

/* Virtual page address to physical page address translation.
 * If kernel version is not older than 2.6.25, both /proc/<pid>/pagemap
 * interface and the ULCC address translator kernel module can be used to do the
 * translation; otherwise, the ULCC kernel module should have been installed
 * and will be used to achieve this purpose.
 * Note: the length of pfnbuf should be at least 3 * sizeof(unsigned long).
 */
int cc_addr_translate(cc_uint64_t *pfnbuf, const unsigned long vmp_start,
					  const unsigned int n)
{
#ifdef _ULCC_CONFIG_PAGEMAP

	char	fname[32];
	int		fid, i;

	sprintf(fname, "/proc/%d/pagemap", getpid());
	fid = open(fname, O_RDONLY);
	if(fid < 0)
	{
		_ULCC_ERROR("failed to open pagemap address translator");
		return -1;
	}

	if(lseek(fid, ULCC_PAGE_NBR(vmp_start) * 8, SEEK_SET) == (off_t)-1)
	{
		_ULCC_ERROR("failed to seek to translation start address");
		close(fid);
		return -1;
	}

	if(read(fid, pfnbuf, 8 * n) < 8 * n)
	{
		_ULCC_ERROR("failed to read in all pfn info");
		close(fid);
		return -1;
	}

	for(i = 0; i < n; i++)
	{
		if(pfnbuf[i] & PAGEMAP_PAGE_PRESENT)
		{
			pfnbuf[i] &= PAGEMAP_MASK_PFN;
		}
		else
		{
			pfnbuf[i] = 0;
		}
	}

	close(fid);
	return 0;

#else
#ifdef _ULCC_CONFIG_KMODULE_ADDRTRAN	/* TODO */

/*	int		fid;

	fid = open(_ULCC_CONFIG_ADDRTRAN_DEVPATH, O_RDWR);
	if(fid < 0)
	{
		_ULCC_ERROR("failed to open address translator kernel module");
		return -1;
	}

	pfnbuf[0] = 1L;			// Use compact format
	pfnbuf[1] = vmp_start;
	pfnbuf[2] = (cc_uint64_t)n;
	if(read(fid, pfnbuf, ULCC_MAX(3, n) * sizeof(unsigned long)) == 0)
	{
		_ULCC_ERROR("translation error; read returned 0");
		return -1;
	}

	close(fid);
	return 0;
*/
	return -1;

#else

	return -1;

#endif
#endif
}
