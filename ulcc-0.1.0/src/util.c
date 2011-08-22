/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include "ulcc.h"
#include "util.h"

/* Create and initilize a new data set.
 */
cc_dataset_t *cc_dataset_new(const int max)
{
	cc_dataset_t *dst;

	if(max <= 0)
	{
		_ULCC_ERROR("max should be positive for cc_dataset_new");
		return (void *)0;
	}

	dst = (cc_dataset_t *)malloc(sizeof(cc_dataset_t));
	if(!dst)
	{
		_ULCC_ERROR("malloc for a new data set failed");
		return (void *)0;
	}

	dst->d_count = 0;
	dst->d_max = max;

	dst->d_start = (unsigned long *)malloc(max * sizeof(unsigned long));
	if(!dst->d_start)
	{
		_ULCC_ERROR("malloc for data set start[] array failed");
		free(dst);
		return (void *)0;
	}
	dst->d_end = (unsigned long *)malloc(max * sizeof(unsigned long));
	if(!dst->d_end)
	{
		_ULCC_ERROR("malloc for data set end[] array failed");
		free(dst->d_start);
		free(dst);
		return (void *)0;
	}

	return dst;
}

int cc_dataset_add(cc_dataset_t *dst, const unsigned long start, const unsigned long end)
{
	/* If this data set is not full yet, insert this new region */
	if(dst->d_count < dst->d_max)
	{
		dst->d_start[dst->d_count] = start;
		dst->d_end[dst->d_count] = end;
		dst->d_count++;

		return 0;
	}
	else
	{
		return -1;
	}
}

int cc_dataset_add2(cc_dataset_t *dst, const cc_dataset_t *dst2)
{
	int i;

	if(dst->d_count + dst2->d_count < dst->d_max)
	{
		for(i = 0; i < dst2->d_count; i++)
		{
			dst->d_start[dst->d_count] = dst2->d_start[i];
			dst->d_end[dst->d_count] = dst2->d_end[i];
			dst->d_count++;
		}

		return 0;
	}
	else
	{
		return -1;
	}
}

void cc_dataset_clr(cc_dataset_t *dst)
{
	dst->d_count = 0;
}

void cc_dataset_free(cc_dataset_t *dst)
{
	free(dst->d_start);
	free(dst->d_end);
	free(dst);
}

int cc_cpuset_proc(cc_cpuset_t *cst, const pid_t pid)
{
	return sched_getaffinity(pid, sizeof(*cst), cst);
}

int cc_cpuset_add(cc_cpuset_t *cst, const cc_cid_t *cpus, const int n)
{
	int		i;

	for(i = 0; i < n; i++)
	{
		CPU_SET(cpus[i], cst);
	}

	return 0;
}

int cc_cpuset_from_thrdset(cc_cpuset_t *cst, const cc_thrdset_t *tst)
{
	cpu_set_t	mask;
	int		i, j;

	for(i = 0; i < tst->t_count; i++)
	{
		if(pthread_getaffinity_np(tst->t_threads[i], sizeof(mask), &mask) != 0)
		{
			return -1;
		}
		for(j = 0; j < ULCC_NUM_CPUS * 2; i++)
		{
			if(CPU_ISSET(j, &mask))
			{
				CPU_SET(j, cst);
			}
		}
	}

	return 0;
}

int cc_cpuset_count(const cc_cpuset_t *cst)
{
	int	i, count = 0;

	for(i = 0; i < ULCC_NUM_CPUS * 2; i++)
	{
		if(CPU_ISSET(i, cst))
		{
			count++;
		}
	}

	return count;
}

cc_thrdset_t *cc_thrdset_new(int max)
{
	cc_thrdset_t *tst;

	if(max <= 0)
	{
		return (void *)0;
	}

	tst = (cc_thrdset_t *)malloc(sizeof(cc_thrdset_t));
	if(!tst)
	{
		_ULCC_ERROR("malloc for a new thread set structure failed");
		return (void *)0;
	}

	tst->t_count = 0;
	tst->t_max = max;

	tst->t_threads = (cc_tid_t *)malloc(max * sizeof(cc_tid_t));
	if(!tst->t_threads)
	{
		_ULCC_ERROR("malloc for thread set threads[] array failed");
		free(tst);
		return (void *)0;
	}

	return tst;
}

int cc_thrdset_add(cc_thrdset_t *tst, const cc_tid_t *threads, const int n)
{
	int i;

	/* No room to host more threads? */
	if(tst->t_max - tst->t_count < n)
	{
		return -1;
	}

	for(i = 0; i < n; i++)
	{
		tst->t_threads[tst->t_count++] = threads[i];
	}

	return 0;
}

void cc_thrdset_free(cc_thrdset_t *tst)
{
	free(tst->t_threads);
	free(tst);
}

int cc_cache_size(void)
{
	return (ULCC_CACHE_KB * 1024);
}

int cc_cache_colors(void)
{
	return ULCC_NUM_CACHE_COLORS;
}
