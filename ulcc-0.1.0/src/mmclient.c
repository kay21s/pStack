/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#define _XOPEN_SOURCE 600
#include <time.h>
#include <mqueue.h>
#include <semaphore.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "ulcc.h"
#include "memmgr.h"
#include "mmclient.h"


/* Memory manager free pages array
 */
unsigned long *mm_free_pages _ULCC_HIDDEN = MAP_FAILED;
sem_t *sem_mm_free_pages _ULCC_HIDDEN = SEM_FAILED;

int cc_mmclient_init(void)
{
	return mm_free_pages_open();
}

void cc_mmclient_fini(void)
{
	mm_free_pages_close();
}

int mm_free_pages_lock(void)
{
	int		ret = 0;

	if(sem_mm_free_pages == SEM_FAILED)
	{
		return -1;
	}

	while(sem_wait(sem_mm_free_pages) == -1)
	{
		if(errno != EINTR)
		{
			ret = -1;
			break;
		}
	}

	return ret;
}

int mm_free_pages_unlock(void)
{
	return sem_post(sem_mm_free_pages);
}

int mm_free_pages_open(void)
{
	int		shmfd;

	if(mm_free_pages != MAP_FAILED)
	{
		_ULCC_ERROR("memory manager free pages array already opened");
		return -1;
	}

	/* This shared memory region must have been created by the memory manager;
	 * otherwise, free_pages array will not be used by this ulcc client.
	 */
	shmfd = shm_open(ULCC_NAME_SHM_MM_FREE_PAGES, O_RDONLY,
		ULCC_PRIV_SHM_MM_FREE_PAGES);
	if(shmfd == -1)
	{
		_ULCC_ERROR("shm_open error for mm_free_pages");
		return -1;
	}

	mm_free_pages = mmap(NULL, sizeof(unsigned long) * ULCC_NUM_CACHE_COLORS,
		PROT_READ, MAP_SHARED, shmfd, 0);
	if(mm_free_pages == MAP_FAILED)
	{
		_ULCC_ERROR("mmap error to map free pages array to local address");
		close(shmfd);
		return -1;
	}
	close(shmfd);

	return 0;
}

void mm_free_pages_close(void)
{
	if(mm_free_pages == MAP_FAILED)
	{
		return;
	}
	munmap(mm_free_pages, sizeof(unsigned long) * ULCC_NUM_CACHE_COLORS);
	mm_free_pages = MAP_FAILED;
}

/* Determine whether memory manager is needed for picking pages. Heuristics
 * used include:
 * 1. For c_colors more than half the total amount of cache colors, memory
 * manager is not needed;
 * 2. For the number of pages requested per color fewer than 1/4
 * MM_PAGE_BLOCK_PAGES, memory manager is not needed;
 * ... ...
 */
int use_memmgr(const int c_colors, const int c_pages_per_color)
{
	if(c_colors >= ULCC_NUM_CACHE_COLORS / 2)
	{
		return 0;
	}

	if(c_pages_per_color < MM_PAGE_BLOCK_PAGES / 4)
	{
		return 0;
	}

	return 1;
}

int max_pick_loops(const int c_pages, const int c_colors)
{
	return (c_pages * ULCC_NUM_CACHE_COLORS / MIN_PAGES_PER_LOOP + 10);
}

/* If color is -1, pages means the total number of pages still needed in all
 * colors concerned; if color is between 0 and ULCC_NUM_CACHE_COLORS, pages is
 * the number of pages still needed in that particular color.
 * Heuristics:
 * 1. If the number of remaining pages in a particular color is less than one
 * fourth the size of memmgr slab, return 0 to indicate that a separate request
 * to memmgr for pages in this color is not worth it any more. Move on to the
 * next color instead.
 * ... ...
 */
int next_pages_per_loop(const int color, const int pages)
{
	int pages_next_loop;

	if(color == -1)
	{
		pages_next_loop = ULCC_MIN(pages, MAX_PAGES_PER_LOOP);
		pages_next_loop = ULCC_MAX(pages_next_loop, MIN_PAGES_PER_LOOP);
	}
	else
	{
		if(pages < MM_PAGE_BLOCK_PAGES / 4)
		{
			pages_next_loop = 0;
		}
		else
		{
			pages_next_loop = MM_PAGE_BLOCK_PAGES;
		}
	}

	return pages_next_loop;
}

#ifdef _ULCC_CONFIG_KMODULE_PAGEPIPE
/* TODO */
int cc_mm_sndreq(const int color, const int pages, const unsigned long pipeid,
				 const unsigned long key)
{
	return -1;
}
#else
int cc_mm_sndreq(const int color, const int pages)
{
	sem_t				*sem_wake;
	unsigned int		rnd_seed;
	struct timespec		timeout;
	mqd_t				mqid;
	mm_svcmsg_t			req;

	if(color < 0)
	{
		return 0;
	}

	mqid = mq_open(ULCC_NAME_MM_SVCQUE, O_WRONLY);
	if(mqid == (mqd_t)-1)
	{
		return -1;
	}

	req.svc_cmd = MM_MSG_GETPAGES;
	req.svc_color = color;
	req.svc_count = pages;
	/* Create a wakeup semaphore */
	rnd_seed = getpid() + time(NULL);
	do
	{
		_new_sem_name(req.svc_wake, rnd_seed);
		sem_wake = sem_open(req.svc_wake, O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, 0);
		if(sem_wake == SEM_FAILED)
		{
			if(errno != EEXIST)
			{
				mq_close(mqid);
				return -1;
			}
			else
			{
				rnd_seed++;
				continue;
			}
		}
		else
		{
			break;
		}
	} while(1);

	if(clock_gettime(CLOCK_REALTIME, &timeout) == -1)
	{
		_ULCC_ERROR("clock_gettime error");
		sem_unlink(req.svc_wake);
		sem_close(sem_wake);
		mq_close(mqid);
		return -1;
	}
	timeout.tv_sec += 1;

	if(mq_timedsend(mqid, (char *)&req, sizeof(req), MM_MSGPRIO_GETPAGES,
		&timeout) == -1)
	{
		if(errno == ETIMEDOUT)
		{
			_ULCC_ERROR("message send timed out");
		}
		else
		{
			_ULCC_ERROR("message send error");
		}
		sem_unlink(req.svc_wake);
		sem_close(sem_wake);
		mq_close(mqid);
		return -1;
	}

	if(clock_gettime(CLOCK_REALTIME, &timeout) == -1)
	{
		_ULCC_ERROR("clock_gettime error after sending message");
		sem_unlink(req.svc_wake);
		sem_close(sem_wake);
		mq_close(mqid);
		return -1;
	}
	timeout.tv_sec += 1;

	if(sem_timedwait(sem_wake, &timeout) < 0)
	{
		if(errno == ETIMEDOUT)
		{
			_ULCC_ERROR("semaphore wait timed out");
		}
		else
		{
			_ULCC_ERROR("semaphore wait error");
		}
		sem_unlink(req.svc_wake);
		sem_close(sem_wake);
		mq_close(mqid);
		return -1;
	}

	sem_unlink(req.svc_wake);
	sem_close(sem_wake);
	mq_close(mqid);
	return 0;
}
#endif

/* The size of name should be at least MM_WAKE_LEN bytes */
void _new_sem_name(char *name, unsigned int rnd_seed)
{
	unsigned int	num_rand;
	char			*p;
	int				i;

	num_rand = rand_r(&rnd_seed);

	p = name;
	strcpy(p, "/ulcc-");
	p += 6;
	for(i = 0; i < sizeof(unsigned int) * 8; i++)
	{
		*p++ = num_rand % 2 ? '1' : '0';
		num_rand = num_rand >> 1;
	}
	*p = '\0';
}
