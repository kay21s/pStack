/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <mqueue.h>
#include <fcntl.h>
#include <string.h>
#include <semaphore.h>
#include <syslog.h>
#include <errno.h>
#include <mqueue.h>
#include <time.h>
#include <pthread.h>
#include "arch.h"
#include "translator.h"
#include "memmgr.h"
#include "mmsvr.h"


/* Continue if pages cannot be locked in memory? */
/*static int cont_pages_unlocked = 1;*/

/* Continue if failed to initialize free pages? */
static int cont_wo_free_pages = 1;

/* Maximum number of messages in the message queues */
#define MM_MAXMSG_DEFAULT	16
static long max_num_msg = MM_MAXMSG_DEFAULT;

/* Total number of physical memory pages present in the system */
static long tot_mem_pages = 0;
/* Maximum percentage of physical memory to be held */
static int max_percent_held = 25;
/* Maximum number of pages to be held */
static long max_pages_held = 0;

/* Pages currently held by the memory manager
 */
static mm_page_block_t *page_blocks_head[ULCC_NUM_CACHE_COLORS] =
	{(mm_page_block_t *)0,};
static mm_page_block_t *page_blocks_tail[ULCC_NUM_CACHE_COLORS] =
	{(mm_page_block_t *)0,};
static unsigned long	pb_pages[ULCC_NUM_CACHE_COLORS] = {0,};

/* The page blocks cache; a very simple implementation here
 */
cache_page_blocks_t		cachepb;

/* Number of pages currently available in each color, shared between memory
 * manager and ULCC cache allocator.
 */
unsigned long *free_pages = MAP_FAILED;
sem_t *sem_free_pages = SEM_FAILED;

/* Message queue identifiers */
mqd_t svcque = -1;
mqd_t ctlque = -1;	/* Only the owner or the root can send msg to the queue */

/* Memory manager continue? */
int mm_cont = 1;


int parse_args(int argc, char *argv[])
{
	if(argc >= 2 && !strcmp(argv[1], "stop"))
	{
		if(stop_service() < 0)
		{
			printf("error when stopping memory manager\n");
		}
		else
		{
			printf("memory manager stopped\n");
		}
		return -1;
	}

	/* How many pages can be held by the memory manager at maximum */
	tot_mem_pages = total_mem_pages();
	max_pages_held = tot_mem_pages * max_percent_held / 100;
	if(max_pages_held <= 0)
	{
		return -1;
	}

	return 0;
}

int stop_service(void)
{
	sem_t			*sem_wake;
	unsigned int	rnd_seed;
	struct timespec	timeout;
	mm_ctlmsg_t		req;
	mqd_t			mqid;

	mqid = mq_open(ULCC_NAME_MM_CTLQUE, O_WRONLY);
	if(mqid == (mqd_t)-1)
	{
		perror("failed to open memory manager service queue");
		return -1;
	}

	req.ctl_cmd = MM_MSG_EXIT;
	rnd_seed = getpid() + time(NULL);
	do
	{
		_new_sem_name(req.ctl_wake, rnd_seed);
		sem_wake = sem_open(req.ctl_wake, O_CREAT | O_EXCL,
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
		perror("clock_gettime error");
		sem_unlink(req.ctl_wake);
		sem_close(sem_wake);
		mq_close(mqid);
		return -1;
	}
	timeout.tv_sec += 2;

	if(mq_timedsend(mqid, (char *)&req, sizeof(req), MM_MSGPRIO_EXIT,
		&timeout) == -1)
	{
		if(errno == ETIMEDOUT)
		{
			perror("exit message send timed out");
		}
		else
		{
			perror("exit message send error");
		}
		sem_unlink(req.ctl_wake);
		sem_close(sem_wake);
		mq_close(mqid);
		return -1;
	}

	if(clock_gettime(CLOCK_REALTIME, &timeout) == -1)
	{
		perror("clock_gettime error after sending message");
		sem_unlink(req.ctl_wake);
		sem_close(sem_wake);
		mq_close(mqid);
		return -1;
	}
	timeout.tv_sec += 5;	/* wait for at most 5 seconds before mm exits */

	if(sem_timedwait(sem_wake, &timeout) < 0)
	{
		if(errno == ETIMEDOUT)
		{
			perror("wait_for_exit timed out");
		}
		else
		{
			perror("wait_for_exit error");
		}
		sem_unlink(req.ctl_wake);
		sem_close(sem_wake);
		mq_close(mqid);
		return -1;
	}

	sem_unlink(req.ctl_wake);
	sem_close(sem_wake);
	mq_close(mqid);
	return 0;
}

int mm_init()
{
/*	if(mlockall(MCL_FUTURE) < 0)
	{
		if(cont_pages_unlocked)
		{
			syslog(LOG_ERR, "mlockall error: %m; pages will be managed in "
				"unlocked mode");
		}
		else
		{
			syslog(LOG_EMERG, "mlockall error: %m; cannot continue with pages "
				"unlocked");
			return -1;
		}
	}
*/
	if(cache_pb_init() < 0)
	{
		syslog(LOG_EMERG, "page blocks cache init error");
		return -1;
	}

	if(page_blocks_init() < 0)
	{
		syslog(LOG_EMERG, "page_blocks init error");
		return -1;
	}

	if(free_pages_init() < 0)
	{
		if(cont_wo_free_pages)
		{
			syslog(LOG_ERR, "free_pages init error; "
				"continue without free_pages statistics");
		}
		else
		{
			syslog(LOG_EMERG, "free_pages init error; exiting memory manager");
			page_blocks_fini();
			return -1;
		}
	}

	if(mm_queues_init() < 0)
	{
		syslog(LOG_EMERG, "memory manager queues init error; "
			"exiting memory manager");
		free_pages_fini();
		page_blocks_fini();
		return -1;
	}

	return 0;
}

void mm_fini()
{
/*	munlockall();*/
	mm_queues_fini();
	free_pages_fini();
}

void *thread_control(void *param)
{
	char				msgbuf[MM_CTLQUE_MSGSIZE + 1];
	mm_ctlmsg_t			*pmsg = (mm_ctlmsg_t *)msgbuf;

	while(mm_cont)
	{
		if(mq_receive(ctlque, msgbuf, MM_CTLQUE_MSGSIZE, NULL) == -1)
		{
			break;
		}

		switch(pmsg->ctl_cmd) {
		case MM_MSG_EXIT:
			do_exit(pmsg);
			break;
		case MM_MSG_PRESSURE:
			do_pressure(pmsg);
			break;
		default:
			break;
		}
	}

	return NULL;
}

void mm_go()
{
	char			msgbuf[MM_SVCQUE_MSGSIZE + 1];
	mm_svcmsg_t		*pmsg = (mm_svcmsg_t *)msgbuf;
	unsigned int	prio;
	pthread_t		tid;

	if(pthread_create(&tid, NULL, thread_control, NULL) != 0)
	{
		syslog(LOG_ERR, "failed to create the control thread");
		return;
	}

	syslog(LOG_INFO, "entered service loop; ready to take requests");
	while(mm_cont)
	{
		if(mq_receive(svcque, msgbuf, MM_SVCQUE_MSGSIZE, &prio) == -1)
		{
			break;
		}

		switch(pmsg->svc_cmd) {
		case MM_MSG_GETPAGES:
			if(do_getpages(pmsg) < 0)
			{
				syslog(LOG_EMERG, "fatal error in react to page request; "
					"mem mgr will exit");
				mm_cont = 0;
			}
			break;
		default:
			break;
		}
	}
}

void do_exit(mm_ctlmsg_t *pmsg)
{
	sem_t			*sem_wakeup;
	mm_svcmsg_t		wakemsg;

	pmsg->ctl_wake[MM_WAKE_LEN - 1] = '\0';
	sem_wakeup = sem_open(pmsg->ctl_wake, 0);
	if(sem_wakeup != SEM_FAILED)
	{
		sem_post(sem_wakeup);
		sem_close(sem_wakeup);
	}

	syslog(LOG_INFO, "received exit request; mem mgr will exit");
	mm_cont = 0;
	/* Wake up service queue in case it is blocked waiting for messages */
	wakemsg.svc_cmd = MM_MSG_INVALID;
	mq_send(svcque, (char *)&wakemsg, sizeof(wakemsg), 1);
}

int do_getpages(mm_svcmsg_t *pmsg)
{
	int					color, pages;
	sem_t				*sem_wakeup;
	mm_page_block_t		*pb, *p;

	pmsg->svc_wake[MM_WAKE_LEN - 1] = '\0';
	sem_wakeup = sem_open(pmsg->svc_wake, 0);
	if(sem_wakeup == SEM_FAILED)
	{
		return 0;
	}

	color = pmsg->svc_color;
	pages = pmsg->svc_count;
	pb = page_blocks_head[color];

	while(pb && pb_pages[color] > 0 && pages > 0)
	{
		if(pages >= pb->b_count)
		{
			free(pb->b_pages);
			pb->b_pages = NULL;

			pb_pages[color] -= pb->b_count;
			pages -= pb->b_count;

			pb->b_count = 0;
			pb = pb->next;
			page_blocks_head[color]->next = NULL;
			cache_pb_put(page_blocks_head[color]);
			page_blocks_head[color] = pb;
		}
		else
		{
			p = (void *)(ULCC_ALIGN_HIGHER((unsigned long)pb->b_pages) +
				ULCC_PAGE_BYTES * (pb->b_count - pages));
			if(munmap(p, ULCC_PAGE_BYTES * pages) == -1)
			{
				syslog(LOG_ERR, "munmap error during do_pagereq: %d, %m", errno);
				sem_post(sem_wakeup);
				sem_close(sem_wakeup);
				return -1;
			}
			/* Refill the page hole */
			if(mmap(p, ULCC_PAGE_BYTES * pages, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0, 0) != p)
			{
				syslog(LOG_ERR, "mmap error during do_pagereq: %d, %m", errno);
				sem_post(sem_wakeup);
				sem_close(sem_wakeup);
				return -1;
			}
			pb->b_count -= pages;
			pb_pages[color] -= pages;
			pages = 0;
		}
	}

	if(!pb)
	{
		page_blocks_tail[color] = NULL;
	}

	sem_post(sem_wakeup);
	sem_close(sem_wakeup);

	free_pages_lock();
	free_pages[color] = pb_pages[color];
	free_pages_unlock();

	return 0;
}

/* Memory manager should be reactive to system meomry pressure. This is handled
 * through the MM_MSG_PRESSURE message sent to control queue. Here we only
 * provide a simple `mechanism' to enable the user do this, but we do not provide
 * hardcoded `policy' as to how the memory manager should adjust its memory
 * holding.
 */
void do_pressure(mm_ctlmsg_t *pmsg)
{
	/* Increase memory holding */
	if(pmsg->ctl_arg > 0)
	{
		/* TODO */
	}
	/* Decrease memory holding */
	else if(pmsg->ctl_arg < 0)
	{
		/* TODO */
	}
}

long total_mem_pages(void)
{
	return sysconf(_SC_PHYS_PAGES);
}

long avail_mem_pages(void)
{
	return sysconf(_SC_AVPHYS_PAGES);
}

int free_pages_init()
{
	int		shmfd, i;

	sem_free_pages = sem_open(ULCC_NAME_SEM_MM_FREE_PAGES, O_CREAT,
		ULCC_PRIV_SEM_MM_FREE_PAGES, 0);
	if(sem_free_pages == SEM_FAILED)
	{
		syslog(LOG_ERR, "sem_open error for %s: %m", ULCC_NAME_SEM_MM_FREE_PAGES);
		return -1;
	}

	shmfd = shm_open(ULCC_NAME_SHM_MM_FREE_PAGES, O_RDWR | O_CREAT,
		ULCC_PRIV_SHM_MM_FREE_PAGES);
	if(shmfd == -1)
	{
		syslog(LOG_ERR, "shm_open error for %s: %m", ULCC_NAME_SHM_MM_FREE_PAGES);
		sem_close(sem_free_pages);
		sem_unlink(ULCC_NAME_SEM_MM_FREE_PAGES);
		sem_free_pages = SEM_FAILED;
		return -1;
	}

	if(ftruncate(shmfd, sizeof(unsigned long) * ULCC_NUM_CACHE_COLORS) == -1)
	{
		syslog(LOG_ERR, "ftruncate error for free_pages: %m");
		close(shmfd);
		shm_unlink(ULCC_NAME_SHM_MM_FREE_PAGES);
		sem_close(sem_free_pages);
		sem_unlink(ULCC_NAME_SEM_MM_FREE_PAGES);
		sem_free_pages = SEM_FAILED;
		return -1;
	}

	free_pages = mmap((void *)0, sizeof(unsigned long) * ULCC_NUM_CACHE_COLORS,
		PROT_READ | PROT_WRITE, MAP_SHARED, shmfd, 0);
	if(free_pages == MAP_FAILED)
	{
		syslog(LOG_ERR, "mmap error for free_pages: %m");
		close(shmfd);
		shm_unlink(ULCC_NAME_SHM_MM_FREE_PAGES);
		sem_close(sem_free_pages);
		sem_unlink(ULCC_NAME_SEM_MM_FREE_PAGES);
		sem_free_pages = SEM_FAILED;
		return -1;
	}
	close(shmfd);

	for(i = 0; i < ULCC_NUM_CACHE_COLORS; i++)
	{
		free_pages[i] = pb_pages[i];
	}

	free_pages_unlock();
	return 0;
}

void free_pages_fini()
{
	shm_unlink(ULCC_NAME_SHM_MM_FREE_PAGES);
	free_pages = MAP_FAILED;
	sem_close(sem_free_pages);
	sem_unlink(ULCC_NAME_SEM_MM_FREE_PAGES);
	sem_free_pages = SEM_FAILED;
}

/* Initialize page blocks structure
 */
#define PB_INIT_BATCH_PAGES		1024
int page_blocks_init()
{
	void			*mem, *mem_aligned;
	long			pages_held, delta;
	cc_uint64_t		*pfnbuf;
	int				i, cont;
	int				ret = 0;

	pfnbuf = malloc(sizeof(cc_uint64_t) * PB_INIT_BATCH_PAGES);
	if(!pfnbuf)
	{
		return -1;
	}

	cont = 1;
	pages_held = 0;
	while(pages_held < max_pages_held)
	{
		mem = malloc(ULCC_PAGE_BYTES * (PB_INIT_BATCH_PAGES + 1));
		if(!mem)
		{
			break;
		}
		mem_aligned = (void *)ULCC_ALIGN_HIGHER((unsigned long)mem);

		/* Enforce physical page mapping */
		for(i = 0; i < PB_INIT_BATCH_PAGES; i++)
		{
			*(char *)(mem_aligned + i * ULCC_PAGE_BYTES) = 'x';
		}

		if(cc_addr_translate(pfnbuf, (unsigned long)mem_aligned,
			PB_INIT_BATCH_PAGES) < 0)
		{
			syslog(LOG_ERR, "address translation error during page_blocks init;"
				" %ld pages already held", pages_held);
			free(mem);
			break;
		}

		/* Insert pages to page blocks queue */
		for(i = 0, delta = 0; i < PB_INIT_BATCH_PAGES; i++)
		{
			if(cc_pfn_present(pfnbuf[i]))
			{
				if(insert_page(mem_aligned + i * ULCC_PAGE_BYTES,
					cc_pfn_color(pfnbuf[i])) < 0)
				{
					syslog(LOG_ERR, "insert page error during page_blocks init;"
						" %ld pages already held", pages_held + delta);
					cont = 0;
					break;
				}
				delta++;
			}
		}

		pages_held += delta;
		free(mem);

		if(!cont)
		{
			break;
		}
	} /* while */

	/* How many pages have been collected */
	if(pages_held < max_pages_held)
	{
		page_blocks_fini();
		ret = -1;
	}

	free(pfnbuf);
	return ret;
}

void page_blocks_fini()
{
	mm_page_block_t		*p, *q;
	int					i;

	for(i = 0; i < ULCC_NUM_CACHE_COLORS; i++)
	{
		p = page_blocks_head[i];
		while(p)
		{
			q = p->next;
			mm_page_block_free(p);	/* Directly free it, bypassing pb cache */
			p = q;
		}

		pb_pages[i] = 0;
	}
}

int mm_queues_init()
{
	mode_t				mode_old, mode_new;
	struct mq_attr		qattr;

	/* Temporarily set umask to all permission, s.t. client program can
	open the service message queue */
	mode_new = 0;
	mode_old = umask(mode_new);
	qattr.mq_maxmsg = max_num_msg;
	qattr.mq_msgsize = MM_SVCQUE_MSGSIZE;
	svcque = mq_open(ULCC_NAME_MM_SVCQUE, O_RDWR | O_CREAT,
		ULCC_PRIV_MM_SVCQUE, &qattr);
	if(svcque == -1)
	{
		syslog(LOG_ERR, "mq_open error for service queue: %d, %m", errno);
		umask(mode_old);
		return -1;
	}
	umask(mode_old);

	qattr.mq_msgsize = MM_CTLQUE_MSGSIZE;
	ctlque = mq_open(ULCC_NAME_MM_CTLQUE, O_RDWR | O_CREAT,
		ULCC_PRIV_MM_CTLQUE, &qattr);
	if(ctlque == -1)
	{
		syslog(LOG_ERR, "mq_open error for control queue: %d, %m", errno);
		mq_close(svcque);
		mq_unlink(ULCC_NAME_MM_SVCQUE);
		svcque = -1;
		return -1;
	}

	return 0;
}

void mm_queues_fini()
{
	mq_close(svcque);
	mq_unlink(ULCC_NAME_MM_SVCQUE);
	svcque = -1;
	mq_close(ctlque);
	mq_unlink(ULCC_NAME_MM_CTLQUE);
	ctlque = -1;
}

/* Insert a page in specified color to the page blocks queue. After return, the
 * original page at vaddr will be remapped to zero page.
 */
int insert_page(void *vaddr, const int color)
{
	void				*remap_to;
	mm_page_block_t		*pb;

	/* Whether a new page block needs to be allocated */
	if(!(pb_pages[color] % MM_PAGE_BLOCK_PAGES))
	{
		pb = cache_pb_get();
		if(!pb)
		{
			syslog(LOG_ERR, "failed to get a page block from the pb cache");
			return -1;
		}

		if(!page_blocks_head[color])
		{
			/* This is an empty page block queue */
			page_blocks_head[color] = pb;
			page_blocks_tail[color] = pb;
		}
		else
		{
			page_blocks_tail[color]->next = pb;
			page_blocks_tail[color] = pb;
		}
	}
	else
	{
		pb = page_blocks_tail[color];
	}

	remap_to = (void *)(ULCC_ALIGN_HIGHER((unsigned long)pb->b_pages) +
		ULCC_PAGE_BYTES * (pb->b_count));
	if(mremap(vaddr, ULCC_PAGE_BYTES, ULCC_PAGE_BYTES,
		MREMAP_MAYMOVE | MREMAP_FIXED, remap_to) == MAP_FAILED)
	{
		syslog(LOG_ERR, "mremap error when inserting page: %d, %m", errno);
		return -1;
	}
	if(mmap(vaddr, ULCC_PAGE_BYTES, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0, 0) != vaddr)
	{
		syslog(LOG_ERR, "mmap error when inserting page: %d, %m", errno);
		return -1;
	}

	pb->b_count++;
	pb_pages[color]++;

	return 0;
}

mm_page_block_t *mm_page_block_new()
{
	mm_page_block_t		*pb;

	pb = (mm_page_block_t *)malloc(sizeof(mm_page_block_t));
	if(!pb)
	{
		return NULL;
	}

	pb->b_pages = malloc(ULCC_PAGE_BYTES * (MM_PAGE_BLOCK_PAGES + 1));
	if(!pb->b_pages)
	{
		free(pb);
		return NULL;
	}

	pb->b_count = 0;
	pb->b_max = MM_PAGE_BLOCK_PAGES;
	pb->next = NULL;

	return pb;
}

void mm_page_block_free(mm_page_block_t *pb)
{
	ULCC_FREE(pb->b_pages);
	free(pb);
}

int cache_pb_init()
{
	cachepb.head_free = NULL;
	return 0;
}

void cache_pb_fini()
{
	mm_page_block_t		*p, *q;

	p = cachepb.head_free;
	while(p)
	{
		q = p->next;
		mm_page_block_free(p);
		p = q;
	}

	cachepb.head_free = NULL;
}

mm_page_block_t *cache_pb_get()
{
	mm_page_block_t		*p;

	if(cachepb.head_free)
	{
		p = cachepb.head_free;
		cachepb.head_free = p->next;
		if(!p->b_pages)
		{
			p->b_pages = malloc(ULCC_PAGE_BYTES * (MM_PAGE_BLOCK_PAGES + 1));
			if(!p->b_pages)
			{
				mm_page_block_free(p);
				p = NULL;
			}
		}
	}
	else
	{
		p = mm_page_block_new();
	}

	return p;
}

void cache_pb_put(mm_page_block_t *p)
{
	p->next = cachepb.head_free;
	cachepb.head_free = p;
}

void free_pages_lock()
{
	while(sem_wait(sem_free_pages) == -1)
	{
		if(errno != EINTR)
		{
			break;
		}
	}
}

void free_pages_unlock()
{
	sem_post(sem_free_pages);
}

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
