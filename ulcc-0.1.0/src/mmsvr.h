/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_MMSVR_H_
#define _ULCC_MMSVR_H_

/* A block of page slots held by memory manager
 */
typedef struct mm_page_block_s
{
	void *b_pages;	/* A vm region holding pages in this block. The address of the
					 * first page in this block is ULCC_ALIGN_HIGHER(b_pages). */
	int b_count;	/* How many pages currently in this page block */
	int b_max;		/* Maximum available page slots in this block */
	struct mm_page_block_s *next;
} mm_page_block_t;

/* A simple page blocks cache
 */
typedef struct cache_page_blocks_s
{
	mm_page_block_t		*head_free;
} cache_page_blocks_t;


int parse_args(int argc, char *argv[]);
int mm_init();
void mm_fini();
void mm_go();

long total_mem_pages(void);
long avail_mem_pages(void);
int free_pages_init();
void free_pages_fini();
void free_pages_lock();
void free_pages_unlock();
int page_blocks_init();
void page_blocks_fini();
int mm_queues_init();
void mm_queues_fini();
mm_page_block_t *mm_page_block_new();
void mm_page_block_free(mm_page_block_t *pb);
int cache_pb_init();
void cache_pb_fini();
mm_page_block_t *cache_pb_get();
void cache_pb_put(mm_page_block_t *);
int insert_page(void *paddr, const int color);
int do_getpages(mm_svcmsg_t *pmsg);
void do_exit(mm_ctlmsg_t *pmsg);
void do_pressure(mm_ctlmsg_t *pmsg);
int stop_service(void);
void _new_sem_name(char *name, unsigned int rnd_seed);
void *thread_control(void *param);

#endif
