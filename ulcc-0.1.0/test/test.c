/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, as published by the
 * Free Software Foundation. Read the file COPYING for details of GNU GPL.
 */

#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include "ulcc.h"
#include "remapper.h"

/* Get time difference */
#define TDIFF(t1, t2) (((t2).tv_sec + ((double)((t2).tv_usec))/1000000) - \
		((t1).tv_sec + ((double)((t1).tv_usec))/1000000))

/* This example demonstrates the use of ULCC to improve the performance of a
 * weak-locality, loop-pattern program, which was not doable before ULCC.
 */
void test1()
{
	cc_aid_t		aid_strong, aid_weak;
	char			*p, *start, *end, c;
	int				i, size = 4096 * 781;
	struct timeval	t1, t2;
	void			*mem;
	cc_cacheslot_t	cs;

	printf("Start Test 1: improving the performance of a weak-locality loop\n");

	/* Allocate a large data region whose size is larger than LLC */
	mem = malloc(size);
	start = (char *)ULCC_ALIGN_HIGHER((unsigned long)mem);
	end = start + 4096 * 780;
	for(p = start; p < end; p += 4096)
	{
		*p = 'x';
	}

	/* Test the looping time before using ULCC */
	gettimeofday(&t1, NULL);
	for(i = 0; i < 10000; i++)
	{
		for(p = start; p < end; p += 64)
		{
			c = *p;
		}
	}
	gettimeofday(&t2, NULL);
	printf("Time w/o ULCC: %.4lf s\n", TDIFF(t1, t2));

	/* Allocate a private cache space for part of the large data, such that
	 * this part of data can be kept in LLC across different loops, w/o
	 * incurring misses.
	 */
	cs.s_type = CC_PRIVATE;
	cs.s_size = 4096 * 680;
	aid_strong = cc_alloc2((unsigned long)start,
		(unsigned long)(start + 4096 * 640), NULL, &cs, 0);
	if(aid_strong == CC_AID_INVALID)
	{
		printf("cc_alloc2 error\n");
	}

	/* We don't have enough cache space to hold the rest of the large data, so
	 * we squeeze them into a small shared cache space, which is separated from
	 * the previously allocated private space.
	 */
	cs.s_type = CC_SHARED;
	cs.s_size = 4096 * 60;
	aid_weak = cc_alloc2_cpus((unsigned long)(start + 4096 * 640),
		(unsigned long)(end), NULL, &cs, 0);
	if(aid_weak == CC_AID_INVALID)
	{
		printf("cc_alloc2_cpus error\n");
	}

	/* Now we test the time of the looping again. Across different loops, part
	 * of the data is kept in LLC w/o suffering the disruption of the rest of
	 * the data. It should be faster than the previous time.
	 */
	gettimeofday(&t1, NULL);
	for(i = 0; i < 10000; i++)
	{
		for(p = start; p < end; p += 64)
		{
			c = *p;
		}
	}
	gettimeofday(&t2, NULL);
	printf("Time w/ ULCC: %.4lf s\n", TDIFF(t1, t2));

	/* Deallocate */
	if(cc_dealloc(aid_strong) < 0)
	{
		fprintf(stderr, "dealloc aid_strong error\n");
	}
	if(cc_dealloc(aid_weak) < 0)
	{
		fprintf(stderr, "dealloc aid_weak error\n");
	}

	free(mem);
	printf("Test 1 finished\n\n");
}

char *data1_start, *data1_end;
char *data2_start, *data2_end;
int ulcc_enable = 0;
void *thread_test2(void *param)
{
	int				it = (int)param, i;
	char			*p, r;
	struct timeval	t1, t2;

	if(it % 2)	/* strong locality */
	{
		gettimeofday(&t1, NULL);
		for(i = 0; i < 30000; i++)
		{
			for(p = data1_start; p < data1_end; p += 64)
			{
				r = *p;
			}
		}
		gettimeofday(&t2, NULL);
		printf("%s ULCC support: strong locality - %.4lf\n",
			ulcc_enable ? "With" : "Without",
			TDIFF(t1, t2));
	}
	else	/* weak locality */
	{
		gettimeofday(&t1, NULL);
		for(i = 0; i < 50000; i++)
		{
			for(p = data1_start; p < data1_end; p += 64)
			{
				r = *p;
			}
		}
		gettimeofday(&t2, NULL);
		printf("%s ULCC support: weak locality - %.4lf\n",
			ulcc_enable ? "With" : "Without",
			TDIFF(t1, t2));
	}

	return NULL;
}

void test2()
{
	int				size1 = 2 * 1024 * 1024, size2 = 8 * 1024 * 1024;
	pthread_t		tid[2] = {-1, -1};
	void			*data1, *data2;
	cc_aid_t		aid_data1, aid_data2;
	cc_cacheslot_t	cs;
	char			*p;
	int				i;

	/* Create two data regions to be scanned by two threads
	 */
	data1 = malloc(size1);
	data1_start = (char *)ULCC_ALIGN_HIGHER((unsigned long)data1);
	data1_end = (char *)ULCC_ALIGN_LOWER((unsigned long)(data1 + size1));

	data2 = malloc(size2);
	data2_start = (char *)ULCC_ALIGN_HIGHER((unsigned long)data2);
	data2_end = (char *)ULCC_ALIGN_LOWER((unsigned long)(data2 + size2));

	for(p = data1_start; p < data1_end; p += 4096)
	{
		*p = 'x';
	}
	for(p = data2_start; p < data2_end; p += 4096)
	{
		*p = 'x';
	}

	printf("Start Test 2: improving the performance of a strong-locality loop"
		" co-running with a weak-locality loop\n");

	/* Do scanning w/o the support of ULCC */
	ulcc_enable = 0;
	for(i = 0; i < 2; i++)
	{
		if(pthread_create(&tid[i], NULL, thread_test2, (void *)i))
		{
			printf("failed to create thread %d!\n", i);
			return;
		}
	}
	for(i = 0; i < 2; i++)
	{
		pthread_join(tid[i], NULL);
	}

	/* Allocate cache space and do scanning w/ the support of ULCC
	 */
	cs.s_type = CC_PRIVATE;
	cs.s_size = size1 + cc_cache_size() / cc_cache_colors() * 2;
	aid_data1 = cc_alloc2((unsigned long)data1_start, (unsigned long)data1_end,
		NULL, &cs, CC_ALLOC_NOMOVE | CC_MAPORDER_RAND);
	if(aid_data1 == CC_AID_INVALID)
	{
		perror("cc_alloc2 error for strong-locality data1");
	}

	cs.s_type = CC_SHARED;
	cs.s_size = cc_cache_size() / cc_cache_colors() * 1;
	aid_data2 = cc_alloc2((unsigned long)data2_start, (unsigned long)data2_end,
		NULL, &cs, 0);
	if(aid_data2 == CC_AID_INVALID)
	{
		perror("cc_alloc2 error for weak-locality data2");
	}

	ulcc_enable = 1;
	for(i = 0; i < 2; i++)
	{
		if(pthread_create(&tid[i], NULL, thread_test2, (void *)i))
		{
			printf("failed to create thread %d!\n", i);
			return;
		}
	}
	for(i = 0; i < 2; i++)
	{
		pthread_join(tid[i], NULL);
	}

	if(cc_dealloc(aid_data1) < 0)
	{
		perror("cc_dealloc error for data1");
	}
	if(cc_dealloc(aid_data2) < 0)
	{
		perror("cc_dealloc error for data2");
	}

	printf("Test 2 finished\n\n");
	free(data1);
	free(data2);
}

void test3()
{
	cc_aid_t		aid_strong, aid_weak;
	char			*p, *start, *end, c;
	int				i, size = 4096 * 781;
	struct timeval	t1, t2;
	void			*mem;
	cc_cacheslot_t	cs;

	printf("Start Test 3: improving the performance of a weak-locality loop\n");

	/* Allocate a large data region whose size is larger than LLC */
	mem = malloc(size);
	start = (char *)ULCC_ALIGN_HIGHER((unsigned long)mem);
	end = start + 4096 * 780;
	for(p = start; p < end; p += 4096)
	{
		*p = 'x';
	}

	/* Test the looping time before using ULCC */
	gettimeofday(&t1, NULL);
	for(i = 0; i < 10000; i++)
	{
		for(p = start; p < end; p += 64)
		{
			c = *p;
		}
	}
	gettimeofday(&t2, NULL);
	printf("Time w/o ULCC: %.4lf s\n", TDIFF(t1, t2));

	cs.s_type = CC_PRIVATE;
	cs.s_size = 4096 * 680;
	aid_strong = cc_alloc(NULL, NULL, &cs, 0);
	if(aid_strong == CC_AID_INVALID)
	{
		printf("cc_alloc error for strong locality reservation\n");
	}

	cs.s_type = CC_SHARED;
	cs.s_size = 4096 * 60;
	aid_weak = cc_alloc_cpus(NULL, NULL, &cs, 0);
	if(aid_weak == CC_AID_INVALID)
	{
		printf("cc_alloc_cpus error for weak locality reservation\n");
	}

	if(cc_alloc_add2(aid_strong, (unsigned long)start,
		(unsigned long)(start + 4096 * 640), 0) != aid_strong)
	{
		printf("cc_alloc_add2 error for strong locality data");
	}
	if(cc_alloc_add2(aid_weak, (unsigned long)(start + 4096 * 640),
		(unsigned long)end, 0) != aid_weak)
	{
		printf("cc_alloc_add2 error for weak locality data");
	}

	/* Now we test the time of the looping again. Across different loops, part
	 * of the data is kept in LLC w/o suffering the disruption of the rest of
	 * the data. It should be faster than the previous time.
	 */
	gettimeofday(&t1, NULL);
	for(i = 0; i < 10000; i++)
	{
		for(p = start; p < end; p += 64)
		{
			c = *p;
		}
	}
	gettimeofday(&t2, NULL);
	printf("Time w/ ULCC: %.4lf s\n", TDIFF(t1, t2));

	/* Deallocate */
	if(cc_dealloc(aid_strong) < 0)
	{
		fprintf(stderr, "dealloc aid_strong error\n");
	}
	if(cc_dealloc(aid_weak) < 0)
	{
		fprintf(stderr, "dealloc aid_weak error\n");
	}

	free(mem);
	printf("Test 3 finished\n\n");
}

void test_remapper()
{
	int					size = 1024 * 1024 * 32;	/* 32MB */
	unsigned long		start, end;
	struct timeval		t1, t2;
	void				*mem;
	cc_cacheregn_t		regn;

	mem = malloc(size);
	start = ULCC_ALIGN_HIGHER((unsigned long)mem);
	end = ULCC_ALIGN_LOWER((unsigned long)(mem + size));

	cc_cacheregn_clr(&regn);
	cc_cacheregn_set(&regn, 0, 1, 1);

	gettimeofday(&t1, NULL);
	if(cc_remap(&start, &end, 1, &regn, 0, NULL) < 0)
	{
		printf("cc_remap failed\n");
	}
	gettimeofday(&t2, NULL);

	printf("time on cc_remap: %.4lf\n", TDIFF(t1, t2));
	free(mem);
}

int main(int argc, char *argv[])
{
	/* Initialize ULCC */
	if(cc_init() < 0)
	{
		fprintf(stderr, "ULCC init error\n");
		return 1;
	}

	test1();
	test2();
	test3();
	test_remapper();

	/* Finalize ULCC */
	cc_fini();
	return 0;
}
