/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#include <stdio.h>
#include <string.h>
#include <mqueue.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "ulcc.h"
#include "memmgr.h"
#include "cache.h"

int env_init()
{
	return 0;
}

int env_fini()
{
	sem_unlink(ULCC_NAME_SEM_CACHE_STATUS);
	sem_unlink(ULCC_NAME_SEM_BUSY_PAGES);
	sem_unlink(ULCC_NAME_SEM_MM_FREE_PAGES);

	shm_unlink(ULCC_NAME_SHM_CACHE_STATUS);
	shm_unlink(ULCC_NAME_SHM_BUSY_PAGES);
	shm_unlink(ULCC_NAME_SHM_MM_FREE_PAGES);

	mq_unlink(ULCC_NAME_MM_SVCQUE);
	mq_unlink(ULCC_NAME_MM_CTLQUE);
	return 0;
}

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		perror("no action specified (create or remove?)");
		return 1;
	}

	if(!strcmp(argv[1], "create"))
	{
		if(env_init())
		{
			fprintf(stderr, "ULCC environment creation error\n");
			return 1;
		}
		printf("ULCC environment created\n");
	}
	else if(!strcmp(argv[1], "remove"))
	{
		if(env_fini() < 0)
		{
			fprintf(stderr, "ULCC environment remove error\n");
			return 1;
		}
		printf("ULCC environment removed\n");
	}

	return 0;
}
