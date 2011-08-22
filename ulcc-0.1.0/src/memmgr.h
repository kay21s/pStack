/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_MEMMGR_H_
#define _ULCC_MEMMGR_H_

#define ULCC_NAME_MM_SVCQUE				"/ulcc-mq-mm-svcque"
#define ULCC_NAME_MM_CTLQUE				"/ulcc-mq-mm-ctlque"
#define ULCC_NAME_SHM_MM_FREE_PAGES		"/ulcc-shm-mm-free-pages"
#define ULCC_NAME_SEM_MM_FREE_PAGES		"/ulcc-sem-mm-free-pages"

#define ULCC_PRIV_MM_SVCQUE				(S_IWGRP | S_IWOTH)
#define ULCC_PRIV_MM_CTLQUE				0
#define ULCC_PRIV_SHM_MM_FREE_PAGES		(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define ULCC_PRIV_SEM_MM_FREE_PAGES		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP \
										| S_IROTH | S_IWOTH)

#define MM_PAGE_BLOCK_PAGES				512
/* The format of wakeup semaphore name: "/ulcc-" followed some 0/1's */
#define MM_WAKE_LEN						(sizeof(unsigned int) * 8 + 7)

/* Service message format
 */
#ifdef _ULCC_CONFIG_KMODULE_PAGEPIPE	/* TODO */
typedef struct mm_svcmsg_s
{
	int				svc_cmd;		/* Request: MM_REQ_PAGES or MM_REQ_NOTIFY? */
	unsigned long	svc_pipeid;		/* Id of the pagepipe */
	unsigned long	svc_key;		/* Key held by the requester */
	int				svc_color;
	int				svc_count;
	char			svc_wake[MM_WAKE_LEN];
} mm_svcmsg_t;
#else
typedef struct mm_svcmsg_s
{
	int		svc_cmd;
	int		svc_color;
	int		svc_count;
	char	svc_wake[MM_WAKE_LEN];
} mm_svcmsg_t;
#endif
#define MM_SVCQUE_MSGSIZE	(sizeof(mm_svcmsg_t))

/* Control message format
 */
typedef struct mm_ctlmsg_s
{
	int		ctl_cmd;
	long	ctl_arg;
	char	ctl_wake[MM_WAKE_LEN];
} mm_ctlmsg_t;
#define MM_CTLQUE_MSGSIZE	(sizeof(mm_ctlmsg_t))

/* Messages */
#define MM_MSG_INVALID			0

#define MM_MSG_GETPAGES			1	/* Get messages in a specific color */
#define MM_MSG_PUTPAGES			2	/* Not used in current version */
#define MM_MSG_PRESSURE			1	/* Memory pressure notification */
#define MM_MSG_EXIT				31	/* Require memory manager to exit */

/* Message priorities */
#define MM_MSGPRIO_GETPAGES		1
#define MM_MSGPRIO_PUTPAGES		2	/* Not used in current version */
#define MM_MSGPRIO_PRESSURE		1
#define MM_MSGPRIO_EXIT			31

#endif
