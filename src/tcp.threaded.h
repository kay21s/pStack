/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
  See the file COPYING for license details.
*/
#ifndef _NIDS_TCP_H
#define _NIDS_TCP_H
#include <sys/time.h>
#include "parallel.h"

struct skbuff {
	struct skbuff *next;
	struct skbuff *prev;

	void *data;
	u_int len;
	u_int truesize;
	u_int urg_ptr;

	char fin;
	char urg;
	u_int seq;
	u_int ack;
};

int tcp_init(int, TCP_THREAD_LOCAL_P);
void tcp_exit(TCP_THREAD_LOCAL_P);
void process_tcp(u_char *, int, TCP_THREAD_LOCAL_P);
void process_icmp(u_char *, TCP_THREAD_LOCAL_P);
void tcp_check_timeouts(struct timeval *, TCP_THREAD_LOCAL_P);

#endif /* _NIDS_TCP_H */
