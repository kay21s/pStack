/*
   Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
   See the file COPYING for license details.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "nids.h"

#define LOG_MAX 100
#define SZLACZEK "\n--------------------------------------------------\n"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

int tcp_est = 0;
int tcp_data = 0;
int tcp_close = 0;
int tcp_reset = 0;

extern uint64_t tcp_proc_time;
extern uint64_t tcp_proc_num;
extern int false_positive;
extern int conflict_into_list;

void
tcp_callback (struct tcp_stream *a_tcp, void **this_time_not_needed)
{
	int dest;

	printf("A tcp!, saddr = %d.%d.%d.%d,", 
		a_tcp->addr.saddr & 0x000000ff,
		(a_tcp->addr.saddr & 0x0000ff00) >> 8,
		(a_tcp->addr.saddr & 0x00ff0000) >> 16,
		(a_tcp->addr.saddr & 0xff000000) >> 24
		);
	printf("daddr = %d.%d.%d.%d,", 
		a_tcp->addr.daddr & 0x000000ff,
		(a_tcp->addr.daddr & 0x0000ff00) >> 8,
		(a_tcp->addr.daddr & 0x00ff0000) >> 16,
		(a_tcp->addr.daddr & 0xff000000) >> 24
		);
	printf("sport = %d, dport = %d\n", a_tcp->addr.source, a_tcp->addr.dest);

	if (a_tcp->nids_state == NIDS_JUST_EST) {
		a_tcp->client.collect ++;
		a_tcp->server.collect ++;
		tcp_est ++;
		return;
	} else if (a_tcp->nids_state == NIDS_DATA) {
      // seems the stream is closing, log as much as possible
//      do_log (adres (a_tcp->addr), a_tcp->server.data,
//	      a_tcp->server.count - a_tcp->server.offset);
		tcp_data ++;
		return;
	} else if (a_tcp->nids_state == NIDS_CLOSE) {
		tcp_close ++;
		return;
	} else if (a_tcp->nids_state == NIDS_RESET) {
		tcp_reset ++;
		return;
	}
}


int
main ()
{
	if (!nids_init ())
	{
		printf("%s\n", nids_errbuf);
		exit(1);
	}
	nids_register_tcp (tcp_callback);
	nids_run ();
	printf("TCP time is %llu, number = %d\n", tcp_proc_time/tcp_proc_num, tcp_proc_num);
	printf("false positive = %d, conflict into list = %d\n", false_positive, conflict_into_list);

	return 0;
}
