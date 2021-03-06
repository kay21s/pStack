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
#include "parallel.h"
#include "../ulcc-0.1.0/src/ulcc.h"
#include "../ulcc-0.1.0/src/remapper.h"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

int tcp_est = 0;
int tcp_data = 0;
int tcp_close = 0;
int tcp_reset = 0;

char trace_file[128];

uint64_t tcp_proc_time = 0;
uint64_t tcp_proc_num = 0;
uint64_t ip_proc_time = 0;
uint64_t ip_proc_num = 0;
uint64_t lb_proc_time = 0;
uint64_t lb_proc_num = 0;
uint64_t fifo_proc_time = 0;
uint64_t fifo_proc_num = 0;
uint64_t tcb_proc_time = 0;
uint64_t tcb_proc_num = 0;

int false_positive = 0;
int conflict_into_list = 0;

int search_num = 0, search_hit_num = 0, search_set_hit_num = 0;
int add_num = 0, add_hit_num = 0, add_set_hit_num = 0;
int delete_num = 0, delete_hit_num = 0, delete_set_hit_num = 0;
int not_found = 0;

int number_of_cpus_used;

int max_tcp_num = 0;
int total_tcp_num = 0;
int tcp_num = 0;

uint64_t total_packet_num = 0;
uint64_t total_packet_len = 0;

struct timeval begin_time, end_time;

extern TEST_SET tcp_test[];

void
tcp_callback (struct tcp_stream *a_tcp, void **this_time_not_needed)
{
	int dest;

#if 0
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
#endif

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

extern uint64_t total_num;
int
main (int argc, char *argv[])
{
	int opt, cpu_num, i;
	extern char *optarg;
	uint64_t process_time;
	float speed;

	while ((opt = getopt(argc, argv, "p:f:i:")) != -1) {
		switch (opt) {
			case 'p':
				cpu_num = atoi(optarg);
				if ((cpu_num < 0) || (cpu_num > MAX_CPU_CORES)) {
					printf("Wrongly specified CPU number=%d\n", cpu_num);
					return -1;
				} else
					printf("Prescribe %d cpu core(s).\n", atoi(optarg));
				break;
			case 'f':
				printf("Prescribe trace file: %s.\n", optarg);
				strncpy(trace_file, optarg, 127);
				break;
		}
	}
	
#if defined(PARALLEL)
	number_of_cpus_used = cpu_num;
#endif
	if (!nids_init()) {
		printf("%s\n", nids_errbuf);
		exit(1);
	}
	//nids_register_tcp (tcp_callback);
	nids_run ();
#if 1
	
#if defined(PARALLEL)
	int major_hit = 0, total_tcp = 0, false_positive = 0, step = 0, search_num = 0; 
	printf("Core Num:\tFalse Positive\t Conflict into List\t Major Location: Search \t Not found \t Add \t\t Delete \t Total TCP \t Max TCP\n");
	for (i = 1; i < MAX_CPU_CORES; i ++) {
		printf("%d:\t\t %d\t\t %d \t\t %d/%d \t\t %d \t %d/%d \t %d/%d \t %d \t %d \t %d\n", 
			i,
			tcp_test[i].false_positive,
			tcp_test[i].conflict_into_list,
			tcp_test[i].search_hit_num,
			tcp_test[i].search_num,
			tcp_test[i].not_found,
			tcp_test[i].add_hit_num,
			tcp_test[i].add_num,
			tcp_test[i].delete_hit_num,
			tcp_test[i].delete_num,
			tcp_test[i].total_tcp_num,
			tcp_test[i].max_tcp_num,
			tcp_test[i].step
			);

		major_hit += tcp_test[i].add_hit_num;
		total_tcp += tcp_test[i].total_tcp_num;
		false_positive += tcp_test[i].false_positive;
		step += tcp_test[i].step;
		search_num += tcp_test[i].search_num;
	}
	printf("Total_tcp = %d, Major location hit ratio is %.2f, search_step = %.2f, false positive = %d\n", 
		total_tcp, (float)(100 * major_hit)/(float)total_tcp, (float)step/(float)search_num, false_positive);
	printf("TCP time is %llu, number = %d\n", tcp_proc_time/(tcp_proc_num+1), tcp_proc_num);
	printf("IP time is %llu, number = %d\n", ip_proc_time/(ip_proc_num+1), ip_proc_num);
	printf("LB time is %llu, number = %d\n", lb_proc_time/(lb_proc_num+1), lb_proc_num);
	printf("FIFO time is %llu, number = %d\n", fifo_proc_time/(fifo_proc_num+1), fifo_proc_num);
#else
	printf("TCP time is %llu, number = %d\n", tcp_proc_time/(tcp_proc_num+1), tcp_proc_num);
	printf("IP time is %llu, number = %d\n", ip_proc_time/(ip_proc_num+1), ip_proc_num);
	printf("TCB time is %llu, number = %d\n", tcb_proc_time/(tcb_proc_num+1), tcb_proc_num);
	printf("false positive = %d, conflict into list = %d\n", false_positive, conflict_into_list);
	printf("Major location statistics: Search : %d/%d, Not found : %d, Add : %d/%d, Delete : %d/%d\n",
			search_hit_num, search_num, not_found, add_hit_num, add_num, delete_hit_num, delete_num);
	printf("Total TCP number is %d, Max TCP number is %d\n", total_tcp_num, max_tcp_num);
//	printf("average concurrent connection number : %d\n", total_num/total_packet_num);
#endif
	process_time = compute_time(&begin_time, &end_time);
	speed = ((float) (total_packet_len + 24 * total_packet_num) * 8) / ((float) process_time * 1000);

	printf("Processed Packets : %d, in %d (us) \n", total_packet_num, process_time);
	printf("Average Packet Length is %d\n", total_packet_len / total_packet_num);
	printf("Processing speed: %5.2f Gbps, %5.2f Mpps\n", speed, total_packet_num/(float)process_time);
#endif
	return 0;
}
