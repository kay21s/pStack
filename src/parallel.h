
#ifndef PARALLEL_H
#define PARALLEL_H

#define MAX_CPU_CORES 8

typedef struct _ip_thread_local_p {
	struct timer_list *timer_head;
	struct timer_list *timer_tail;
	struct hostfrags **fragtable;
	struct hostfrags *this_host;
	int self_cpu_id;
	int hash_size;
	int numpack;
	int timenow;
	unsigned int time0;
} __attribute__ ((aligned (64))) _IP_THREAD_LOCAL_P ;
typedef _IP_THREAD_LOCAL_P *IP_THREAD_LOCAL_P;

typedef struct _tcp_thread_local_p {
	struct tcp_timeout *nids_tcp_timeouts;
	void *tcp_stream_table;
	struct tcp_stream *tcb_array;
	int tcp_num;
	int tcp_stream_table_size;
	int self_cpu_id;
} __attribute__ ((aligned (64))) _TCP_THREAD_LOCAL_P ;
typedef _TCP_THREAD_LOCAL_P *TCP_THREAD_LOCAL_P;

#endif
