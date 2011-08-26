#ifndef PARALLEL_H
#define PARALLEL_H

#include <stdint.h>
#include "conn_attribute.h"

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
	struct tcp_stream *tcb_array;
	uint64_t *bitmap;
#if defined(MAJOR_INDEXFREE_TCP)
	elem_list_type **conflict_list;
#endif

#if defined(ORIGIN_TCP)
	struct tcp_stream **tcp_stream_table;
	struct tcp_stream *free_streams;
	struct tcp_stream *streams_pool;
	struct tcp_stream *tcp_latest;
	struct tcp_stream *tcp_oldest;
	int max_stream;
#else
	void *tcp_stream_table;
#endif

	int bitmap_size;
	int walker;
//	int tcp_num;
	int tcp_stream_table_size;
	int self_cpu_id;
} __attribute__ ((aligned (64))) _TCP_THREAD_LOCAL_P ;
typedef _TCP_THREAD_LOCAL_P *TCP_THREAD_LOCAL_P;

typedef struct test_set {
	uint32_t conflict_into_list;
	uint32_t false_positive;

	// For Major Location
	uint32_t search_num, search_hit_num, search_set_hit_num;
	uint32_t add_num, add_hit_num, add_set_hit_num;
	uint32_t delete_num, delete_hit_num, delete_set_hit_num;
	uint32_t not_found;
	uint32_t tcp_num;
	uint32_t total_tcp_num;
	uint32_t max_tcp_num;
} __attribute__ ((aligned (64))) TEST_SET;

#endif
