#ifndef ORIGIN_TCP_H
#define ORIGIN_TCP_H

#include "parallel.h"

#if defined(ORIGIN_TCP)

struct tcp_stream *find_stream(struct tcphdr *, struct ip *, int *, TCP_THREAD_LOCAL_P);
void add_new_tcp(struct tcphdr *, struct ip *, TCP_THREAD_LOCAL_P);
void nids_free_tcp_stream(struct tcp_stream *, TCP_THREAD_LOCAL_P);
void process_tcp(u_char *, int, TCP_THREAD_LOCAL_P);
int tcp_init(int, TCP_THREAD_LOCAL_P);
void tcp_exit(TCP_THREAD_LOCAL_P);
#endif

#endif
