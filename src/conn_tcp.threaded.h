#ifndef CONN_TCP_H
#define CONN_TCP_H

#include "conn_attribute.h"
#include "parallel.h"

#if defined(NEW_TCP)

struct tcp_stream *find_stream(struct tcphdr *, struct ip *, int *, TCP_THREAD_LOCAL_P);
void add_new_tcp(struct tcphdr *, struct ip *, TCP_THREAD_LOCAL_P);
void nids_free_tcp_stream(struct tcp_stream *, TCP_THREAD_LOCAL_P);
void process_tcp(u_char *, int, TCP_THREAD_LOCAL_P);
int tcp_init(int, TCP_THREAD_LOCAL_P);
void tcp_exit(TCP_THREAD_LOCAL_P);
#endif

#endif
