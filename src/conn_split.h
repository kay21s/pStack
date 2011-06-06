#ifndef CONN_TCP_H
#define CONN_TCP_H

#include "conn_attribute.h"

#if defined(SPLIT_TCP)

struct tcp_stream *find_stream(struct tcphdr *, struct ip *, int *);
void nids_free_tcp_stream(struct tcp_stream *);
void process_tcp(u_char *, int);
int tcp_init(int);
void tcp_exit(void);
#endif

#endif
