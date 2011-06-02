#ifndef CONN_TCP_H
#define CONN_TCP_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "nids.h"
#include "util.h"

typedef uint32_t idx_type ;

struct tcp_stream *find_stream(struct tcphdr *, struct ip *, int *);
void add_new_tcp(struct tcphdr *, struct ip *);
void nids_free_tcp_stream(struct tcp_stream *);
int tcp_init(int);
void tcp_exit(void);

#endif
