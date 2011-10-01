#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <nmmintrin.h>
#include "nids.h"
#include "util.h"
#include "tcp.threaded.h"

#if defined(ORIGIN_TCP)

extern TEST_SET tcp_test[MAX_CPU_CORES];

extern int number_of_cpus_used;
extern struct proc_node *tcp_procs;

extern int get_ts(struct tcphdr *, unsigned int *);
extern int get_wscale(struct tcphdr *, unsigned int *);
extern void del_tcp_closing_timeout(struct tcp_stream *, TCP_THREAD_LOCAL_P);
extern void purge_queue(struct half_stream *);
extern void handle_ack(struct half_stream *, u_int);
extern void tcp_queue(struct tcp_stream *, struct tcphdr *,
	struct half_stream *, struct half_stream *,
	char *, int, int, TCP_THREAD_LOCAL_P);
extern void prune_queue(struct half_stream *, struct tcphdr *);

u_int
mk_hash_index(struct tuple4 addr, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
#if defined(CRC_HASH)
	unsigned int crc1 = 0;
	uint32_t port = addr.source ^ addr.dest;
	crc1 = _mm_crc32_u32(crc1, addr.saddr ^ addr.daddr);
	crc1 = _mm_crc32_u32(crc1, port);
	return crc1 % tcp_thread_local_p->tcp_stream_table_size;
#else
	u_int hash = addr.saddr ^ addr.source ^ addr.daddr ^ addr.dest;
	return hash % tcp_thread_local_p->tcp_stream_table_size;
#endif
}

void
nids_free_tcp_stream(struct tcp_stream * a_tcp,TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	int hash_index = a_tcp->hash_index;
	struct lurker_node *i, *j;

	tcp_test[tcp_thread_local_p->self_cpu_id].delete_num ++;

	del_tcp_closing_timeout(a_tcp,tcp_thread_local_p);
	purge_queue(&a_tcp->server);
	purge_queue(&a_tcp->client);

	if (a_tcp->next_node)
		a_tcp->next_node->prev_node = a_tcp->prev_node;
	if (a_tcp->prev_node)
		a_tcp->prev_node->next_node = a_tcp->next_node;
	else
		tcp_thread_local_p->tcp_stream_table[hash_index] = a_tcp->next_node;
	if (a_tcp->next_time)
		a_tcp->next_time->prev_time = a_tcp->prev_time;
	if (a_tcp->prev_time)
		a_tcp->prev_time->next_time = a_tcp->next_time;
	if (a_tcp == tcp_thread_local_p->tcp_oldest)
		tcp_thread_local_p->tcp_oldest = a_tcp->prev_time;
	if (a_tcp == tcp_thread_local_p->tcp_latest)
		tcp_thread_local_p->tcp_latest = a_tcp->next_time;

	i = a_tcp->listeners;

	while (i) {
		j = i->next;
		free(i);
		i = j;
	}
	a_tcp->next_free = tcp_thread_local_p->free_streams;
	tcp_thread_local_p->free_streams = a_tcp;
	tcp_test[tcp_thread_local_p->self_cpu_id].tcp_num --;
}

void
add_new_tcp(struct tcphdr * this_tcphdr, struct ip * this_iphdr,TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	struct tcp_stream *tolink;
	struct tcp_stream *a_tcp;
	int hash_index;
	struct tuple4 addr;

	tcp_test[tcp_thread_local_p->self_cpu_id].add_num ++;

	addr.source = ntohs(this_tcphdr->th_sport);
	addr.dest = ntohs(this_tcphdr->th_dport);
	addr.saddr = this_iphdr->ip_src.s_addr;
	addr.daddr = this_iphdr->ip_dst.s_addr;
	hash_index = mk_hash_index(addr, tcp_thread_local_p);

/*
	if (tcp_thread_local_p->tcp_num > tcp_thread_local_p->max_stream) {
		struct lurker_node *i;

		tcp_thread_local_p->tcp_oldest->nids_state = NIDS_TIMED_OUT;
		for (i = tcp_thread_local_p->tcp_oldest->listeners; i; i = i->next)
			(i->item) (tcp_thread_local_p->tcp_oldest, &i->data);
		nids_free_tcp_stream(tcp_thread_local_p->tcp_oldest,tcp_thread_local_p);
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_TOOMUCH, tcp_thread_local_p->ugly_iphdr, this_tcphdr);
	}
*/  

	a_tcp = tcp_thread_local_p->free_streams;
	if (!a_tcp) {
		int i;
		tcp_thread_local_p->streams_pool = (struct tcp_stream *) malloc((tcp_thread_local_p->max_stream + 1) * sizeof(struct tcp_stream));
		if (!tcp_thread_local_p->streams_pool) {
			nids_params.no_mem("tcp_init");
			exit(0);
		}
		for (i = 0; i < tcp_thread_local_p->max_stream; i++)
			tcp_thread_local_p->streams_pool[i].next_free = &(tcp_thread_local_p->streams_pool[i + 1]);
		tcp_thread_local_p->streams_pool[tcp_thread_local_p->max_stream].next_free = 0;
		tcp_thread_local_p->free_streams = tcp_thread_local_p->streams_pool;
		a_tcp = tcp_thread_local_p->free_streams;
	}
	if (!a_tcp) {
		fprintf(stderr, "gdb me ...\n");
		pause();
	}
	tcp_thread_local_p->free_streams = a_tcp->next_free;

	int core = tcp_thread_local_p->self_cpu_id;
	tcp_test[core].tcp_num ++;
	tcp_test[core].total_tcp_num ++;
	if (tcp_test[core].tcp_num > tcp_test[core].max_tcp_num) {
		tcp_test[core].max_tcp_num = tcp_test[core].tcp_num;
	}

	tolink = tcp_thread_local_p->tcp_stream_table[hash_index];
	memset(a_tcp, 0, sizeof(struct tcp_stream));
	a_tcp->hash_index = hash_index;
	a_tcp->addr = addr;
	a_tcp->client.state = TCP_SYN_SENT;
	a_tcp->client.seq = ntohl(this_tcphdr->th_seq) + 1;
	a_tcp->client.first_data_seq = a_tcp->client.seq;
	a_tcp->client.window = ntohs(this_tcphdr->th_win);
	a_tcp->client.ts_on = get_ts(this_tcphdr, &a_tcp->client.curr_ts);
	a_tcp->client.wscale_on = get_wscale(this_tcphdr, &a_tcp->client.wscale);
	a_tcp->server.state = TCP_CLOSE;
	a_tcp->next_node = tolink;
	a_tcp->prev_node = 0;
	if (tolink)
		tolink->prev_node = a_tcp;
	tcp_thread_local_p->tcp_stream_table[hash_index] = a_tcp;
	a_tcp->next_time = tcp_thread_local_p->tcp_latest;
	a_tcp->prev_time = 0;
	if (!tcp_thread_local_p->tcp_oldest)
		tcp_thread_local_p->tcp_oldest = a_tcp;
	if (tcp_thread_local_p->tcp_latest)
		tcp_thread_local_p->tcp_latest->prev_time = a_tcp;
	tcp_thread_local_p->tcp_latest = a_tcp;
}

/*
struct tcp_stream *
find_stream(struct tcphdr * this_tcphdr, struct ip * this_iphdr,
			            int *from_client, TCP_THREAD_LOCAL_P  tcp_thread_local_p) {
	int hash_index;
	struct tuple4 addr;
	struct tcp_stream *a_tcp;

	addr.source = this_tcphdr->th_sport;
	addr.dest = this_tcphdr->th_dport;
	addr.saddr = this_iphdr->ip_src.s_addr;
	addr.daddr = this_iphdr->ip_dst.s_addr;

	hash_index = mk_hash_index(addr, tcp_thread_local_p);

	for (a_tcp = tcp_thread_local_p->tcp_stream_table[hash_index]; a_tcp; a_tcp = a_tcp->next_node) {

		if( (addr.saddr == a_tcp->addr.saddr)
			&& (addr.daddr == a_tcp->addr.daddr)
			&& (addr.source == a_tcp->addr.source)
			&& (addr.dest == a_tcp->addr.dest) ) {
			// from the client side
			*from_client = 1;
			return a_tcp;

		} else if ( (addr.saddr == a_tcp->addr.daddr)
			&& (addr.daddr == a_tcp->addr.saddr)
			&& (addr.source == a_tcp->addr.dest)
			&& (addr.dest == a_tcp->addr.source)) {
			// from the server side
			*from_client = 0;
			return a_tcp;
		}
	}
	return NULL;
}
*/

struct tcp_stream *
nids_find_tcp_stream(struct tuple4 *addr, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	int hash_index;
	struct tcp_stream *a_tcp;

	hash_index = mk_hash_index(*addr, tcp_thread_local_p);
	for (a_tcp = tcp_thread_local_p->tcp_stream_table[hash_index];
			a_tcp && memcmp(&a_tcp->addr, addr, sizeof (struct tuple4));
			a_tcp = a_tcp->next_node);
	return a_tcp ? a_tcp : 0;
}

struct tcp_stream *
find_stream(struct tcphdr * this_tcphdr, struct ip * this_iphdr,
	    int *from_client, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	struct tuple4 this_addr, reversed;
	struct tcp_stream *a_tcp;

	tcp_test[tcp_thread_local_p->self_cpu_id].search_num ++;

	this_addr.source = ntohs(this_tcphdr->th_sport);
	this_addr.dest = ntohs(this_tcphdr->th_dport);
	this_addr.saddr = this_iphdr->ip_src.s_addr;
	this_addr.daddr = this_iphdr->ip_dst.s_addr;
	a_tcp = nids_find_tcp_stream(&this_addr, tcp_thread_local_p);
	if (a_tcp) {
		*from_client = 1;
		return a_tcp;
	}
	reversed.source = ntohs(this_tcphdr->th_dport);
	reversed.dest = ntohs(this_tcphdr->th_sport);
	reversed.saddr = this_iphdr->ip_dst.s_addr;
	reversed.daddr = this_iphdr->ip_src.s_addr;
	a_tcp = nids_find_tcp_stream(&reversed, tcp_thread_local_p);
	if (a_tcp) {
		*from_client = 0;
		return a_tcp;
	}

	tcp_test[tcp_thread_local_p->self_cpu_id].not_found ++;
	return 0;
}

void
tcp_exit(TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	int i;
	struct lurker_node *j;
	struct tcp_stream *a_tcp, *t_tcp;

	if (!tcp_thread_local_p->tcp_stream_table || !tcp_thread_local_p->streams_pool)
		return;
	for (i = 0; i < tcp_thread_local_p->tcp_stream_table_size; i++) {
		a_tcp = tcp_thread_local_p->tcp_stream_table[i];
		while(a_tcp) {
			t_tcp = a_tcp;
			a_tcp = a_tcp->next_node;
			for (j = t_tcp->listeners; j; j = j->next) {
				t_tcp->nids_state = NIDS_EXITING;
				(j->item)(t_tcp, &j->data);
			}
			nids_free_tcp_stream(t_tcp, tcp_thread_local_p);
		}
	}
	free(tcp_thread_local_p->tcp_stream_table);
	tcp_thread_local_p->tcp_stream_table = NULL;
	free(tcp_thread_local_p->streams_pool);
	tcp_thread_local_p->streams_pool = NULL;
	/* FIXME: anything else we should free? */
	/* yes plz.. */
	//  tcp_latest = tcp_oldest = NULL;
	// tcp_thread_local_p->tcp_num = 0;
}

int
tcp_init(int size, TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	int i;
	struct tcp_timeout *tmp;

	if (!size) return 0;
	tcp_thread_local_p->tcp_stream_table_size = size;
	tcp_thread_local_p->tcp_stream_table = calloc(tcp_thread_local_p->tcp_stream_table_size, sizeof(char *));
	if (!tcp_thread_local_p->tcp_stream_table) {
		nids_params.no_mem("tcp_init");
		return -1;
	}
	tcp_thread_local_p->max_stream = 3 *tcp_thread_local_p->tcp_stream_table_size;
	tcp_thread_local_p->streams_pool = (struct tcp_stream *) malloc((tcp_thread_local_p->max_stream + 1) * sizeof(struct tcp_stream));
	if (!tcp_thread_local_p->streams_pool) {
		nids_params.no_mem("tcp_init");
		return -1;
	}
	for (i = 0; i < tcp_thread_local_p->max_stream; i++)
		tcp_thread_local_p->streams_pool[i].next_free = &(tcp_thread_local_p->streams_pool[i + 1]);
	tcp_thread_local_p->streams_pool[tcp_thread_local_p->max_stream].next_free = 0;
	tcp_thread_local_p->free_streams = tcp_thread_local_p->streams_pool;

	while (tcp_thread_local_p->nids_tcp_timeouts) {
		tmp = tcp_thread_local_p->nids_tcp_timeouts->next;
		free(tcp_thread_local_p->nids_tcp_timeouts);
		tcp_thread_local_p->nids_tcp_timeouts = tmp;
	}
	return 0;
}

void
process_tcp(u_char * data, int skblen, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	struct ip *this_iphdr = (struct ip *)data;
	struct tcphdr *this_tcphdr = (struct tcphdr *)(data + 4 * this_iphdr->ip_hl);
	int datalen, iplen;
	int from_client = 1;
	unsigned int tmp_ts;
	struct tcp_stream *a_tcp;
	struct half_stream *snd, *rcv;

#if 0
	static int a =0;
	a ++;
	if (a % 50000 == 0)
		printf(" %d \n", a);
#endif

	//  ugly_iphdr = this_iphdr;
	iplen = ntohs(this_iphdr->ip_len);
	if ((unsigned)iplen < 4 * this_iphdr->ip_hl + sizeof(struct tcphdr)) {
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
				this_tcphdr);
		return;
	} // ktos sie bawi

	datalen = iplen - 4 * this_iphdr->ip_hl - 4 * this_tcphdr->th_off;

	if (datalen < 0) {
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
				this_tcphdr);
		return;
	} // ktos sie bawi

	if ((this_iphdr->ip_src.s_addr | this_iphdr->ip_dst.s_addr) == 0) {
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
				this_tcphdr);
		return;
	}
	//  if (!(this_tcphdr->th_flags & TH_ACK))
	//    detect_scan(this_iphdr);
	if (!nids_params.n_tcp_streams) return;

#if 0
	{
		printf("IN PROCESS_TCP A tcp!, saddr = %d.%d.%d.%d,", 
				this_iphdr->ip_src.s_addr & 0x000000ff,
				(this_iphdr->ip_src.s_addr & 0x0000ff00) >> 8,
				(this_iphdr->ip_src.s_addr & 0x00ff0000) >> 16,
				(this_iphdr->ip_src.s_addr & 0xff000000) >> 24
		      );
		printf("daddr = %d.%d.%d.%d,", 
				this_iphdr->ip_dst.s_addr & 0x000000ff,
				(this_iphdr->ip_dst.s_addr & 0x0000ff00) >> 8,
				(this_iphdr->ip_dst.s_addr & 0x00ff0000) >> 16,
				(this_iphdr->ip_dst.s_addr & 0xff000000) >> 24
		      );
		printf("sport = %d, dport = %d\n", this_tcphdr->th_sport, this_tcphdr->th_dport);
	}
#endif

#if 0
	if (my_tcp_check(this_tcphdr, iplen - 4 * this_iphdr->ip_hl,
				this_iphdr->ip_src.s_addr, this_iphdr->ip_dst.s_addr)) {
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
				this_tcphdr);
		return;
	}
	check_flags(this_iphdr, this_tcphdr);
	//ECN
#endif
	if (!(a_tcp = find_stream(this_tcphdr, this_iphdr, &from_client, tcp_thread_local_p))) {
		if ((this_tcphdr->th_flags & TH_SYN) &&
				!(this_tcphdr->th_flags & TH_ACK) &&
				!(this_tcphdr->th_flags & TH_RST))
			add_new_tcp(this_tcphdr, this_iphdr, tcp_thread_local_p);
		return;
	}

#if 0
	if (!((a_tcp->addr.source == this_tcphdr->th_sport &&
		a_tcp->addr.dest == this_tcphdr->th_dport &&
		a_tcp->addr.saddr == this_iphdr->ip_src.s_addr &&
		a_tcp->addr.daddr == this_iphdr->ip_dst.s_addr) ||
		(a_tcp->addr.dest == this_tcphdr->th_sport &&
		a_tcp->addr.source == this_tcphdr->th_dport &&
		a_tcp->addr.daddr == this_iphdr->ip_src.s_addr &&
		a_tcp->addr.saddr == this_iphdr->ip_dst.s_addr))) {
		false_positive ++;
	}
#endif

	if (from_client) {
		snd = &a_tcp->client;
		rcv = &a_tcp->server;
	}
	else {
		rcv = &a_tcp->client;
		snd = &a_tcp->server;
	}
	if ((this_tcphdr->th_flags & TH_SYN)) {
		if (from_client || a_tcp->client.state != TCP_SYN_SENT ||
				a_tcp->server.state != TCP_CLOSE || !(this_tcphdr->th_flags & TH_ACK))
			return;
		if (a_tcp->client.seq != ntohl(this_tcphdr->th_ack))
			return;
		a_tcp->server.state = TCP_SYN_RECV;
		a_tcp->server.seq = ntohl(this_tcphdr->th_seq) + 1;
		a_tcp->server.first_data_seq = a_tcp->server.seq;
		a_tcp->server.ack_seq = ntohl(this_tcphdr->th_ack);
		a_tcp->server.window = ntohs(this_tcphdr->th_win);
		if (a_tcp->client.ts_on) {
			a_tcp->server.ts_on = get_ts(this_tcphdr, &a_tcp->server.curr_ts);
			if (!a_tcp->server.ts_on)
				a_tcp->client.ts_on = 0;
		} else a_tcp->server.ts_on = 0;	
		if (a_tcp->client.wscale_on) {
			a_tcp->server.wscale_on = get_wscale(this_tcphdr, &a_tcp->server.wscale);
			if (!a_tcp->server.wscale_on) {
				a_tcp->client.wscale_on = 0;
				a_tcp->client.wscale  = 1;
				a_tcp->server.wscale = 1;
			}	
		} else {
			a_tcp->server.wscale_on = 0;	
			a_tcp->server.wscale = 1;
		}	
		return;
	}
	//  printf("datalen = %d, th_seq = %d, ack_seq = %d, window = %d, wscale = %d\n",
	//	  	datalen, this_tcphdr->th_seq, rcv->ack_seq, rcv->window, rcv->wscale);
	if (
			! (  !datalen && ntohl(this_tcphdr->th_seq) == rcv->ack_seq  )
			&&
			( !before(ntohl(this_tcphdr->th_seq), rcv->ack_seq + rcv->window*rcv->wscale) ||
			  before(ntohl(this_tcphdr->th_seq) + datalen, rcv->ack_seq)  
			)
	   )    { 
		return;
	}

	if ((this_tcphdr->th_flags & TH_RST)) {
		if (a_tcp->nids_state == NIDS_DATA) {
			struct lurker_node *i;

			a_tcp->nids_state = NIDS_RESET;
			for (i = a_tcp->listeners; i; i = i->next)
				(i->item) (a_tcp, &i->data);
		}
		nids_free_tcp_stream(a_tcp, tcp_thread_local_p);
		return;
	}

	/* PAWS check */
	if (rcv->ts_on && get_ts(this_tcphdr, &tmp_ts) && 
			before(tmp_ts, snd->curr_ts))
		return; 	

	if ((this_tcphdr->th_flags & TH_ACK)) {
		if (from_client && a_tcp->client.state == TCP_SYN_SENT &&
				a_tcp->server.state == TCP_SYN_RECV) {
			if (ntohl(this_tcphdr->th_ack) == a_tcp->server.seq) {
				a_tcp->client.state = TCP_ESTABLISHED;
				a_tcp->client.ack_seq = ntohl(this_tcphdr->th_ack);
				{
					struct proc_node *i;
					struct lurker_node *j;
					void *data;

					a_tcp->server.state = TCP_ESTABLISHED;
					a_tcp->nids_state = NIDS_JUST_EST;

#if !defined(DISABLE_UPPER_LAYER)
					for (i = tcp_procs; i; i = i->next) {
						char whatto = 0;
						char cc = a_tcp->client.collect;
						char sc = a_tcp->server.collect;
						char ccu = a_tcp->client.collect_urg;
						char scu = a_tcp->server.collect_urg;

						(i->item) (a_tcp, &data);
						if (cc < a_tcp->client.collect)
							whatto |= COLLECT_cc;
						if (ccu < a_tcp->client.collect_urg)
							whatto |= COLLECT_ccu;
						if (sc < a_tcp->server.collect)
							whatto |= COLLECT_sc;
						if (scu < a_tcp->server.collect_urg)
							whatto |= COLLECT_scu;
						if (nids_params.one_loop_less) {
							if (a_tcp->client.collect >=2) {
								a_tcp->client.collect=cc;
								whatto&=~COLLECT_cc;
							}
							if (a_tcp->server.collect >=2 ) {
								a_tcp->server.collect=sc;
								whatto&=~COLLECT_sc;
							}
						}  
						if (whatto) {
							j = mknew(struct lurker_node);
							j->item = i->item;
							j->data = data;
							j->whatto = whatto;
							j->next = a_tcp->listeners;
							a_tcp->listeners = j;
						}
					}

					if (!a_tcp->listeners) {
						nids_free_tcp_stream(a_tcp, tcp_thread_local_p);
						return;
					}
#endif
					a_tcp->nids_state = NIDS_DATA;
				}
			}
			// return;
		}
	}
	if ((this_tcphdr->th_flags & TH_ACK)) {
		handle_ack(snd, ntohl(this_tcphdr->th_ack));
		if (rcv->state == FIN_SENT)
			rcv->state = FIN_CONFIRMED;
		if (rcv->state == FIN_CONFIRMED && snd->state == FIN_CONFIRMED) {
			struct lurker_node *i;

			a_tcp->nids_state = NIDS_CLOSE;
			for (i = a_tcp->listeners; i; i = i->next)
				(i->item) (a_tcp, &i->data);
			nids_free_tcp_stream(a_tcp, tcp_thread_local_p);
			return;
		}
	}
	if (datalen + (this_tcphdr->th_flags & TH_FIN) > 0)
		tcp_queue(a_tcp, this_tcphdr, snd, rcv,
				(char *) (this_tcphdr) + 4 * this_tcphdr->th_off,
				datalen, skblen, tcp_thread_local_p);
	snd->window = ntohs(this_tcphdr->th_win);
	if (rcv->rmem_alloc > 65535)
		prune_queue(rcv, this_tcphdr);
#if !defined(DISABLE_UPPER_LAYER)
	if (!a_tcp->listeners)
		nids_free_tcp_stream(a_tcp, tcp_thread_local_p);
#endif
}
#endif
