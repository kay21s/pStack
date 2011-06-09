#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "nids.h"
#include "util.h"
#include "bitmap.h"
#include "conn_split.h"

#if defined(SPLIT_TCP)

#define SET_NUMBER_TH 100000 //0.1 Million buckets = 0.7 Million Elem
#define SET_NUMBER_BH 100000 //0.1 Million buckets = 0.7 Million Elem

int conflict_into_list = 0;
int false_positive = 0;
int processed_num = 0;

int search_num = 0, search_hit_num = 0;
int add_num = 0, add_hit_num = 0;
int delete_num = 0, delete_hit_num = 0;
int not_found = 0;

extern struct proc_node *tcp_procs;

static void *tcp_stream_table_th;
static void *tcp_stream_table_bh;
static struct tcp_stream *tcb_array;
extern int tcp_num;
extern int tcp_stream_table_size;
extern int get_ts(struct tcphdr *, unsigned int *);
extern int get_wscale(struct tcphdr *, unsigned int *);
extern int mk_hash_index(struct tuple4);
extern void del_tcp_closing_timeout(struct tcp_stream *);
extern void purge_queue(struct half_stream *);
extern void handle_ack(struct half_stream *, u_int);
extern void tcp_queue(struct tcp_stream *, struct tcphdr *,
	struct half_stream *, struct half_stream *,
	char *, int, int);
extern void prune_queue(struct half_stream *, struct tcphdr *);

#if 0
elem_type F(elem_type tag, idx_type idx)
{
	return tag^((~idx^0xaaaa)<<16|(idx^0x8a28));
}

index_type F_reverse(elem_type tag, idx_type etag)
{
	return ((~idx^0xaaaa)<<16|(idx^0x8a28))
}
#endif

static struct tcp_stream *
find_stream_th(struct tcphdr *this_tcphdr, struct ip *this_iphdr, int *from_client)
{
	int hash_index, i;
	elem_type *ptr;
	elem_list_type *ptr_l;
	sig_type sign;
	struct tuple4 addr;
	idx_type tcb_index;
	
	addr.source = this_tcphdr->th_sport;
	addr.dest = this_tcphdr->th_dport;
	addr.saddr = this_iphdr->ip_src.s_addr;
	addr.daddr = this_iphdr->ip_dst.s_addr;

	hash_index = mk_hash_index(addr);

	sign = calc_signature(this_iphdr->ip_src.s_addr,
			this_iphdr->ip_dst.s_addr,
			this_tcphdr->th_sport,
			this_tcphdr->th_dport);

	// Search the cache
	elem_type *set_header = (elem_type *)&(((char *)tcp_stream_table_th)[hash_index * SET_SIZE]);

#if defined(MAJOR_LOCATION)
	uint8_t loc = get_major_location(sign);
	search_num ++;
	if (sig_match_e(sign, set_header + loc)) {
		tcb_index = get_cached_index(set_header, loc);
		if (addr.source == tcb_array[tcb_index].addr.source)
			*from_client = 1;
		else
			*from_client = 0;

		search_hit_num ++;
		return &tcb_array[tcb_index];
	}
#endif

	for (ptr = set_header, i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(sign, ptr)) {
			tcb_index = get_cached_index(set_header, i);
			if (addr.source == tcb_array[tcb_index].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			return &tcb_array[tcb_index];
		}
	}

	// Not in cache, search collision linked list
	for (ptr_l = *(elem_list_type **)(&(((char *)tcp_stream_table_th)[hash_index * SET_SIZE]) + SET_SIZE - PTR_SIZE);
		ptr_l != NULL;
		ptr_l = ptr_l->next) {
		
		if (sig_match_l(sign, ptr_l)) {
			if (addr.source == tcb_array[index_l(ptr_l)].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			return &tcb_array[index_l(ptr_l)];
		}
	}

	// Not found
	not_found ++;
	return NULL;
}

static struct tcp_stream *
find_stream_bh(struct tcphdr *this_tcphdr, struct ip *this_iphdr, int *from_client)
{
	int hash_index, i;
	elem_type *ptr;
	elem_list_type *ptr_l;
	sig_type sign;
	struct tuple4 addr;
	idx_type tcb_index;
	
	addr.source = this_tcphdr->th_sport;
	addr.dest = this_tcphdr->th_dport;
	addr.saddr = this_iphdr->ip_src.s_addr;
	addr.daddr = this_iphdr->ip_dst.s_addr;

	hash_index = mk_hash_index(addr);

	sign = calc_signature(this_iphdr->ip_src.s_addr,
			this_iphdr->ip_dst.s_addr,
			this_tcphdr->th_sport,
			this_tcphdr->th_dport);

	// Search the cache
	elem_type *set_header = (elem_type *)&(((char *)tcp_stream_table_bh)[hash_index * SET_SIZE]);

#if defined(MAJOR_LOCATION)
	uint8_t loc = get_major_location(sign);
	search_num ++;
	if (sig_match_e(sign, set_header + loc)) {
		tcb_index = get_cached_index(set_header, loc);
		if (addr.source == tcb_array[tcb_index].addr.source)
			*from_client = 1;
		else
			*from_client = 0;

		search_hit_num ++;
		return &tcb_array[tcb_index];
	}
#endif

	for (ptr = set_header, i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(sign, ptr)) {
			tcb_index = get_cached_index(set_header, i);
			if (addr.source == tcb_array[tcb_index].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			return &tcb_array[tcb_index];
		}
	}

	// Not in cache, search collision linked list
	for (ptr_l = *(elem_list_type **)(&(((char *)tcp_stream_table_bh)[hash_index * SET_SIZE]) + SET_SIZE - PTR_SIZE);
		ptr_l != NULL;
		ptr_l = ptr_l->next) {
		
		if (sig_match_l(sign, ptr_l)) {
			if (addr.source == tcb_array[index_l(ptr_l)].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			return &tcb_array[index_l(ptr_l)];
		}
	}

	// Not found
	not_found ++;
	return NULL;
}

// A function to make it compatible to origin tcp.c
struct tcp_stream *
find_stream(struct tcphdr *this_tcphdr, struct ip *this_iphdr, int *from_client)
{
	struct tcp_stream *a_tcp;
	if (!(a_tcp = find_stream_bh(this_tcphdr, this_iphdr, from_client))) {
		// Cannot find in Established Connections, Find in the unestablished ones
		if (!(a_tcp = find_stream_th(this_tcphdr, this_iphdr, from_client))) {
			return NULL;
		}
	}

	return a_tcp;
}

static void
add_into_cache_th(struct tuple4 addr, idx_type index, struct tcp_stream *a_tcp)
{
	sig_type sign;
	int hash_index, i;
	elem_type *ptr;
	elem_list_type *ptr_l, **head_l;

	sign = calc_signature(addr.saddr, addr.daddr, addr.source, addr.dest);

	hash_index = mk_hash_index(addr);
	a_tcp->hash_index = hash_index;

	// Search the cache
	elem_type *set_header = (elem_type *)&(((char *)tcp_stream_table_th)[hash_index * SET_SIZE]);

#if defined(MAJOR_LOCATION)
	uint8_t loc = get_major_location(sign);
	add_num ++;
	if (sig_match_e(0, set_header + loc)) {
		ptr = set_header + loc;
		ptr->signature = sign;
		store_cached_index(set_header, loc, index);
		add_hit_num ++;
		return;
	}
#endif
	for (ptr = set_header, i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(0, ptr)) {
			ptr->signature = sign;
			store_cached_index(set_header, i, index);
			return;
		}
	}

	conflict_into_list ++;
	// Insert into the collision list
	// FIXME : Optimize the malloc with lock-free library
	ptr_l = (elem_list_type *)malloc(sizeof(elem_list_type));
	store_index_l(ptr_l, index);
	store_sig_l(ptr_l, sign);
	head_l = (elem_list_type **)(&(((char *)tcp_stream_table_th)[hash_index * SET_SIZE]) + SET_SIZE - PTR_SIZE);

	ptr_l->next = *head_l;
	*head_l = ptr_l;
}

static void 
add_into_cache_bh(struct tuple4 addr, idx_type index, struct tcp_stream *a_tcp)
{
	sig_type sign;
	int hash_index, i;
	elem_type *ptr;
	elem_list_type *ptr_l, **head_l;

	sign = calc_signature(addr.saddr, addr.daddr, addr.source, addr.dest);

	hash_index = mk_hash_index(addr);
	a_tcp->hash_index = hash_index;

	// Search the cache
	elem_type *set_header = (elem_type *)&(((char *)tcp_stream_table_bh)[hash_index * SET_SIZE]);

#if defined(MAJOR_LOCATION)
	uint8_t loc = get_major_location(sign);
	add_num ++;
	if (sig_match_e(0, set_header + loc)) {
		ptr = set_header + loc;
		ptr->signature = sign;
		store_cached_index(set_header, loc, index);
		add_hit_num ++;
		return;
	}
#endif
	for (ptr = set_header, i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(0, ptr)) {
			ptr->signature = sign;
			store_cached_index(set_header, i, index);
			return;
		}
	}

	conflict_into_list ++;
	// Insert into the collision list
	// FIXME : Optimize the malloc with lock-free library
	ptr_l = (elem_list_type *)malloc(sizeof(elem_list_type));
	store_index_l(ptr_l, index);
	store_sig_l(ptr_l, sign);
	head_l = (elem_list_type **)(&(((char *)tcp_stream_table_bh)[hash_index * SET_SIZE]) + SET_SIZE - PTR_SIZE);

	ptr_l->next = *head_l;
	*head_l = ptr_l;
}

void
add_new_tcp(struct tcphdr *this_tcphdr, struct ip *this_iphdr)
{
	struct tcp_stream *tolink;
	struct tcp_stream *a_tcp;
	struct tuple4 addr;
	idx_type index;

	addr.source = this_tcphdr->th_sport;
	addr.dest = this_tcphdr->th_dport;
	addr.saddr = this_iphdr->ip_src.s_addr;
	addr.daddr = this_iphdr->ip_dst.s_addr;

	tcp_num++;

	// get free index from bitmap
	index = get_free_index();

	// let's have the block
	a_tcp = &(tcb_array[index]);

	// add the index into hash cache
	add_into_cache_th(addr, index, a_tcp);

	// fill the tcp block
	memset(a_tcp, 0, sizeof(struct tcp_stream));
	a_tcp->addr = addr;
	a_tcp->client.state = TCP_SYN_SENT;
	a_tcp->client.seq = ntohl(this_tcphdr->th_seq) + 1;
	a_tcp->client.first_data_seq = a_tcp->client.seq;
	a_tcp->client.window = ntohs(this_tcphdr->th_win);
	a_tcp->client.ts_on = get_ts(this_tcphdr, &a_tcp->client.curr_ts);
	a_tcp->client.wscale_on = get_wscale(this_tcphdr, &a_tcp->client.wscale);
	a_tcp->server.state = TCP_CLOSE;

	return;
}

static idx_type 
delete_from_cache_th(struct tcp_stream *a_tcp)
{
	sig_type sign;
	idx_type tcb_index; 
	int hash_index, i;
	elem_type *ptr;
	elem_list_type *ptr_l, *pre_l;
	struct tuple4 addr;

	addr = a_tcp->addr;
	sign = calc_signature(addr.saddr, addr.daddr, addr.source, addr.dest);

	hash_index = mk_hash_index(addr);

	// Search the cache
	elem_type *set_header = (elem_type *)&(((char *)tcp_stream_table_th)[hash_index * SET_SIZE]);

#if defined(MAJOR_LOCATION)
	uint8_t loc = get_major_location(sign);
	delete_num ++;
	if (sig_match_e(sign, set_header + loc)) {
		ptr = set_header + loc;
		ptr->signature = 0;
		tcb_index = get_cached_index(set_header, loc);
		delete_hit_num ++;
		return tcb_index;
	}
#endif
	for (ptr = set_header, i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(sign, ptr)) {
			ptr->signature = 0;
			tcb_index = get_cached_index(set_header, i);
			return tcb_index;
		}
	}

	// Search the collision list
	for (ptr_l = *(elem_list_type **)(&(((char *)tcp_stream_table_th)[hash_index * SET_SIZE]) + SET_SIZE - PTR_SIZE), pre_l = NULL;
		ptr_l != NULL;
		pre_l = ptr_l, ptr_l = ptr_l->next) {
		
		if (sig_match_l(sign, ptr_l)) {
			tcb_index = index_l(ptr_l);

			if (pre_l == NULL) {
				// The first match, update head
				*(elem_list_type **)(&(((char *)tcp_stream_table_th)[hash_index * SET_SIZE]) + SET_SIZE - PTR_SIZE) = ptr_l->next;
			} else {
				// Link to next
				pre_l->next = ptr_l->next;
			}

			free(ptr_l);

			return tcb_index;
		}
	}
	
	printf("Not found??? What's the matter?????\n");
	exit(0);
	return -1;
}
static idx_type 
delete_from_cache_bh(struct tcp_stream *a_tcp)
{
	sig_type sign;
	idx_type tcb_index; 
	int hash_index, i;
	elem_type *ptr;
	elem_list_type *ptr_l, *pre_l;
	struct tuple4 addr;

	addr = a_tcp->addr;
	sign = calc_signature(addr.saddr, addr.daddr, addr.source, addr.dest);

	hash_index = mk_hash_index(addr);

	// Search the cache
	elem_type *set_header = (elem_type *)&(((char *)tcp_stream_table_bh)[hash_index * SET_SIZE]);

#if defined(MAJOR_LOCATION)
	uint8_t loc = get_major_location(sign);
	delete_num ++;
	if (sig_match_e(sign, set_header + loc)) {
		ptr = set_header + loc;
		ptr->signature = 0;
		tcb_index = get_cached_index(set_header, loc);
		delete_hit_num ++;
		return tcb_index;
	}
#endif
	for (ptr = set_header, i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(sign, ptr)) {
			ptr->signature = 0;
			tcb_index = get_cached_index(set_header, i);
			return tcb_index;
		}
	}

	// Search the collision list
	for (ptr_l = *(elem_list_type **)(&(((char *)tcp_stream_table_bh)[hash_index * SET_SIZE]) + SET_SIZE - PTR_SIZE), pre_l = NULL;
		ptr_l != NULL;
		pre_l = ptr_l, ptr_l = ptr_l->next) {
		
		if (sig_match_l(sign, ptr_l)) {
			tcb_index = index_l(ptr_l);

			if (pre_l == NULL) {
				// The first match, update head
				*(elem_list_type **)(&(((char *)tcp_stream_table_bh)[hash_index * SET_SIZE]) + SET_SIZE - PTR_SIZE) = ptr_l->next;
			} else {
				// Link to next
				pre_l->next = ptr_l->next;
			}

			free(ptr_l);

			return tcb_index;
		}
	}
	
	printf("Not found??? What's the matter?????\n");
	exit(0);
	return -1;
}

void
nids_free_tcp_stream(struct tcp_stream *a_tcp)
{
	struct lurker_node *i, *j;
	idx_type tcb_index;

	del_tcp_closing_timeout(a_tcp);
	purge_queue(&a_tcp->server);
	purge_queue(&a_tcp->client);

	if (a_tcp->client.data)
		free(a_tcp->client.data);
	if (a_tcp->server.data)
		free(a_tcp->server.data);

	i = a_tcp->listeners;
	while (i) {
		j = i->next;
		free(i);
		i = j;
	}
	tcp_num --;

	if (a_tcp->client.state == TCP_SYN_SENT ||
		a_tcp->server.state == TCP_SYN_RECV) {
		// Not reach TCP_ESTABLISHED yet, find in the top half
		tcb_index = delete_from_cache_th(a_tcp);
	} else {
		tcb_index = delete_from_cache_bh(a_tcp);
	}
	ret_free_index(tcb_index);
	return;
}

int
tcp_init(int size)
{
	int i;
	struct tcp_timeout *tmp;

	// The hash table
	tcp_stream_table_size = SET_NUMBER_BH;
	tcp_stream_table_th = calloc(SET_NUMBER_TH, SET_SIZE);
	if (!tcp_stream_table_th) {
		printf("tcp_stream_table in tcp_init");
		exit(0);
		return -1;
	}
	tcp_stream_table_bh = calloc(SET_NUMBER_BH, SET_SIZE);
	if (!tcp_stream_table_bh) {
		printf("tcp_stream_table in tcp_init");
		exit(0);
		return -1;
	}

	// The TCB array
	tcb_array = calloc(MAX_STREAM, sizeof(struct tcp_stream));
	if (!tcb_array) {
		printf("tcp_array in tcp_init");
		exit(0);
		return -1;
	}

	// Following can be optimized
	init_hash();
	while (nids_tcp_timeouts) {
		tmp = nids_tcp_timeouts->next;
		free(nids_tcp_timeouts);
		nids_tcp_timeouts = tmp;
	}
	return 0;
}

// FIXME: Need search the cache table, call corresponding callback function,
// and release resource in this function
void
tcp_exit(void)
{
	int i;
	struct lurker_node *j;
	struct tcp_stream *a_tcp, *t_tcp;

	if (!tcp_stream_table_th || !tcp_stream_table_bh || !tcb_array)
		return;
	free(tcb_array);
	free(tcp_stream_table_th);
	free(tcp_stream_table_bh);
	tcp_stream_table_th = NULL;
	tcp_stream_table_bh = NULL;
	tcp_num = 0;
	return;
}

void
process_tcp(u_char *data, int skblen)
{
	struct ip *this_iphdr = (struct ip *)data;
	struct tcphdr *this_tcphdr = (struct tcphdr *)(data + 4 * this_iphdr->ip_hl);
	int datalen, iplen;
	int from_client = 1, from_bh = 1;
	unsigned int tmp_ts;
	struct tcp_stream *a_tcp;
	struct half_stream *snd, *rcv;
	idx_type index;

//	ugly_iphdr = this_iphdr;
	iplen = ntohs(this_iphdr->ip_len);
	if ((unsigned)iplen < 4 * this_iphdr->ip_hl + sizeof(struct tcphdr)) {
		return;
	} // ktos sie bawi
  
	datalen = iplen - 4 * this_iphdr->ip_hl - 4 * this_tcphdr->th_off;
  
	if (datalen < 0 || ((this_iphdr->ip_src.s_addr | this_iphdr->ip_dst.s_addr) == 0)) {
		return;
	}

#if 0
	{
	processed_num ++;
	printf("| %d |IN PROCESS_TCP A tcp!, saddr = %d.%d.%d.%d,", 
		processed_num,
		this_iphdr->ip_src.s_addr & 0x000000ff,
		(this_iphdr->ip_src.s_addr & 0x0000ff00) >> 8,
		(this_iphdr->ip_src.s_addr & 0x00ff0000) >> 16,
		(this_iphdr->ip_src.s_addr & 0xff000000) >> 24);
	printf("daddr = %d.%d.%d.%d,", 
		this_iphdr->ip_dst.s_addr & 0x000000ff,
		(this_iphdr->ip_dst.s_addr & 0x0000ff00) >> 8,
		(this_iphdr->ip_dst.s_addr & 0x00ff0000) >> 16,
		(this_iphdr->ip_dst.s_addr & 0xff000000) >> 24);
	printf("sport = %d, dport = %d\n", this_tcphdr->th_sport, this_tcphdr->th_dport);
	}
#endif

	// FIXME: In libnids, connection is find first to avoid the single SYN-Attack
	// This is designed for normal TCP which can accerlerate TCP processing
	// Check can be made when adding connections into Top Half cache
	if ((this_tcphdr->th_flags & TH_SYN) &&
		!(this_tcphdr->th_flags & TH_ACK) &&
		!(this_tcphdr->th_flags & TH_RST)) {
		// SYN Packet, Add the tcp connection block
		add_new_tcp(this_tcphdr, this_iphdr);
		return;
	}
	
	// Second packet of Three-way hand-shaking, ACK+SYN
	if ((this_tcphdr->th_flags & TH_SYN) &&
		(this_tcphdr->th_flags & TH_ACK)) {

		// Find stream in the top half of connection table (Connections not established)
		a_tcp = find_stream_th(this_tcphdr, this_iphdr, &from_client);
		if (from_client || a_tcp->client.state != TCP_SYN_SENT ||
			a_tcp->server.state != TCP_CLOSE || !(this_tcphdr->th_flags & TH_ACK) ||
			a_tcp->client.seq != ntohl(this_tcphdr->th_ack))
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


	// Find TCB in the bottom half first(Established connections), 
	// then find in the top half if not found.
	if (!(a_tcp = find_stream_bh(this_tcphdr, this_iphdr, &from_client))) {
		// Cannot find in Established Connections, Find in the unestablished ones
		from_bh = 0;
		if (!(a_tcp = find_stream_th(this_tcphdr, this_iphdr, &from_client))) {
			return;
		}
	}

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


	if (from_client) {
		snd = &a_tcp->client;
		rcv = &a_tcp->server;
	} else {
		rcv = &a_tcp->client;
		snd = &a_tcp->server;
	}

	//printf("datalen = %d, th_seq = %d, ack_seq = %d, window = %d, wscale = %d\n",
	//	datalen, this_tcphdr->th_seq, rcv->ack_seq, rcv->window, rcv->wscale);
	// Some error detection, uses window, wscale
	if ( !(!datalen && ntohl(this_tcphdr->th_seq) == rcv->ack_seq) &&
		(!before(ntohl(this_tcphdr->th_seq), rcv->ack_seq + rcv->window*rcv->wscale) ||
		before(ntohl(this_tcphdr->th_seq) + datalen, rcv->ack_seq))) { 
		return;
	}

	// Connection is reset
	if ((this_tcphdr->th_flags & TH_RST)) {
		if (a_tcp->nids_state == NIDS_DATA) {
			struct lurker_node *i;

			a_tcp->nids_state = NIDS_RESET;
			for (i = a_tcp->listeners; i; i = i->next)
				(i->item) (a_tcp, &i->data);
		}
		nids_free_tcp_stream(a_tcp);
		return;
	}

	/* PAWS check */
	if (rcv->ts_on && get_ts(this_tcphdr, &tmp_ts) && before(tmp_ts, snd->curr_ts))
		return; 	
  
	if ((this_tcphdr->th_flags & TH_ACK)) {

		// The third ACK of Three-way hand-shaking
		// TCP connection turns into Established
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
						nids_free_tcp_stream(a_tcp);
						return;
					}
					a_tcp->nids_state = NIDS_DATA;
				}
			}

			// Move the connection from top half to bottom half
			index = delete_from_cache_th(a_tcp);
			add_into_cache_bh(a_tcp->addr, index, a_tcp);
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
			nids_free_tcp_stream(a_tcp);
			return;
		}
	}

	if (datalen + (this_tcphdr->th_flags & TH_FIN) > 0)
		tcp_queue(a_tcp, this_tcphdr, snd, rcv,
			(char *) (this_tcphdr) + 4 * this_tcphdr->th_off,
			datalen, skblen);
		
	snd->window = ntohs(this_tcphdr->th_win);
	if (rcv->rmem_alloc > 65535)
		prune_queue(rcv, this_tcphdr);
	if (!a_tcp->listeners)
		nids_free_tcp_stream(a_tcp);
}
#endif
