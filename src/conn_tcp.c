#include "bitmap.h"
#include <string.h>

#define CACHE_LINE_SIZE 64
#define PTR_SIZE 8
#define ELEM_SIZE 8
#define SET_ASSOCIATIVE ((CACHE_LINE_SIZE-PTR_SIZE)/ELEM_SIZE)
#define SET_SIZE CACHE_LINE_SIZE
#define SET_NUMBER 200000 //0.2 Million buckets = 1.4 Million Elem

//typedef elem_type uint32_t;
typedef uint32_t sig_type;
typedef struct {
	sig_type signature;
	idx_type index;
} elem_type;

typedef struct ll_type {
	elem_type elem;
	struct ll_type *next;
} elem_list_type;

int conflict_into_list = 0;

static void *tcp_stream_table;
static struct tcp_stream *tcb_array;
extern int tcp_num;
extern int tcp_stream_table_size;
extern int get_ts(struct tcphdr *, unsigned int *);
extern int get_wscale(struct tcphdr *, unsigned int *);
extern int mk_hash_index(struct tuple4);
extern void del_tcp_closing_timeout(struct tcp_stream *);
extern void purge_queue(struct half_stream *);

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

inline sig_type calc_signature(const uint32_t sip, const uint32_t dip, const uint16_t sport, const uint16_t dport)
{
	uint32_t port = sport ^ dport;
	return sip ^ dip ^ port;
}

inline int sig_match_e(const sig_type sign, const elem_type *ptr)
{
	return (sign == ptr->signature)? 1 : 0;
}

inline int sig_match_l(const sig_type sign, const elem_list_type *ptr)
{
	return (sign == ptr->elem.signature)? 1 : 0;
}

inline idx_type index_e(const elem_type *ptr)
{
	return ptr->index;
}

inline idx_type index_l(const elem_list_type *ptr)
{
	return ptr->elem.index;
}

struct tcp_stream *
find_stream(struct tcphdr *this_tcphdr, struct ip *this_iphdr, int *from_client)
{
	int hash_index, i;
	elem_type *ptr;
	elem_list_type *ptr_l;
	sig_type sign;
	struct tuple4 addr;
	
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
	for (ptr = (elem_type *)&(((char *)tcp_stream_table)[hash_index * SET_SIZE]), i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(sign, ptr)) {
			if (addr.source == tcb_array[index_e(ptr)].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			return &tcb_array[index_e(ptr)];
		}
	}

	// Not in cache, search collision linked list
	for (ptr_l = *(elem_list_type **)(&(((char *)tcp_stream_table)[hash_index * SET_SIZE]) + SET_ASSOCIATIVE * sizeof(elem_type));
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
	return NULL;
}

static void add_into_cache(struct tuple4 addr, idx_type index, struct tcp_stream *a_tcp)
{
	sig_type sign;
	int hash_index, i;
	elem_type *ptr;
	elem_list_type *ptr_l, **head_l;

	sign = calc_signature(addr.saddr, addr.daddr, addr.source, addr.dest);

	hash_index = mk_hash_index(addr);
	a_tcp->hash_index = hash_index;

	// Search the cache
	for (ptr = (elem_type *)&(((char *)tcp_stream_table)[hash_index * SET_SIZE]), i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(0, ptr)) {
			ptr->signature = sign;
			ptr->index = index;
			return;
		}
	}

	conflict_into_list ++;
	// Insert into the collision list
	// FIXME : Optimize the malloc with lock-free library
	ptr_l = (elem_list_type *)malloc(sizeof(elem_list_type));
	head_l = (elem_list_type **)(&(((char *)tcp_stream_table)[hash_index * SET_SIZE]) + SET_ASSOCIATIVE * sizeof(elem_type));

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
	add_into_cache(addr, index, a_tcp);

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
delete_from_cache(struct tcp_stream *a_tcp)
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
	for (ptr = (elem_type *)&(((char *)tcp_stream_table)[hash_index * SET_SIZE]), i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(sign, ptr)) {
			ptr->signature = 0;
			return index_e(ptr);
		}
	}

	// Search the collision list
	for (ptr_l = *(elem_list_type **)(&(((char *)tcp_stream_table)[hash_index * SET_SIZE]) + SET_ASSOCIATIVE * sizeof(elem_type)), pre_l = NULL;
		ptr_l != NULL;
		pre_l = ptr_l, ptr_l = ptr_l->next) {
		
		if (sig_match_l(sign, ptr_l)) {
			tcb_index = index_l(ptr_l);

			if (pre_l == NULL) {
				// The first match, update head
				*(elem_list_type **)(&(((char *)tcp_stream_table)[hash_index * SET_SIZE]) + SET_ASSOCIATIVE * sizeof(elem_type)) = ptr_l->next;
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

	tcb_index = delete_from_cache(a_tcp);
	ret_free_index(tcb_index);
	return;
}

int
tcp_init(int size)
{
	int i;
	struct tcp_timeout *tmp;

	// The hash table
	tcp_stream_table_size = SET_NUMBER;
	tcp_stream_table = calloc(SET_NUMBER, SET_SIZE);
	if (!tcp_stream_table) {
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

	if (!tcp_stream_table || !tcb_array)
		return;
	free(tcb_array);
	free(tcp_stream_table);
	tcp_stream_table = NULL;
	tcp_num = 0;
	return;
}
