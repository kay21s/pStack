#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "nids.h"
#include "util.h"
#include "bitmap.threaded.h"
#include "conn_major_indexfree.threaded.h"
#include "tcp.threaded.h"
#include "parallel.h"
#include  <nmmintrin.h>

#if defined(MAJOR_INDEXFREE_TCP)

#define SET_NUMBER 80000 //0.1 Million buckets = 1.6 Million Elem
#define CACHE_ELEM_NUM 1280000 // element number stored in cache, 100000 * 16

int conflict_into_list = 0;
int false_positive = 0;

int search_num = 0, search_hit_num = 0, search_set_hit_num = 0;
int add_num = 0, add_hit_num = 0, add_set_hit_num = 0;
int delete_num = 0, delete_hit_num = 0, delete_set_hit_num = 0;
int not_found = 0;

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

int is_false_positive(struct tuple4 addr, idx_type tcb_index, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	struct tcp_stream *tcb_p = &(tcp_thread_local_p->tcb_array[tcb_index]);
	if (!((addr.source == tcb_p->addr.source &&
		addr.dest == tcb_p->addr.dest &&
		addr.saddr == tcb_p->addr.saddr &&
		addr.daddr == tcb_p->addr.daddr ) ||
		(addr.dest == tcb_p->addr.source &&
		addr.source == tcb_p->addr.dest &&
		addr.daddr == tcb_p->addr.saddr &&
		addr.saddr == tcb_p->addr.daddr ))) {

		// Yes, it is false positive
		false_positive ++;

#if 1		
		int sign2 = calc_signature(
				tcb_p->addr.saddr,
				tcb_p->addr.daddr,
				tcb_p->addr.source,
				tcb_p->addr.dest);
		printf("||the Founded one in the table: Sip: %d.%d.%d.%d, Sport:%d, Dip : %d.%d.%d.%d, Dport:%d , sign = %x\n", 
				tcb_p->addr.saddr & 0x000000FF,
				(tcb_p->addr.saddr & 0x0000FF00)>>8,
				(tcb_p->addr.saddr & 0x00FF0000)>>16,
				(tcb_p->addr.saddr & 0xFF000000)>>24,
				tcb_p->addr.source,
				tcb_p->addr.daddr & 0x000000FF,
				(tcb_p->addr.daddr & 0x0000FF00)>>8,
				(tcb_p->addr.daddr & 0x00FF0000)>>16,
				(tcb_p->addr.daddr & 0xFF000000)>>24,
				tcb_p->addr.dest,
				sign2
		      );
		int crc1 = 0;
		crc1 = _mm_crc32_u32(crc1, tcb_p->addr.saddr);
		crc1 = _mm_crc32_u32(crc1, tcb_p->addr.daddr);
		crc1 = _mm_crc32_u32(crc1, tcb_p->addr.source ^ tcb_p->addr.dest);
		printf("(%x", crc1);
		crc1 = 0;
		crc1 = _mm_crc32_u32(crc1, tcb_p->addr.daddr);
		crc1 = _mm_crc32_u32(crc1, tcb_p->addr.saddr);
		crc1 = _mm_crc32_u32(crc1, tcb_p->addr.source ^ tcb_p->addr.dest);
		printf("--  %x)\n", crc1);
		sign2 = calc_signature(
				addr.saddr,
				addr.daddr,
				addr.source,
				addr.dest);
		printf("Current one: Sip: %d.%d.%d.%d, Sport:%d, Dip : %d.%d.%d.%d, Dport:%d , sign = %x||\n", 
				addr.saddr & 0x000000FF,
				(addr.saddr & 0x0000FF00)>>8,
				(addr.saddr & 0x00FF0000)>>16,
				(addr.saddr & 0xFF000000)>>24,
				addr.source,
				addr.daddr & 0x000000FF,
				(addr.daddr & 0x0000FF00)>>8,
				(addr.daddr & 0x00FF0000)>>16,
				(addr.daddr & 0xFF000000)>>24,
				addr.dest,
				sign2
		      );
		crc1 = 0;
		crc1 = _mm_crc32_u32(crc1, addr.saddr);
		crc1 = _mm_crc32_u32(crc1, addr.daddr);
		crc1 = _mm_crc32_u32(crc1, addr.source ^ addr.dest);
		printf("(%x", crc1);
		crc1 = 0;
		crc1 = _mm_crc32_u32(crc1, addr.daddr);
		crc1 = _mm_crc32_u32(crc1, addr.saddr);
		crc1 = _mm_crc32_u32(crc1, addr.source ^ addr.dest);
		printf("--  %x)\n", crc1);
#endif

		return 1;
	} else {
		return 0;
	}
}

u_int
mk_hash_index(struct tuple4 addr, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
  u_int hash = addr.saddr ^ addr.source ^ addr.daddr ^ addr.dest;
  return hash % tcp_thread_local_p->tcp_stream_table_size;
}

// This can be altered to better algorithm, 
// four bits for indexing 16 way-associative
static inline uint8_t 
get_major_location(sig_type sign)
{
	// the least significant 3 bits
	return sign & 0x0f;
}

// Here the 16 set-associative array is divided into 4 subsets
// Use the 3rd and 4th bits as the subset index
static inline uint8_t
get_subset_index(sig_type sign)
{
	return sign & 0x0c;
}

struct tcp_stream *
find_stream(struct tcphdr *this_tcphdr, struct ip *this_iphdr, int *from_client, TCP_THREAD_LOCAL_P tcp_thread_local_p)
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

	hash_index = mk_hash_index(addr, tcp_thread_local_p);

	sign = calc_signature(this_iphdr->ip_src.s_addr,
			this_iphdr->ip_dst.s_addr,
			this_tcphdr->th_sport,
			this_tcphdr->th_dport);

	// Search the cache
	elem_type *set_header = (elem_type *)&(((char *)tcp_thread_local_p->tcp_stream_table)[hash_index * SET_SIZE]);

#if defined(MAJOR_LOCATION)
	uint8_t loc = get_major_location(sign);
	search_num ++;

	// Search the Major location first
	if (sig_match_e(sign, set_header + loc)) {
		tcb_index = calc_index(hash_index, loc);

		// False positive test
		if (!is_false_positive(addr, tcb_index, tcp_thread_local_p)) {
			if (addr.source == tcp_thread_local_p->tcb_array[tcb_index].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			search_hit_num ++;
			return &(tcp_thread_local_p->tcb_array)[tcb_index];
		}
	}

	// Search the Subset of the Major location
	uint8_t subset = get_subset_index(sign);
	for (loc = subset; loc < subset + 4; loc ++) {
		if (sig_match_e(sign, set_header + loc)) {
			tcb_index = calc_index(hash_index, loc);

			// False positive test
			if (is_false_positive(addr, tcb_index, tcp_thread_local_p)) continue;

			if (addr.source == tcp_thread_local_p->tcb_array[tcb_index].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			search_set_hit_num ++;
			return &(tcp_thread_local_p->tcb_array)[tcb_index];
		}
	}

	// From next subset to the end
	for (loc = subset + 4; loc < SET_ASSOCIATIVE; loc ++) {
		if (sig_match_e(sign, set_header + loc)) {
			tcb_index = calc_index(hash_index, loc);

			// False positive test
			if (is_false_positive(addr, tcb_index, tcp_thread_local_p)) continue;

			if (addr.source == tcp_thread_local_p->tcb_array[tcb_index].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			return &(tcp_thread_local_p->tcb_array)[tcb_index];
		}
	}

	// From start to previous subset
	for (loc = 0; loc < subset; loc ++) {
		if (sig_match_e(sign, set_header + loc)) {
			tcb_index = calc_index(hash_index, loc);

			// False positive test
			if (is_false_positive(addr, tcb_index, tcp_thread_local_p)) continue;

			if (addr.source == tcp_thread_local_p->tcb_array[tcb_index].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			return &(tcp_thread_local_p->tcb_array)[tcb_index];
		}
	}
#else

	for (ptr = set_header, i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(sign, ptr)) {
			tcb_index = calc_index(hash_index, i);

			// False positive test
			if (is_false_positive(addr, tcb_index, tcp_thread_local_p)) continue;

			if (addr.source == tcp_thread_local_p->tcb_array[tcb_index].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			return &(tcp_thread_local_p->tcb_array)[tcb_index];
		}
	}
#endif

	// Not in cache, search collision linked list
	for (ptr_l = tcp_thread_local_p->conflict_list[hash_index];
		ptr_l != NULL;
		ptr_l = ptr_l->next) {
		
		if (sig_match_l(sign, ptr_l)) {

			// False positive test
			if (is_false_positive(addr, index_l(ptr_l), tcp_thread_local_p)) continue;

			if (addr.source == tcp_thread_local_p->tcb_array[index_l(ptr_l)].addr.source)
				*from_client = 1;
			else
				*from_client = 0;

			return &(tcp_thread_local_p->tcb_array)[index_l(ptr_l)];
		}
	}

	// Not found
	not_found ++;
	return NULL;
}

static idx_type add_into_cache(struct tuple4 addr, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	sig_type sign;
	int hash_index, i;
	elem_type *ptr;
	elem_list_type *ptr_l, **head_l;
	idx_type tcb_index;

	sign = calc_signature(addr.saddr, addr.daddr, addr.source, addr.dest);

	hash_index = mk_hash_index(addr, tcp_thread_local_p);

	// Search the cache
	elem_type *set_header = (elem_type *)&(((char *)tcp_thread_local_p->tcp_stream_table)[hash_index * SET_SIZE]);

#if defined(MAJOR_LOCATION)
	uint8_t loc = get_major_location(sign);
	add_num ++;
	if (sig_match_e(0, set_header + loc)) {
		ptr = set_header + loc;
		ptr->signature = sign;
		add_hit_num ++;
		return calc_index(hash_index, loc);
	}

	uint8_t subset = get_subset_index(sign);
	for (loc = subset; loc < subset + 4; loc ++) {
		if (sig_match_e(0, set_header + loc)) {
			ptr = set_header + loc;
			ptr->signature = sign;
			add_set_hit_num ++;
			return calc_index(hash_index, loc);
		}
	}

	// From next subset to the end
	for (loc = subset + 4; loc < SET_ASSOCIATIVE; loc ++) {
		if (sig_match_e(0, set_header + loc)) {
			ptr = set_header + loc;
			ptr->signature = sign;
			add_set_hit_num ++;
			return calc_index(hash_index, loc);
		}
	}

	// From start to previous subset
	for (loc = 0; loc < subset; loc ++) {
		if (sig_match_e(0, set_header + loc)) {
			ptr = set_header + loc;
			ptr->signature = sign;
			add_set_hit_num ++;
			return calc_index(hash_index, loc);
		}
	}
#else
	for (ptr = set_header, i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(0, ptr)) {
			ptr->signature = sign;
			return calc_index(hash_index, i);
		}
	}
#endif

	conflict_into_list ++;
	// Insert into the collision list
	// FIXME : Optimize the malloc with lock-free library
	ptr_l = (elem_list_type *)malloc(sizeof(elem_list_type));

	// get free index from bitmap
	// Store the TCB in collision linked list in the part above CACHE_ELEM_NUM
	// in TCB array.
	tcb_index = get_free_index(tcp_thread_local_p) + CACHE_ELEM_NUM;
	store_index_l(tcb_index, ptr_l);
	store_sig_l(sign, ptr_l);
	head_l = &(tcp_thread_local_p->conflict_list[hash_index]);

	ptr_l->next = *head_l;
	*head_l = ptr_l;
	return tcb_index;
}

void
add_new_tcp(struct tcphdr *this_tcphdr, struct ip *this_iphdr, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	struct tcp_stream *tolink;
	struct tcp_stream *a_tcp;
	struct tuple4 addr;
	idx_type index;

	addr.source = this_tcphdr->th_sport;
	addr.dest = this_tcphdr->th_dport;
	addr.saddr = this_iphdr->ip_src.s_addr;
	addr.daddr = this_iphdr->ip_dst.s_addr;

	tcp_thread_local_p->tcp_num++;
	if (tcp_thread_local_p->tcp_num > MAX_STREAM/(number_of_cpus_used-1)) {
		printf("Too many streams for a core\n");
		exit(0);
	}

	// add the index into hash cache
	index = add_into_cache(addr, tcp_thread_local_p);

	// let's have the block
	a_tcp = &(tcp_thread_local_p->tcb_array[index]);

	// fill the tcp block
	memset(a_tcp, 0, sizeof(struct tcp_stream));
	if (addr.saddr == 0 || addr.daddr == 0)
		printf("IP equals to zero !!!!!\n");
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
delete_from_cache(struct tcp_stream *a_tcp, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	sig_type sign;
	idx_type tcb_index; 
	int hash_index, i;
	elem_type *ptr;
	elem_list_type *ptr_l, *pre_l;
	struct tuple4 addr;

	addr = a_tcp->addr;
	sign = calc_signature(addr.saddr, addr.daddr, addr.source, addr.dest);

	hash_index = mk_hash_index(addr, tcp_thread_local_p);

	// Search the cache
	elem_type *set_header = (elem_type *)&(((char *)tcp_thread_local_p->tcp_stream_table)[hash_index * SET_SIZE]);

#if defined(MAJOR_LOCATION)
	uint8_t loc = get_major_location(sign);
	delete_num ++;
	if (sig_match_e(sign, set_header + loc)) {
		tcb_index = calc_index(hash_index, loc);

		// False positive test
		if (!is_false_positive(addr, tcb_index, tcp_thread_local_p)) {
			ptr = set_header + loc;
			ptr->signature = 0;
			delete_hit_num ++;
			return 0;
		}
	}

	uint8_t subset = get_subset_index(sign);
	for (loc = subset; loc < subset + 4; loc ++) {
		if (sig_match_e(sign, set_header + loc)) {
			tcb_index = calc_index(hash_index, loc);

			// False positive test
			if (is_false_positive(addr, tcb_index, tcp_thread_local_p)) continue;

			ptr = set_header + loc;
			ptr->signature = 0;
			delete_set_hit_num ++;
			return 0;
		}
	}

	// From next subset to the end
	for (loc = subset + 4; loc < SET_ASSOCIATIVE; loc ++) {
		if (sig_match_e(sign, set_header + loc)) {
			tcb_index = calc_index(hash_index, loc);

			// False positive test
			if (is_false_positive(addr, tcb_index, tcp_thread_local_p)) continue;

			ptr = set_header + loc;
			ptr->signature = 0;
			delete_set_hit_num ++;
			return 0;
		}
	}

	// From start to previous subset
	for (loc = 0; loc < subset; loc ++) {
		if (sig_match_e(sign, set_header + loc)) {
			tcb_index = calc_index(hash_index, loc);

			// False positive test
			if (is_false_positive(addr, tcb_index, tcp_thread_local_p)) continue;

			ptr = set_header + loc;
			ptr->signature = 0;
			delete_set_hit_num ++;
			return 0;
		}
	}
#else
	for (ptr = set_header, i = 0;
		i < SET_ASSOCIATIVE;
		i ++, ptr ++) {
		
		if (sig_match_e(sign, ptr)) {
			tcb_index = calc_index(hash_index, i);

			// False positive test
			if (is_false_positive(addr, tcb_index, tcp_thread_local_p)) continue;

			ptr->signature = 0;
			return 0;
		}
	}
#endif

	// Search the collision list
	for (ptr_l = tcp_thread_local_p->conflict_list[hash_index];
		ptr_l != NULL;
		pre_l = ptr_l, ptr_l = ptr_l->next) {
		
		if (sig_match_l(sign, ptr_l)) {
			tcb_index = index_l(ptr_l);

			// False positive test
			if (is_false_positive(addr, tcb_index, tcp_thread_local_p)) continue;

			if (pre_l == NULL) {
				// The first match, update head
				tcp_thread_local_p->conflict_list[hash_index] = ptr_l->next;
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
nids_free_tcp_stream(struct tcp_stream *a_tcp, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	struct lurker_node *i, *j;
	idx_type tcb_index;

	del_tcp_closing_timeout(a_tcp, tcp_thread_local_p);
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
	tcp_thread_local_p->tcp_num --;

	tcb_index = delete_from_cache(a_tcp, tcp_thread_local_p);
	if (tcb_index >= CACHE_ELEM_NUM) {
		ret_free_index(tcb_index - CACHE_ELEM_NUM, tcp_thread_local_p);
	}
	return;
}

int
tcp_init(int size, TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	int i;
	struct tcp_timeout *tmp;

	init_bitmap(tcp_thread_local_p);

	// The hash table
	tcp_thread_local_p->tcp_stream_table_size = SET_NUMBER/(number_of_cpus_used - 1);
	tcp_thread_local_p->tcp_stream_table = calloc(SET_NUMBER/(number_of_cpus_used - 1), SET_SIZE);
	if (!tcp_thread_local_p->tcp_stream_table) {
		printf("tcp_stream_table in tcp_init");
		exit(0);
		return -1;
	}

	// The conflict Ptr list
	tcp_thread_local_p->conflict_list = calloc(SET_NUMBER/(number_of_cpus_used - 1), PTR_SIZE);
	if (!tcp_thread_local_p->conflict_list) {
		printf("conflict in tcp_init");
		exit(0);
		return -1;
	}

	// The TCB array
	tcp_thread_local_p->tcb_array = calloc(MAX_STREAM/(number_of_cpus_used - 1), sizeof(struct tcp_stream));
	if (!tcp_thread_local_p->tcb_array) {
		printf("What the fuck, NULL in calloc\n");
	}
	printf("+++++++++++%d+++++++++++++\n", MAX_STREAM/(number_of_cpus_used - 1));
	if (!tcp_thread_local_p->tcb_array) {
		printf("tcp_array in tcp_init");
		exit(0);
		return -1;
	}

	// Following can be optimized
	// init_hash();
	while (tcp_thread_local_p->nids_tcp_timeouts) {
		tmp = tcp_thread_local_p->nids_tcp_timeouts->next;
		free(tcp_thread_local_p->nids_tcp_timeouts);
		tcp_thread_local_p->nids_tcp_timeouts = tmp;
	}
	return 0;
}

// FIXME: Need search the cache table, call corresponding callback function,
// and release resource in this function
void
tcp_exit(TCP_THREAD_LOCAL_P tcp_thread_local_p)
{
	int i;
	struct lurker_node *j;
	struct tcp_stream *a_tcp, *t_tcp;

	if (!tcp_thread_local_p->tcp_stream_table || !tcp_thread_local_p->tcb_array)
		return;
	free(tcp_thread_local_p->tcb_array);
	free(tcp_thread_local_p->tcp_stream_table);
	free(tcp_thread_local_p->conflict_list);
	tcp_thread_local_p->tcp_stream_table = NULL;
	tcp_thread_local_p->tcp_num = 0;
	return;
}

void
process_tcp(u_char * data, int skblen, TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	struct ip *this_iphdr = (struct ip *)data;
	struct tcphdr *this_tcphdr = (struct tcphdr *)(data + 4 * this_iphdr->ip_hl);
	int datalen, iplen;
	int from_client = 1;
	unsigned int tmp_ts;
	struct tcp_stream *a_tcp;
	struct half_stream *snd, *rcv;

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
	if (!a_tcp->listeners)
		nids_free_tcp_stream(a_tcp, tcp_thread_local_p);
}
#endif