/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
  See the file COPYING for license details.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include "checksum.h"
#include "scan.h"
#include "tcp.threaded.h"
#include "util.h"
#include "nids.h"
#include "hash.h"
#include "conn_attribute.h"
#include "conn_tcp.threaded.h"
#include "conn_indexfree.threaded.h"
#include "conn_major_indexfree.threaded.h"
#if 0
#include "conn_split.h"
#include "conn_indexfree.h"
#include "conn_major_indexfree.h"
#endif
#if ! HAVE_TCP_STATES
enum {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING			/* now a valid state */
};

#endif

#define EXP_SEQ (snd->first_data_seq + rcv->count + rcv->urg_count)

extern struct proc_node *tcp_procs;

void purge_queue(struct half_stream * h)
{
	struct skbuff *tmp, *p = h->list;

	while (p) {
		free(p->data);
		tmp = p->next;
		free(p);
		p = tmp;
	}
	h->list = h->listtail = 0;
	h->rmem_alloc = 0;
}

static void
add_tcp_closing_timeout(struct tcp_stream * a_tcp, TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	struct tcp_timeout *to;
	struct tcp_timeout *newto;

	if (!nids_params.tcp_workarounds)
		return;
	newto = malloc(sizeof (struct tcp_timeout));
	newto->a_tcp = a_tcp;

	// FIXME: There is a cache thrashing, no matter whether we use multi-IP core
	newto->timeout.tv_sec = nids_last_pcap_header->ts.tv_sec + 10;
	newto->prev = 0;
	for (newto->next = to = tcp_thread_local_p->nids_tcp_timeouts; to; newto->next = to = to->next) {
		if (to->a_tcp == a_tcp) {
			free(newto);
			return;
		}
		if (to->timeout.tv_sec > newto->timeout.tv_sec)
			break;
		newto->prev = to;
	}
	if (!newto->prev)
		tcp_thread_local_p->nids_tcp_timeouts = newto;
	else
		newto->prev->next = newto;
	if (newto->next)
		newto->next->prev = newto;
}

void
del_tcp_closing_timeout(struct tcp_stream * a_tcp, TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	struct tcp_timeout *to;

	if (!nids_params.tcp_workarounds)
		return;
	for (to = tcp_thread_local_p->nids_tcp_timeouts; to; to = to->next)
		if (to->a_tcp == a_tcp)
			break;
	if (!to)
		return;
	if (!to->prev)
		tcp_thread_local_p->nids_tcp_timeouts = to->next;
	else
		to->prev->next = to->next;
	if (to->next)
		to->next->prev = to->prev;
	free(to);
}

void
tcp_check_timeouts(struct timeval *now,TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	struct tcp_timeout *to;
	struct tcp_timeout *next;
	struct lurker_node *i;

	for (to = tcp_thread_local_p->nids_tcp_timeouts; to; to = next) {
		if (now->tv_sec < to->timeout.tv_sec)
			return;
		to->a_tcp->nids_state = NIDS_TIMED_OUT;
		for (i = to->a_tcp->listeners; i; i = i->next)
			(i->item) (to->a_tcp, &i->data);
		next = to->next;
		nids_free_tcp_stream(to->a_tcp, tcp_thread_local_p);
	}
}

int get_ts(struct tcphdr * this_tcphdr, unsigned int * ts)
{
	int len = 4 * this_tcphdr->th_off;
	unsigned int tmp_ts;
	unsigned char * options = (unsigned char*)(this_tcphdr + 1);
	int ind = 0, ret = 0;
	while (ind <=  len - (int)sizeof (struct tcphdr) - 10 )
		switch (options[ind]) {
		case 0: /* TCPOPT_EOL */
			return ret;
		case 1: /* TCPOPT_NOP */
			ind++;
			continue;
		case 8: /* TCPOPT_TIMESTAMP */
			memcpy((char*)&tmp_ts, options + ind + 2, 4);
			*ts=ntohl(tmp_ts);
			ret = 1;
			/* no break, intentionally */
		default:
			if (options[ind+1] < 2 ) /* "silly option" */
				return ret;
			ind += options[ind+1];
		}

	return ret;
}

int get_wscale(struct tcphdr * this_tcphdr, unsigned int * ws)
{
	int len = 4 * this_tcphdr->th_off;
	unsigned int tmp_ws;
	unsigned char * options = (unsigned char*)(this_tcphdr + 1);
	int ind = 0, ret = 0;
	*ws=1;
	while (ind <=  len - (int)sizeof (struct tcphdr) - 3 )
		switch (options[ind]) {
		case 0: /* TCPOPT_EOL */
			return ret;
		case 1: /* TCPOPT_NOP */
			ind++;
			continue;
		case 3: /* TCPOPT_WSCALE */
			tmp_ws=options[ind+2];
			if (tmp_ws>14)
				tmp_ws=14;
			*ws=1<<tmp_ws;
			ret = 1;
			/* no break, intentionally */
		default:
			if (options[ind+1] < 2 ) /* "silly option" */
				return ret;
			ind += options[ind+1];
		}

	return ret;
}

static void
add2buf(struct half_stream * rcv, unsigned char *data, int datalen)
{
	int toalloc;

	if (datalen + rcv->count - rcv->offset > rcv->bufsize) {
		if (!rcv->data) {
			if (datalen < 2048)
				toalloc = 4096;
			else
				toalloc = datalen * 2;
			rcv->data = malloc(toalloc);
			rcv->bufsize = toalloc;
		}
		else {
			if (datalen < rcv->bufsize)
				toalloc = 2 * rcv->bufsize;
			else
				toalloc = rcv->bufsize + 2*datalen;
			rcv->data = realloc(rcv->data, toalloc);
			rcv->bufsize = toalloc;
		}
		if (!rcv->data)
			nids_params.no_mem("add2buf");
	}
	memcpy(rcv->data + rcv->count - rcv->offset, data, datalen);
	rcv->count_new += datalen;
	rcv->count += datalen;
}

static void
ride_lurkers(struct tcp_stream * a_tcp, char mask)
{
	struct lurker_node *i;
	char cc, sc, ccu, scu;

	for (i = a_tcp->listeners; i; i = i->next)
		if (i->whatto & mask) {
			cc = a_tcp->client.collect;
			sc = a_tcp->server.collect;
			ccu = a_tcp->client.collect_urg;
			scu = a_tcp->server.collect_urg;

			(i->item) (a_tcp, &i->data);
			if (cc < a_tcp->client.collect)
				i->whatto |= COLLECT_cc;
			if (ccu < a_tcp->client.collect_urg)
				i->whatto |= COLLECT_ccu;
			if (sc < a_tcp->server.collect)
				i->whatto |= COLLECT_sc;
			if (scu < a_tcp->server.collect_urg)
				i->whatto |= COLLECT_scu;
			if (cc > a_tcp->client.collect)
				i->whatto &= ~COLLECT_cc;
			if (ccu > a_tcp->client.collect_urg)
				i->whatto &= ~COLLECT_ccu;
			if (sc > a_tcp->server.collect)
				i->whatto &= ~COLLECT_sc;
			if (scu > a_tcp->server.collect_urg)
				i->whatto &= ~COLLECT_scu;
		}
}

static void
notify(struct tcp_stream * a_tcp, struct half_stream * rcv)
{
	struct lurker_node *i, **prev_addr;
	char mask;

	if (rcv->count_new_urg) {
		if (!rcv->collect_urg)
			return;
		if (rcv == &a_tcp->client)
			mask = COLLECT_ccu;
		else
			mask = COLLECT_scu;
		ride_lurkers(a_tcp, mask);
		goto prune_listeners;
	}
	if (rcv->collect) {
		if (rcv == &a_tcp->client)
			mask = COLLECT_cc;
		else
			mask = COLLECT_sc;
		do {
			int total;
			a_tcp->read = rcv->count - rcv->offset;
			total=a_tcp->read;

			ride_lurkers(a_tcp, mask);
			if (a_tcp->read>total-rcv->count_new)
				rcv->count_new=total-a_tcp->read;

			if (a_tcp->read > 0) {
				memmove(rcv->data, rcv->data + a_tcp->read, rcv->count - rcv->offset - a_tcp->read);
				rcv->offset += a_tcp->read;
			}
		}while (nids_params.one_loop_less && a_tcp->read>0 && rcv->count_new); 
		// we know that if one_loop_less!=0, we have only one callback to notify
		rcv->count_new=0;	    
	}
prune_listeners:
	prev_addr = &a_tcp->listeners;
	i = a_tcp->listeners;
	while (i)
		if (!i->whatto) {
			*prev_addr = i->next;
			free(i);
			i = *prev_addr;
		}
		else {
			prev_addr = &i->next;
			i = i->next;
		}
}

static void
add_from_skb(struct tcp_stream * a_tcp, struct half_stream * rcv,
             struct half_stream * snd,
             u_char *data, int datalen,
             u_int this_seq, char fin, char urg, u_int urg_ptr, TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	u_int lost = EXP_SEQ - this_seq;
	int to_copy, to_copy2;

	if (urg && after(urg_ptr, EXP_SEQ - 1) &&
			(!rcv->urg_seen || after(urg_ptr, rcv->urg_ptr))) {
		rcv->urg_ptr = urg_ptr;
		rcv->urg_seen = 1;
	}

#if !defined(DISABLE_UPPER_LAYER)
	if (rcv->urg_seen && after(rcv->urg_ptr + 1, this_seq + lost) &&
			before(rcv->urg_ptr, this_seq + datalen)) {
		to_copy = rcv->urg_ptr - (this_seq + lost);
		if (to_copy > 0) {
			if (rcv->collect) {
				add2buf(rcv, (char *)(data + lost), to_copy);
				notify(a_tcp, rcv);
			}
			else {
				rcv->count += to_copy;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
		//    rcv->urgdata = data[rcv->urg_ptr - this_seq];
		rcv->count_new_urg = 1;
		notify(a_tcp, rcv);
		rcv->count_new_urg = 0;
		rcv->urg_seen = 0;
		rcv->urg_count++;
		to_copy2 = this_seq + datalen - rcv->urg_ptr - 1;
		if (to_copy2 > 0) {
			if (rcv->collect) {
				add2buf(rcv, (char *)(data + lost + to_copy + 1), to_copy2);
				notify(a_tcp, rcv);
			}
			else {
				rcv->count += to_copy2;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
	}
	else {
		if (datalen - lost > 0) {
			if (rcv->collect) {
				add2buf(rcv, (char *)(data + lost), datalen - lost);
				notify(a_tcp, rcv);
			}
			else {
				rcv->count += datalen - lost;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
	}
#endif
	if (fin) {
		snd->state = FIN_SENT;
		if (rcv->state == TCP_CLOSING)
			add_tcp_closing_timeout(a_tcp,tcp_thread_local_p);
	}
}

void
tcp_queue(struct tcp_stream * a_tcp, struct tcphdr * this_tcphdr,
          struct half_stream * snd, struct half_stream * rcv,
          char *data, int datalen, int skblen
          , TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	u_int this_seq = ntohl(this_tcphdr->th_seq);
	struct skbuff *pakiet, *tmp;

	/*
	 * Did we get anything new to ack?
	 */

	if (!after(this_seq, EXP_SEQ)) {
		if (after(this_seq + datalen + (this_tcphdr->th_flags & TH_FIN), EXP_SEQ)) {
			/* the packet straddles our window end */
			get_ts(this_tcphdr, &snd->curr_ts);

#if defined(DISABLE_UPPER_LAYER)
			// TCP algorithm test, do not copy packet data for upper layer use -- Kay
			rcv->count_new = datalen;
			rcv->count += datalen;
#endif
			add_from_skb(a_tcp, rcv, snd, (u_char *)data, datalen, this_seq,
					(this_tcphdr->th_flags & TH_FIN),
					(this_tcphdr->th_flags & TH_URG),
					ntohs(this_tcphdr->th_urp) + this_seq - 1,
					tcp_thread_local_p);

			/*
			 * Do we have any old packets to ack that the above
			 * made visible? (Go forward from skb)
			 */
			pakiet = rcv->list;
			while (pakiet) {
				if (after(pakiet->seq, EXP_SEQ))
					break;
				if (after(pakiet->seq + pakiet->len + pakiet->fin, EXP_SEQ)) {
					add_from_skb(a_tcp, rcv, snd, pakiet->data,
							pakiet->len, pakiet->seq, pakiet->fin, pakiet->urg,
							pakiet->urg_ptr + pakiet->seq - 1, tcp_thread_local_p);
				}
				rcv->rmem_alloc -= pakiet->truesize;
				if (pakiet->prev)
					pakiet->prev->next = pakiet->next;
				else
					rcv->list = pakiet->next;
				if (pakiet->next)
					pakiet->next->prev = pakiet->prev;
				else
					rcv->listtail = pakiet->prev;
				tmp = pakiet->next;
				free(pakiet->data);
				free(pakiet);
				pakiet = tmp;
			}
		}
		else
			return;
	}
	else {
		struct skbuff *p = rcv->listtail;

		pakiet = mknew(struct skbuff);
		pakiet->truesize = skblen;
		rcv->rmem_alloc += pakiet->truesize;
		pakiet->len = datalen;
		pakiet->data = malloc(datalen);
		if (!pakiet->data)
			nids_params.no_mem("tcp_queue");
		memcpy(pakiet->data, data, datalen);
		pakiet->fin = (this_tcphdr->th_flags & TH_FIN);
		/* Some Cisco - at least - hardware accept to close a TCP connection
		 * even though packets were lost before the first TCP FIN packet and
		 * never retransmitted; this violates RFC 793, but since it really
		 * happens, it has to be dealt with... The idea is to introduce a 10s
		 * timeout after TCP FIN packets were sent by both sides so that
		 * corresponding libnids resources can be released instead of waiting
		 * for retransmissions which will never happen.  -- Sebastien Raveau
		 */
		if (pakiet->fin) {
			snd->state = TCP_CLOSING;
			if (rcv->state == FIN_SENT || rcv->state == FIN_CONFIRMED)
				add_tcp_closing_timeout(a_tcp, tcp_thread_local_p);
		}
		pakiet->seq = this_seq;
		pakiet->urg = (this_tcphdr->th_flags & TH_URG);
		pakiet->urg_ptr = ntohs(this_tcphdr->th_urp);
		for (;;) {
			if (!p || !after(p->seq, this_seq))
				break;
			p = p->prev;
		}
		if (!p) {
			pakiet->prev = 0;
			pakiet->next = rcv->list;
			if (rcv->list)
				rcv->list->prev = pakiet;
			rcv->list = pakiet;
			if (!rcv->listtail)
				rcv->listtail = pakiet;
		}
		else {
			pakiet->next = p->next;
			p->next = pakiet;
			pakiet->prev = p;
			if (pakiet->next)
				pakiet->next->prev = pakiet;
			else
				rcv->listtail = pakiet;
		}
	}
}

void
prune_queue(struct half_stream * rcv, struct tcphdr * this_tcphdr)
{
	struct skbuff *tmp, *p = rcv->list;

	//nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BIGQUEUE, tcp_thread_local_p->ugly_iphdr, this_tcphdr);
	while (p) {
		free(p->data);
		tmp = p->next;
		free(p);
		p = tmp;
	}
	rcv->list = rcv->listtail = 0;
	rcv->rmem_alloc = 0;
}

void
handle_ack(struct half_stream * snd, u_int acknum)
{
	int ackdiff;

	ackdiff = acknum - snd->ack_seq;
	if (ackdiff > 0) {
		snd->ack_seq = acknum;
	}
}

/* static void
check_flags(struct ip * iph, struct tcphdr * th)
{
    u_char flag = *(((u_char *) th) + 13);
    if (flag & 0x40 || flag & 0x80)
        nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BADFLAGS, iph, th);
//ECN is really the only cause of these warnings...
} */


void
nids_discard(struct tcp_stream * a_tcp, int num)
{ /* FIX   libnids will discards at most num bytes after this function */
	if (num < a_tcp->read)
		a_tcp->read = num;
}

void
nids_register_tcp(void (*x))
{
	register_callback(&tcp_procs, x);
}

void
nids_unregister_tcp(void (*x))
{
	unregister_callback(&tcp_procs, x);
}


#if HAVE_ICMPHDR
#define STRUCT_ICMP struct icmphdr
#define ICMP_CODE   code
#define ICMP_TYPE   type
#else
#define STRUCT_ICMP struct icmp
#define ICMP_CODE   icmp_code
#define ICMP_TYPE   icmp_type
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH ICMP_UNREACH
#define ICMP_PROT_UNREACH ICMP_UNREACH_PROTOCOL
#define ICMP_PORT_UNREACH ICMP_UNREACH_PORT
#define NR_ICMP_UNREACH   ICMP_MAXTYPE
#endif


void
process_icmp(u_char * data, TCP_THREAD_LOCAL_P  tcp_thread_local_p)
{
	struct ip *iph = (struct ip *) data;
	struct ip *orig_ip;
	STRUCT_ICMP *pkt;
	struct tcphdr *th;
	struct half_stream *hlf;
	int match_addr;
	struct tcp_stream *a_tcp;
	struct lurker_node *i;

	int from_client;
	/* we will use unsigned, to suppress warning; we must be careful with
	   possible wrap when substracting 
	   the following is ok, as the ip header has already been sanitized */
	unsigned int len = ntohs(iph->ip_len) - (iph->ip_hl << 2);

	if (len < sizeof(STRUCT_ICMP))
		return;
	pkt = (STRUCT_ICMP *) (data + (iph->ip_hl << 2));
	if (ip_compute_csum((char *) pkt, len))
		return;
	if (pkt->ICMP_TYPE != ICMP_DEST_UNREACH)
		return;
	/* ok due to check 7 lines above */  
	len -= sizeof(STRUCT_ICMP);
	// sizeof(struct icmp) is not what we want here

	if (len < sizeof(struct ip))
		return;

	orig_ip = (struct ip *) (((char *) pkt) + 8);
	if (len < (unsigned)(orig_ip->ip_hl << 2) + 8)
		return;
	/* subtraction ok due to the check above */
	len -= orig_ip->ip_hl << 2;
	if ((pkt->ICMP_CODE & 15) == ICMP_PROT_UNREACH ||
			(pkt->ICMP_CODE & 15) == ICMP_PORT_UNREACH)
		match_addr = 1;
	else
		match_addr = 0;
	if (pkt->ICMP_CODE > NR_ICMP_UNREACH)
		return;
	if (match_addr && (iph->ip_src.s_addr != orig_ip->ip_dst.s_addr))
		return;
	if (orig_ip->ip_p != IPPROTO_TCP)
		return;
	th = (struct tcphdr *) (((char *) orig_ip) + (orig_ip->ip_hl << 2));
	if (!(a_tcp = find_stream(th, orig_ip, &from_client, tcp_thread_local_p)))
		return;
	if (a_tcp->addr.dest == iph->ip_dst.s_addr)
		hlf = &a_tcp->server;
	else
		hlf = &a_tcp->client;
	if (hlf->state != TCP_SYN_SENT && hlf->state != TCP_SYN_RECV)
		return;
	a_tcp->nids_state = NIDS_RESET;
	for (i = a_tcp->listeners; i; i = i->next)
		(i->item) (a_tcp, &i->data);
	nids_free_tcp_stream(a_tcp, tcp_thread_local_p);
}
