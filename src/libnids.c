/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#include <config.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <alloca.h>
#include <pcap.h>
#include <errno.h>
#include <config.h>
#if (HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <stdlib.h>
#include "checksum.h"
#if defined(PARALLEL)
#include "ip_fragment.threaded.h"
#include "tcp.threaded.h"
#include "parallel.h"
#include "conn_tcp.threaded.h"
#include "conn_indexfree.threaded.h"
#include "conn_major_indexfree.threaded.h"
#include <sched.h>
#include <pthread.h>
#include <time.h>
#else
#include "ip_fragment.h"
#include "tcp.h"
#endif
#include "scan.h"
#include "util.h"
#include "nids.h"
#include "fifo.h"


#if defined(PARALLEL)

#include <sched.h>
#include "parallel.h"

extern FIFO_CTRL fifo_g[];
extern FIFO_BUFFER buffer_g[];

#define LOAD_BALANCE_ARRAY_SIZE 32

static _IP_THREAD_LOCAL_P ip_thread_local_struct[MAX_CPU_CORES] __attribute__((aligned(16)));
static pthread_t  ip_thread_ctrl[MAX_CPU_CORES] __attribute__((aligned(16)));
static _TCP_THREAD_LOCAL_P tcp_thread_local_struct[MAX_CPU_CORES] __attribute__((aligned(16)));

int cpu_id[8] = {2,4,6,1,3,5,7};
int number_of_cpus_used = 2;
int cpus_time_used[MAX_CPU_CORES];

int load_balance_array[8][LOAD_BALANCE_ARRAY_SIZE]={
{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
{2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2},
{2,4,2,4,2,4,2,4,2,4,2,4,2,4,2,4,2,4,2,4,2,4,2,4,2,4,2,4,2,4,2,4},
{2,4,6,2,4,6,2,4,6,2,4,6,2,4,6,2,4,6,2,4,6,2,4,6,2,4,6,2,4,6,2,4},
{2,4,6,1,2,4,6,1,2,4,6,1,2,4,6,1,2,4,6,1,2,4,6,1,2,4,6,1,2,4,6,1},
{2,4,6,1,3,2,4,6,1,3,2,4,6,1,3,2,4,6,1,3,2,4,6,1,3,2,4,6,1,3,2,4},
{2,4,6,1,3,5,2,4,6,1,3,5,2,4,6,1,3,5,2,4,6,1,3,5,2,4,6,1,3,5,2,4},
{2,4,6,1,3,5,7,2,4,6,1,3,5,7,2,4,6,1,3,5,7,2,4,6,1,3,5,7,2,4,6,1},
};

#endif

#ifdef __linux__
extern int set_all_promisc();
#endif

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))
extern int ip_options_compile(unsigned char *);
extern int raw_init();
static void nids_syslog(int, int, struct ip *, void *);
static int nids_ip_filter(struct ip *, int);

static struct proc_node *ip_frag_procs;
static struct proc_node *ip_procs;
static struct proc_node *udp_procs;

struct proc_node *tcp_procs;
static int linktype;
static pcap_t *desc = NULL;

char nids_errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr * nids_last_pcap_header = NULL;
u_char *nids_last_pcap_data = NULL;
u_int nids_linkoffset = 0;

uint64_t tcp_proc_time = 0;
uint64_t tcp_proc_num = 0;

char *nids_warnings[] = {
    "Murphy - you never should see this message !",
    "Oversized IP packet",
    "Invalid IP fragment list: fragment over size",
    "Overlapping IP fragments",
    "Invalid IP header",
    "Source routed IP frame",
    "Max number of TCP streams reached",
    "Invalid TCP header",
    "Too much data in TCP receive queue",
    "Invalid TCP flags"
};

struct nids_prm nids_params = {
    1040,			/* n_tcp_streams */
    256,			/* n_hosts */
    NULL,			/* device */
//    "/home/kay/trace/merged.pcap",			/* filename */
    "a.pcap",
    168,			/* sk_buff_size */
    -1,				/* dev_addon */
    nids_syslog,		/* syslog() */
    LOG_ALERT,			/* syslog_level */
    256,			/* scan_num_hosts */
    3000,			/* scan_delay */
    10,				/* scan_num_ports */
    nids_no_mem,		/* no_mem() */
    nids_ip_filter,		/* ip_filter() */
    NULL,			/* pcap_filter */
    1,				/* promisc */
    0,				/* one_loop_less */
    1024,			/* pcap_timeout */
    0,				/* multiproc */
    20000,			/* queue_limit */
    0,				/* tcp_workarounds */
    NULL			/* pcap_desc */
};

static int nids_ip_filter(struct ip *x, int len)
{
    (void)x;
    (void)len;
    return 1;
}

static void nids_syslog(int type, int errnum, struct ip *iph, void *data)
{
    char saddr[20], daddr[20];
    char buf[1024];
    struct host *this_host;
    unsigned char flagsand = 255, flagsor = 0;
    int i;

    switch (type) {

    case NIDS_WARN_IP:
	if (errnum != NIDS_WARN_IP_HDR) {
	    strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	    strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	    syslog(nids_params.syslog_level,
		   "%s, packet (apparently) from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	} else
	    syslog(nids_params.syslog_level, "%s\n",
		   nids_warnings[errnum]);
	break;

    case NIDS_WARN_TCP:
	strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
	strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
	if (errnum != NIDS_WARN_TCP_HDR)
	    syslog(nids_params.syslog_level,
		   "%s,from %s:%hu to  %s:%hu\n", nids_warnings[errnum],
		   saddr, ntohs(((struct tcphdr *) data)->th_sport), daddr,
		   ntohs(((struct tcphdr *) data)->th_dport));
	else
	    syslog(nids_params.syslog_level, "%s,from %s to %s\n",
		   nids_warnings[errnum], saddr, daddr);
	break;

    case NIDS_WARN_SCAN:
	this_host = (struct host *) data;
	sprintf(buf, "Scan from %s. Scanned ports: ",
		int_ntoa(this_host->addr));
	for (i = 0; i < this_host->n_packets; i++) {
	    strcat(buf, int_ntoa(this_host->packets[i].addr));
	    sprintf(buf + strlen(buf), ":%hu,",
		    this_host->packets[i].port);
	    flagsand &= this_host->packets[i].flags;
	    flagsor |= this_host->packets[i].flags;
	}
	if (flagsand == flagsor) {
	    i = flagsand;
	    switch (flagsand) {
	    case 2:
		strcat(buf, "scan type: SYN");
		break;
	    case 0:
		strcat(buf, "scan type: NULL");
		break;
	    case 1:
		strcat(buf, "scan type: FIN");
		break;
	    default:
		sprintf(buf + strlen(buf), "flags=0x%x", i);
	    }
	} else
	    strcat(buf, "various flags");
	syslog(nids_params.syslog_level, "%s", buf);
	break;

    default:
	syslog(nids_params.syslog_level, "Unknown warning number ?\n");
    }
}

#if defined(PARALLEL)
inline static int load_balance(int hash_index) {
// map nothing to CPU0 if FREE_CPU0 is defined
	hash_index = (hash_index & 0xFF) + (hash_index >> 8);
	hash_index = (hash_index & 0xF) + (hash_index >> 4);
	hash_index = hash_index & 0x1F; // <32
	int id;
	id = load_balance_array[number_of_cpus_used - 1][hash_index];
	return id;
}

/* called either directly from pcap_hand() or from cap_queue_process_thread()
 * depending on the value of nids_params.multiproc - mcree
 */
static void call_ip_frag_procs(void *data, bpf_u_int32 caplen)
{
	int res;
	struct ip  *this_iphdr = (struct ip *) data;
	u_int saddr = this_iphdr->ip_src.s_addr;
	u_int daddr = this_iphdr->ip_dst.s_addr;
	u_int xor   = saddr ^ daddr;
	u_int sum16 = (xor & 0xFFFF) + (xor >> 16);
	u_short ap_core_id   = load_balance(sum16);

	// FIFO ID equals to the AP core's ID, so that each AP core
	// can use its own ID as the FIFO ID.
	u_short fifo_id = ap_core_id;

	void *data_buf = malloc(caplen);
	memcpy(data_buf, data, caplen);

	{
		FIFO_ELEM elem;
		FIFO_ELEM_DATA(&elem) = data_buf;
		FIFO_ELEM_SIZE(&elem) = caplen; 

		do{ 
			res = insert(&fifo_g[fifo_id], &buffer_g[fifo_id], elem);
		} while (res < 0); 

	}

}
#else
static void call_ip_frag_procs(void *data, bpf_u_int32 caplen)
{
    struct proc_node *i;
    for (i = ip_frag_procs; i; i = i->next)
	(i->item) (data, caplen);
}
#endif

#if defined(PARALLEL)

static void gen_ip_frag_proc(char *, int, IP_THREAD_LOCAL_P);

static void ip_queue_process_thread(void *cpu_id) 
{
	int first = 1;
	int thread_id = (int)(long)cpu_id;
	int fifo_id;

	int result;
	FIFO_ELEM  elem;
	IP_THREAD_LOCAL_P t_ptr = &ip_thread_local_struct[thread_id];
	struct timeval t1, t2;

	//! sched_setaffinity
	unsigned long mask;
//	CPU_ZERO(&mask);
//	CPU_SET(thread_id, &mask);
//	mask = (1 << thread_id);
	mask = 0x1;
	
	printf("HEY, IAM AP : %d\n", thread_id);

/*
	if (sched_setaffinity(0, sizeof(unsigned long), &mask) < 0) {
		printf("Error: sched_setaffinity\n");
		return ;
	}
*/
	tcp_thread_local_struct[thread_id].self_cpu_id = thread_id;
	tcp_init(nids_params.n_tcp_streams, &tcp_thread_local_struct[thread_id]);


	while (1) { /* loop "forever" */

		fifo_id = thread_id;

		do {
			result = extract(&fifo_g[fifo_id], &buffer_g[fifo_id], &elem);
		} while( result != SUCCESS );

		if( first == 1) {
			first = 0;
			gettimeofday(&t1, 0);
		}
		if (elem.len == 0xFFFF) { /* EOF item received: we should exit */
			goto end_loop;
		}
		gen_ip_frag_proc(elem.data, elem.len, t_ptr);
	}
end_loop:
	gettimeofday(&t2, 0);
	cpus_time_used[t_ptr->self_cpu_id] = compute_time(&t1, &t2);
	pthread_exit(NULL);
}

#endif

/* wireless frame types, mostly from tcpdump (wam) */
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)
#define DATA_FRAME_IS_QOS(x)    ((x) & 0x08)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define T_MGMT 0x0		/* management */
#define T_CTRL 0x1		/* control */
#define T_DATA 0x2		/* data */
#define T_RESV 0x3		/* reserved */
#define EXTRACT_LE_16BITS(p) \
	((unsigned short)*((const unsigned char *)(p) + 1) << 8 | \
	(unsigned short)*((const unsigned char *)(p) + 0))
#define EXTRACT_16BITS(p)	((unsigned short)ntohs(*(const unsigned short *)(p)))
#define LLC_FRAME_SIZE 8
#define LLC_OFFSET_TO_TYPE_FIELD 6
#define ETHERTYPE_IP 0x0800

void nids_pcap_handler(u_char * par, struct pcap_pkthdr *hdr, u_char * data)
{
	u_char *data_aligned;
#ifdef DLT_IEEE802_11
	unsigned short fc;
	int linkoffset_tweaked_by_prism_code = 0;
	int linkoffset_tweaked_by_radio_code = 0;
#endif

	/*
	 * Check for savagely closed TCP connections. Might
	 * happen only when nids_params.tcp_workarounds is non-zero;
	 * otherwise nids_tcp_timeouts is always NULL.
	 */
	//    if (NULL != nids_tcp_timeouts)
	//      tcp_check_timeouts(&hdr->ts);

	nids_last_pcap_header = hdr;
	nids_last_pcap_data = data;
	(void)par; /* warnings... */
	switch (linktype) {
		case DLT_EN10MB:
			if (hdr->caplen < 14)
				return;
			/* Only handle IP packets and 802.1Q VLAN tagged packets below. */
			if (data[12] == 8 && data[13] == 0) {
				/* Regular ethernet */
				nids_linkoffset = 14;
			} else if (data[12] == 0x81 && data[13] == 0) {
				/* Skip 802.1Q VLAN and priority information */
				nids_linkoffset = 18;
			} else
				/* non-ip frame */
				return;
			break;
#ifdef DLT_PRISM_HEADER
#ifndef DLT_IEEE802_11
#error DLT_PRISM_HEADER is defined, but DLT_IEEE802_11 is not ???
#endif
		case DLT_PRISM_HEADER:
			nids_linkoffset = 144; //sizeof(prism2_hdr);
			linkoffset_tweaked_by_prism_code = 1;
			//now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11_RADIO
		case DLT_IEEE802_11_RADIO:
			// just get rid of the radio tap header
			if (!linkoffset_tweaked_by_prism_code) {
				nids_linkoffset = EXTRACT_LE_16BITS(data + 2); // skip radiotap header
				linkoffset_tweaked_by_radio_code = 1;
			}
			//now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11
		case DLT_IEEE802_11:
			/* I don't know why frame control is always little endian, but it 
			 * works for tcpdump, so who am I to complain? (wam)
			 */
			if (!linkoffset_tweaked_by_prism_code && !linkoffset_tweaked_by_radio_code)
				nids_linkoffset = 0;
			fc = EXTRACT_LE_16BITS(data + nids_linkoffset);
			if (FC_TYPE(fc) != T_DATA || FC_WEP(fc)) {
				return;
			}
			if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
				/* a wireless distribution system packet will have another
				 * MAC addr in the frame
				 */
				nids_linkoffset += 30;
			} else {
				nids_linkoffset += 24;
			}
			if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
				nids_linkoffset += 2;
			if (hdr->len < nids_linkoffset + LLC_FRAME_SIZE)
				return;
			if (ETHERTYPE_IP !=
					EXTRACT_16BITS(data + nids_linkoffset + LLC_OFFSET_TO_TYPE_FIELD)) {
				/* EAP, LEAP, and other 802.11 enhancements can be 
				 * encapsulated within a data packet too.  Look only at
				 * encapsulated IP packets (Type field of the LLC frame).
				 */
				return;
			}
			nids_linkoffset += LLC_FRAME_SIZE;
			break;
#endif
		default:;
	}
	if (hdr->caplen < nids_linkoffset)
		return;

	/*
	 * sure, memcpy costs. But many EXTRACT_{SHORT, LONG} macros cost, too. 
	 * Anyway, libpcap tries to ensure proper layer 3 alignment (look for
	 * handle->offset in pcap sources), so memcpy should not be called.
	 */
#ifdef LBL_ALIGN
	if ((unsigned long) (data + nids_linkoffset) & 0x3) {
		data_aligned = alloca(hdr->caplen - nids_linkoffset + 4);
		data_aligned -= (unsigned long) data_aligned % 4;
		memcpy(data_aligned, data + nids_linkoffset, hdr->caplen - nids_linkoffset);
	} else 
#endif
		data_aligned = data + nids_linkoffset;

	call_ip_frag_procs(data_aligned,hdr->caplen - nids_linkoffset);
}

#if defined(PARALLEL)
static void gen_ip_frag_proc(char *data, int len, IP_THREAD_LOCAL_P ip_thread_local_p)
{
	struct proc_node *i;
	struct ip *iph = (struct ip *) data;
	int need_free = 0;
	int skblen;

	if (!nids_params.ip_filter(iph, len))
		return;

	if (len < (int)sizeof(struct ip) || iph->ip_hl < 5 || iph->ip_v != 4 ||
			ip_fast_csum((unsigned char *) iph, iph->ip_hl) != 0 ||
			len < ntohs(iph->ip_len) || ntohs(iph->ip_len) < iph->ip_hl << 2) {
		return;
	}
	if (iph->ip_hl > 5 && ip_options_compile((unsigned char *)data)) {
		return;
	}

	switch (ip_defrag_stub((struct ip *) data, &iph, ip_thread_local_p)) {
		case IPF_ISF:
			return;
		case IPF_NOTF:
			need_free = 0;
			iph = (struct ip *) data;
			break;
		case IPF_NEW:
			need_free = 1;
			break;
		default:;
	}
	skblen = ntohs(iph->ip_len) + 16;
	if (!need_free)
		skblen += nids_params.dev_addon;
	skblen = (skblen + 15) & ~15;
	skblen += nids_params.sk_buff_size;

	for (i = ip_procs; i; i = i->next)
		(i->item) (iph, skblen, ip_thread_local_p->self_cpu_id);
	if (need_free)
		free(iph);
}
#else
static void gen_ip_frag_proc(u_char * data, int len)
{
	struct proc_node *i;
	struct ip *iph = (struct ip *) data;
	int need_free = 0;
	int skblen;

	if (!nids_params.ip_filter(iph, len))
		return;

	if (len < (int)sizeof(struct ip) || iph->ip_hl < 5 || iph->ip_v != 4 ||
			ip_fast_csum((unsigned char *) iph, iph->ip_hl) != 0 ||
			len < ntohs(iph->ip_len) || ntohs(iph->ip_len) < iph->ip_hl << 2) {
		return;
	}
	if (iph->ip_hl > 5 && ip_options_compile((unsigned char *)data)) {
		return;
	}

	switch (ip_defrag_stub((struct ip *) data, &iph)) {
		case IPF_ISF:
			return;
		case IPF_NOTF:
			need_free = 0;
			iph = (struct ip *) data;
			break;
		case IPF_NEW:
			need_free = 1;
			break;
		default:;
	}
	skblen = ntohs(iph->ip_len) + 16;
	if (!need_free)
		skblen += nids_params.dev_addon;
	skblen = (skblen + 15) & ~15;
	skblen += nids_params.sk_buff_size;

	for (i = ip_procs; i; i = i->next)
		(i->item) (iph, skblen);
	if (need_free)
		free(iph);
}
#endif

#if HAVE_BSD_UDPHDR
#define UH_ULEN uh_ulen
#define UH_SPORT uh_sport
#define UH_DPORT uh_dport
#else
#define UH_ULEN len
#define UH_SPORT source
#define UH_DPORT dest
#endif

static void process_udp(char *data)
{
    struct proc_node *ipp = udp_procs;
    struct ip *iph = (struct ip *) data;
    struct udphdr *udph;
    struct tuple4 addr;
    int hlen = iph->ip_hl << 2;
    int len = ntohs(iph->ip_len);
    int ulen;
    if (len - hlen < (int)sizeof(struct udphdr))
	return;
    udph = (struct udphdr *) (data + hlen);
    ulen = ntohs(udph->UH_ULEN);
    if (len - hlen < ulen || ulen < (int)sizeof(struct udphdr))
	return;
    /* According to RFC768 a checksum of 0 is not an error (Sebastien Raveau) */
    if (udph->uh_sum && my_udp_check
	((void *) udph, ulen, iph->ip_src.s_addr,
	 iph->ip_dst.s_addr)) return;
    addr.source = ntohs(udph->UH_SPORT);
    addr.dest = ntohs(udph->UH_DPORT);
    addr.saddr = iph->ip_src.s_addr;
    addr.daddr = iph->ip_dst.s_addr;
    while (ipp) {
	ipp->item(&addr, ((char *) udph) + sizeof(struct udphdr),
		  ulen - sizeof(struct udphdr), data);
	ipp = ipp->next;
    }
}

static inline uint64_t read_tsc()
{
	uint64_t        time;
	uint32_t        msw, lsw;
	__asm__         __volatile__("rdtsc\n\t"
			"movl %%edx, %0\n\t"
			"movl %%eax, %1\n\t"
			:         "=r"         (msw), "=r"(lsw)
			:
			:         "%edx"      , "%eax");
	time = ((uint64_t) msw << 32) | lsw;
	return time;
}

#if defined(PARALLEL)
static void gen_ip_proc(u_char * data, int skblen, int cpu_id)
{
	uint64_t time1, time2;
	TCP_THREAD_LOCAL_P t_ptr = &tcp_thread_local_struct[cpu_id];
	switch (((struct ip *) data)->ip_p) {
		case IPPROTO_TCP:
			process_tcp(data, skblen, t_ptr);
			break;

/* Ignore UDP and ICMP
		case IPPROTO_UDP:
			process_udp((char *)data);
			break;
*/
		case IPPROTO_ICMP:
			if (nids_params.n_tcp_streams)
				process_icmp(data, t_ptr);
			break;
		default:
			break;
	}
}
#else
static void gen_ip_proc(u_char * data, int skblen)
{
	uint64_t time1, time2;
	switch (((struct ip *) data)->ip_p) {
		case IPPROTO_TCP:
			time1 = read_tsc();
			process_tcp(data, skblen);
			time2 = read_tsc();
			tcp_proc_time += (time2 - time1);
			tcp_proc_num ++;
			break;
/* Ignore UDP and ICMP
		case IPPROTO_UDP:
			process_udp((char *)data);
			break;
*/
		case IPPROTO_ICMP:
			if (nids_params.n_tcp_streams)
				process_icmp(data);
			break;
		default:
			break;
	}
}
#endif

static void init_procs()
{
    ip_frag_procs = mknew(struct proc_node);
    ip_frag_procs->item = gen_ip_frag_proc;
    ip_frag_procs->next = 0;
    ip_procs = mknew(struct proc_node);
    ip_procs->item = gen_ip_proc;
    ip_procs->next = 0;
    tcp_procs = 0;
    udp_procs = 0;
}

void nids_register_udp(void (*x))
{
    register_callback(&udp_procs, x);
}

void nids_unregister_udp(void (*x))
{
    unregister_callback(&udp_procs, x);
}

void nids_register_ip(void (*x))
{
    register_callback(&ip_procs, x);
}

void nids_unregister_ip(void (*x))
{
    unregister_callback(&ip_procs, x);
}

void nids_register_ip_frag(void (*x))
{
    register_callback(&ip_frag_procs, x);
}

void nids_unregister_ip_frag(void (*x))
{
    unregister_callback(&ip_frag_procs, x);
}

static int open_live()
{
    char *device;
    int promisc = 0;

    if (nids_params.device == NULL)
	nids_params.device = pcap_lookupdev(nids_errbuf);
    if (nids_params.device == NULL)
	return 0;

    device = nids_params.device;
    if (!strcmp(device, "all"))
	device = "any";
    else
	promisc = (nids_params.promisc != 0);

    if ((desc = pcap_open_live(device, 16384, promisc,
			       nids_params.pcap_timeout, nids_errbuf)) == NULL)
	return 0;
#ifdef __linux__
    if (!strcmp(device, "any") && nids_params.promisc
	&& !set_all_promisc()) {
	nids_errbuf[0] = 0;
	strncat(nids_errbuf, strerror(errno), sizeof(nids_errbuf) - 1);
	return 0;
    }
#endif
    if (!raw_init()) {
	nids_errbuf[0] = 0;
	strncat(nids_errbuf, strerror(errno), sizeof(nids_errbuf) - 1);
	return 0;
    }
    return 1;
}


#define START_CAP_QUEUE_PROCESS_THREAD()
#define STOP_CAP_QUEUE_PROCESS_THREAD()

int nids_init()
{
	/* free resources that previous usages might have allocated */
	nids_exit();

	if (nids_params.pcap_desc)
		desc = nids_params.pcap_desc;
	else if (nids_params.filename) {
		if ((desc = pcap_open_offline(nids_params.filename,
						nids_errbuf)) == NULL)
			return 0;
#if defined(PRE_MEM)
		pre_mem_init(desc);
#endif
	} else if (!open_live())
		return 0;


#if defined(PARALLEL)
	int i;
	for (i = 0; i < MAX_CPU_CORES; i++) {
		ip_thread_local_struct[i].self_cpu_id = i;
		ip_frag_init(nids_params.n_tcp_streams, &ip_thread_local_struct[i]);
		int thread_id = cpu_id[i];
		tcp_thread_local_struct[thread_id].self_cpu_id = thread_id;
		tcp_init(nids_params.n_tcp_streams, &tcp_thread_local_struct[thread_id]);
		fifo_init(i);
	}

	for (i = 0; i < number_of_cpus_used - 1; i ++) {
		pthread_create(&ip_thread_ctrl[i], NULL, (void *)ip_queue_process_thread, (void *)(long)cpu_id[i]);
	}

	printf("This is IP core, AP cores create complete\n");
#else
	tcp_init(nids_params.n_tcp_streams);
	ip_frag_init(nids_params.n_hosts);

#endif

	if (nids_params.pcap_filter != NULL) {
		u_int mask = 0;
		struct bpf_program fcode;

		if (pcap_compile(desc, &fcode, nids_params.pcap_filter, 1, mask) <
				0) return 0;
		if (pcap_setfilter(desc, &fcode) == -1)
			return 0;
	}
	switch ((linktype = pcap_datalink(desc))) {
#ifdef DLT_IEEE802_11
#ifdef DLT_PRISM_HEADER
		case DLT_PRISM_HEADER:
#endif
#ifdef DLT_IEEE802_11_RADIO
		case DLT_IEEE802_11_RADIO:
#endif
		case DLT_IEEE802_11:
			/* wireless, need to calculate offset per frame */
			break;
#endif
#ifdef DLT_NULL
		case DLT_NULL:
			nids_linkoffset = 4;
			break;
#endif        
		case DLT_EN10MB:
			nids_linkoffset = 14;
			break;
		case DLT_PPP:
			nids_linkoffset = 4;
			break;
			/* Token Ring Support by vacuum@technotronic.com, thanks dugsong! */
		case DLT_IEEE802:
			nids_linkoffset = 22;
			break;

		case DLT_RAW:
		case DLT_SLIP:
			nids_linkoffset = 0;
			break;
#define DLT_LINUX_SLL   113
		case DLT_LINUX_SLL:
			nids_linkoffset = 16;
			break;
#ifdef DLT_FDDI
		case DLT_FDDI:
			nids_linkoffset = 21;
			break;
#endif        
#ifdef DLT_PPP_SERIAL 
		case DLT_PPP_SERIAL:
			nids_linkoffset = 4;
			break;
#endif        
		default:
			strcpy(nids_errbuf, "link type unknown");
			return 0;
	}
	if (nids_params.dev_addon == -1) {
		if (linktype == DLT_EN10MB)
			nids_params.dev_addon = 16;
		else
			nids_params.dev_addon = 0;
	}
	if (nids_params.syslog == nids_syslog)
		openlog("libnids", 0, LOG_LOCAL0);

	init_procs();
	scan_init();

	if(nids_params.multiproc) {
		strcpy(nids_errbuf, "libnids was compiled without threads support");
		return 0;        
	}

	return 1;
}

int nids_run()
{
	if (!desc) {
		strcpy(nids_errbuf, "Libnids not initialized");
		return 0;
	}

#if defined(PARALLEL)
	unsigned long mask;
//	CPU_ZERO(&mask);
//	CPU_SET(0, &mask);
	mask = 0x1;

    	if (sched_setaffinity(0, sizeof(unsigned long), &mask) < 0) {
		printf("Error: sched_setaffinity\n");
		return -1;
	}
#endif

	pcap_loop(desc, -1, (pcap_handler) nids_pcap_handler, 0);

#if defined(PARALLEL)
	int i, j, res;
	for (i = 0; i < number_of_cpus_used - 1; i ++) {
		int new_id = cpu_id[i];

		FIFO_ELEM elem;
		FIFO_ELEM_DATA(&elem) = (void *) 1;
		FIFO_ELEM_SIZE(&elem) = (uint16_t) 0xFFFF;

		for(j=0; j<=BATCH_SIZE; j++) {
			do{
				res = insert(&fifo_g[new_id], &buffer_g[new_id], elem);
			}while(res < 0);
		}

	}

	for (i = 0; i < number_of_cpus_used - 1; i ++) {
		pthread_join(ip_thread_ctrl[i], NULL);
	}
#endif

	nids_exit();
	return 0;
}

void nids_exit()
{
    if (!desc) {
        strcpy(nids_errbuf, "Libnids not initialized");
	return;
    }
#if defined(PARALLEL)
		int i;
		for (i = 0; i < MAX_CPU_CORES; i ++) {
			if (&ip_thread_local_struct[i])
				ip_frag_exit(&ip_thread_local_struct[i]);
			if (&tcp_thread_local_struct[i])
				tcp_exit(&tcp_thread_local_struct[i]);
		}
#else
    tcp_exit();
    ip_frag_exit();
#endif

    scan_exit();
    strcpy(nids_errbuf, "loop: ");
    strncat(nids_errbuf, pcap_geterr(desc), sizeof nids_errbuf - 7);
    if (!nids_params.pcap_desc)
        pcap_close(desc);
    desc = NULL;

    free(ip_procs);
    free(ip_frag_procs);
}

