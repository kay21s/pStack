#
# Makefile for libnids.
#
# Dug Song <dugsong@monkey.org>

srcdir		= .

LIBSTATIC      = libnids.a

CC		= gcc
# Note: Major location can only be used when COMPACT_TABLE is enabled or INDEXFREE is enabled
# CRC_SIGN can only be used when msse4.2 is enabled
CFLAGS		= -g -lpthread -D_BSD_SOURCE -DLIBNET_VER=-1 -DHAVE_ICMPHDR=1 -DHAVE_TCP_STATES=1 -DHAVE_BSD_UDPHDR=1 
CFLAGS		+= -D__USE_GNU -D_BSD_SOURCE
CFLAGS		+= -DNEW_TCP_0 -DSPLIT_TCP_0 -DORIGIN_TCP_0 -DINDEXFREE_TCP -DMAJOR_INDEXFREE_TCP_0 # Only one should be enabled
CFLAGS		+= -DMAJOR_LOCATION_0 -DCOMPACT_TABLE_0 -DBUILTIN_FUNC -DPRE_MEM 
CFLAGS		+= -DCRC_HASH -DCRC_SIGN2 -msse4.2 
CFLAGS		+= -DPARALLEL_0

#PCAP_CFLAGS	= -I/usr/local/include
#PCAPLIB		= -L/usr/local/lib -lpcap

#LIBS		= -lnsl -pthread 

# Sequential version, Open this
OBJS		= checksum.o ip_fragment.o ip_options.o killtcp.o \
		  libnids.o scan.o tcp.o util.o allpromisc.o hash.o \
		  conn_tcp.o bitmap.o conn_split.o conn_attribute.o \
		  conn_indexfree.o conn_major_indexfree.o
# Parallel version, Open this
#OBJS		= checksum.o ip_fragment.threaded.o ip_options.o killtcp.o \
		  libnids.o scan.o tcp.threaded.o util.o allpromisc.o hash.o \
		  bitmap.threaded.o conn_attribute.o fifo.o \
		  conn_tcp.threaded.o conn_indexfree.threaded.o conn_major_indexfree.threaded.o

.c.o:
	$(CC) -c $(CFLAGS) -I. $<
static: $(LIBSTATIC)

$(LIBSTATIC): $(OBJS)
	ar -cr $@ $(OBJS)

clean:
	rm -f *.o *~ $(LIBSTATIC) $(LIBSHARED)

# EOF
