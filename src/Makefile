#
# Makefile for libnids.
#
# Dug Song <dugsong@monkey.org>

srcdir		= .

LIBSTATIC      = libnids.a

CC		= gcc
# Note: Major location can only be used when COMPACT_TABLE is enabled or INDEXFREE is enabled
# CRC_SIGN can only be used when msse4.2 is enabled
CFLAGS		= -g -D_BSD_SOURCE -DLIBNET_VER=-1 -DHAVE_ICMPHDR=1 -DHAVE_TCP_STATES=1 -DHAVE_BSD_UDPHDR=1 
CFLAGS		+= -DNEW_TCP_0 -DSPLIT_TCP_0 -DORIGIN_0 -DINDEXFREE_TCP_0 -DMAJOR_INDEXFREE_TCP
CFLAGS		+= -DMAJOR_LOCATION -DBUILTIN_FUNC -DCOMPACT_TABLE_0 -DCRC_SIGN_0 -msse4.2 -DPRE_MEM_0

#PCAP_CFLAGS	= -I/usr/local/include
#PCAPLIB		= -L/usr/local/lib -lpcap

#LIBS		= -lnsl -pthread 

OBJS		= checksum.o ip_fragment.o ip_options.o killtcp.o \
		  libnids.o scan.o tcp.o util.o allpromisc.o hash.o \
		  conn_tcp.o bitmap.o conn_split.o conn_attribute.o \
		  conn_indexfree.o conn_major_indexfree.o

.c.o:
	$(CC) -c $(CFLAGS) -I. $<
static: $(LIBSTATIC)

$(LIBSTATIC): $(OBJS)
	ar -cr $@ $(OBJS)

clean:
	rm -f *.o *~ $(LIBSTATIC) $(LIBSHARED)

# EOF
