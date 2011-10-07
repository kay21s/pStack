#
# Makefile for libnids samples.
#
# Dug Song <dugsong@monkey.org>

srcdir		= .


CC		= gcc
CFLAGS		= -O2 -D_GNU_SOURCE -DMAX_CPU_CORES=8 -DPARALLEL

PCAP_CFLAGS	= -I/usr/local/include
PCAPLIB		= ../pcap-1.1.1/libpcap.a

LIBS_CFLAGS	= -I../src $(PCAP_CFLAGS)
LIBS		= -L../src -lnids -lm -lrt -lpthread 

LDFLAGS		+= ../ulcc-0.1.0/src/libulcc.a

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: tcp_test
static: all

tcp_test: tcp_test.o
	$(CC) -o $@ tcp_test.o $(LIBS) $(LDFLAGS) $(PCAPLIB)

clean:
	rm -f *.o *~ tcp_test

# EOF
