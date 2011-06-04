#
# Makefile for libnids samples.
#
# Dug Song <dugsong@monkey.org>

srcdir		= .


CC		= gcc
CFLAGS		= -g -D_BSD_SOURCE
LDFLAGS		= 

PCAP_CFLAGS	= -I/usr/local/include
PCAPLIB		= -L/usr/local/lib -lpcap

LNET_CFLAGS	= -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
LNETLIB		= -lnet

LIBS_CFLAGS	= -I../src $(PCAP_CFLAGS)
LIBS		= -L../src -lnids $(PCAPLIB) 

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: tcp_test
static shared: all

tcp_test: tcp_test.o
	$(CC) -o $@ tcp_test.o $(LDFLAGS) $(LIBS)

static shared install installshared:
	@true

clean:
	rm -f *.o *~ tcp_test

# EOF
