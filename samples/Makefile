#
# Makefile for libnids samples.
#
# Dug Song <dugsong@monkey.org>

srcdir		= .


CC		= gcc
CFLAGS		= -g -D_BSD_SOURCE

PCAP_CFLAGS	= -I/usr/local/include
PCAPLIB		= -L/usr/local/lib -lpcap

LIBS_CFLAGS	= -I../src $(PCAP_CFLAGS)
LIBS		= -L../src -lnids $(PCAPLIB) 

.c.o:
	$(CC) -c $(CFLAGS) -I. $(LIBS_CFLAGS) $<

all: tcp_test
static: all

tcp_test: tcp_test.o
	$(CC) -o $@ tcp_test.o $(LIBS)

clean:
	rm -f *.o *~ tcp_test

# EOF
