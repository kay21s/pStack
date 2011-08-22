include ./ulcc.config

CC= gcc

# Set to generate debug-version libulcc.so and ulccmmd
DEBUG=
#DEBUG= -g

# Compile and link options for libulcc.so
LIB_DEFS=		-D_ULCC_LIB
#LIB_DEFS=		-D_ULCC_LIB -D_ULCC_DBG
LIB_INCS=		-I.
LIB_CFLAGS=		-O -fPIC -Wall $(LIB_DEFS) $(CONFIGS) $(DEBUG)
LIB_LDFLAGS=		-shared
LIB_LIBS=		-lrt -lpthread
LIB_OBJS=		ulcc.o			\
			util.o			\
			arch.o			\
			allocator.o		\
			cache.o			\
			mmclient.o		\
			registry.o		\
			remapper.o		\
			translator-lib.o

# Compile and link options for memory manager daemon, ulccmmd
MM_DEFS=
#MM_DEFS=		-D_ULCC_DBG
MM_INCS=		-I.
MM_CFLAGS=		-O -Wall $(MM_DEFS) $(CONFIGS) $(DEBUG)
MM_LDFLAGS=
MM_LIBS=		-lrt -lpthread
MM_OBJS=		memmgr.o		\
			mmsvr.o			\
			translator-mm.o

# Compile and link options for ULCC utilities
UTIL_DEFS=
UTIL_INCS=		-I.
UTIL_CFLAGS=		-O -Wall $(UTIL_DEFS) $(CONFIGS) $(DEBUG)
UTIL_LDFLAGS=
UTIL_LIBS=		-lrt
UTIL_OBJS=		ulccenv.o


all: libulcc.so ulccmmd ulccenv
	cp -f libulcc.so ulcc.h remapper.h arch.h util.h ../test
	cp -f ulccmmd ulccenv ../bin

libulcc.so: $(LIB_OBJS)
	$(CC) $(LIB_LDFLAGS) $(LIB_LIBS) -o libulcc.so $(LIB_OBJS)

ulccmmd: $(MM_OBJS)
	$(CC) $(MM_LDFLAGS) $(MM_LIBS) -o ulccmmd $(MM_OBJS)

ulccenv: ulccenv.o
	$(CC) $(UTIL_LDFLAGS) $(UTIL_LIBS) -o ulccenv ulccenv.o

ulccenv.o: ulccenv.c
	$(CC) $(UTIL_CFLAGS) $(UTIL_INCS) -c ulccenv.c

ulcc.o: ulcc.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c ulcc.c

util.o: util.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c util.c

arch.o: arch.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c arch.c

allocator.o: allocator.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c allocator.c

cache.o: cache.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c cache.c

mmclient.o: mmclient.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c mmclient.c

registry.o: registry.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c registry.c

remapper.o: remapper.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c remapper.c

translator-lib.o: translator.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -o translator-lib.o -c translator.c

memmgr.o: memmgr.c
	$(CC) $(MM_CFLAGS) $(MM_INCS) -c memmgr.c

mmsvr.o: mmsvr.c
	$(CC) $(MM_CFLAGS) $(MM_INCS) -c mmsvr.c

translator-mm.o: translator.c
	$(CC) $(MM_CFLAGS) $(MM_INCS) -o translator-mm.o -c translator.c

clean:
	rm -f $(LIB_OBJS) $(MM_OBJS) $(UTIL_OBJS) libulcc.so ulccmmd ulccenv
