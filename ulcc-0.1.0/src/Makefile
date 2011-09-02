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


all: libulcc.so ulccmmd ulccenv libulcc.a
	cp -f libulcc.so ulcc.h remapper.h arch.h util.h ../test
	cp -f ulccmmd ulccenv ../bin

libulcc.so: $(LIB_OBJS)
	$(CC) $(LIB_LDFLAGS) $(LIB_LIBS) -o libulcc.so $(LIB_OBJS) -lpthread

libulcc.a: $(LIB_OBJS)
	ar -cr $@ $(LIB_OBJS)

ulccmmd: $(MM_OBJS)
	$(CC) $(MM_LDFLAGS) $(MM_LIBS) -o ulccmmd $(MM_OBJS) -lpthread

ulccenv: ulccenv.o
	$(CC) $(UTIL_LDFLAGS) $(UTIL_LIBS) -o ulccenv ulccenv.o -lpthread

ulccenv.o: ulccenv.c
	$(CC) $(UTIL_CFLAGS) $(UTIL_INCS) -c ulccenv.c -lpthread

ulcc.o: ulcc.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c ulcc.c -lpthread

util.o: util.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c util.c -lpthread

arch.o: arch.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c arch.c -lpthread

allocator.o: allocator.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c allocator.c -lpthread

cache.o: cache.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c cache.c -lpthread

mmclient.o: mmclient.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c mmclient.c -lpthread

registry.o: registry.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c registry.c -lpthread

remapper.o: remapper.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -c remapper.c -lpthread

translator-lib.o: translator.c
	$(CC) $(LIB_CFLAGS) $(LIB_INCS) -o translator-lib.o -c translator.c -lpthread

memmgr.o: memmgr.c
	$(CC) $(MM_CFLAGS) $(MM_INCS) -c memmgr.c -lpthread

mmsvr.o: mmsvr.c
	$(CC) $(MM_CFLAGS) $(MM_INCS) -c mmsvr.c -lpthread

translator-mm.o: translator.c
	$(CC) $(MM_CFLAGS) $(MM_INCS) -o translator-mm.o -c translator.c -lpthread

clean:
	rm -f $(LIB_OBJS) $(MM_OBJS) $(UTIL_OBJS) libulcc.so ulccmmd ulccenv
