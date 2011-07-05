#include <stdint.h>
#include <pthread.h>

typedef struct{
	char * data;
	uint32_t len;
} FIFO_ELEM;

#define FIFO_ELEM_DATA(p)	((p)->data)
#define FIFO_ELEM_SIZE(p)	((p)->len)

#define CACHE_LINE	64 //! Cache-line size for X86 
#define ELEMENT_TYPE	FIFO_ELEM
#define ELEM_SIZE	2048 //! Should be 2^N
#define ELEM_SIZE_MASK	(ELEM_SIZE-1)
#define BATCH_SIZE	50

#define INSERT_FAILED	-1
#define EXTRACT_FAILED	-2
#define SUCCESS		0

#define CONS_WORK_CYCLES 1280
#define PROD_WORK_CYCLES (CONS_WORK_CYCLES*2 + 1)

#if defined(WORKLOAD_DEBUG)

#define PROBAB_MEMCPY 0
#define PROBAB_MALLOC 0
#define PROBAB_YIELD 0
#define PROBAB_LOCK 0
#define PROBAB_WORKLOAD 4
#define PROBAB_WORKLOAD_MASK (PROBAB_WORKLOAD-1)
#define WORKLOAD   (PROBAB_WORKLOAD * CONS_WORK_CYCLES) 
#define MEM_LEN 1024

#endif

#define WAIT_TICKS_LATENCY 60 /* RDTSC in Core 2 costs 30 cycles */

#define TEST_SIZE 2000000 
	
/* Variable definitions */
typedef struct{
	/* shared control variables */
	volatile uint32_t read __attribute__ ((aligned(64)));
	volatile uint32_t write;

	/* consumer's local variables */
	uint32_t localWrite __attribute__ ((aligned(64)));
	uint32_t nextRead;
	uint32_t rBatch;

	/* producer's local variables */
	uint32_t localRead __attribute__ ((aligned(64)));
	uint32_t nextWrite;
	uint32_t wBatch;

	/* constants */
	uint32_t max __attribute__ ((aligned(64)));
	uint32_t batchSize;
} FIFO_CTRL __attribute__ ((aligned(128)));

#define FIFO_READ(p)		((p)->read)	
#define FIFO_WRITE(p)		((p)->write)

#define FIFO_LOCAL_WRITE(p)	((p)->localWrite)
#define FIFO_NEXT_READ(p)	((p)->nextRead)
#define FIFO_R_BATCH(p)		((p)->rBatch)

#define FIFO_LOCAL_READ(p)	((p)->localRead)
#define FIFO_NEXT_WRITE(p)	((p)->nextWrite)
#define FIFO_W_BATCH(p)		((p)->wBatch)

#define FIFO_MAX(p)		((p)->max)
#define FIFO_BATCH_SIZE(p)	((p)->batchSize)

/* ***************** */

/* buffer definitions */
typedef struct{
	ELEMENT_TYPE buffer[ELEM_SIZE];
} FIFO_BUFFER __attribute__((aligned(16)));

#define BUFFER_ELEM(p, i)	((p)->buffer[i])
#define BUFFER_ELEM_PTR(p, i)	(&((p)->buffer[i]))
#define ELEM_NEXT(i)		(((i)+1) & ELEM_SIZE_MASK)

/* ***************** */

/* Init messages */
typedef struct{
        uint32_t        cpu_id;
        pthread_barrier_t * barrier;
} INIT_INFO;
        
#define INIT_ID(p)      ((p)->cpu_id)
#define INIT_BAR(p)     ((p)->barrier)

void * consumer(void *);
void producer(void *, uint32_t);
inline int insert(FIFO_CTRL *, FIFO_BUFFER *, ELEMENT_TYPE);
inline int extract(FIFO_CTRL *, FIFO_BUFFER *, ELEMENT_TYPE *);
int fifo_init(int);
